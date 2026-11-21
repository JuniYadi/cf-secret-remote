import { describe, expect, it } from "bun:test";
import { diffFingerprints, fingerprints } from "@cfs/core";
import vector from "../../../../packages/core/test-vectors/fingerprint.json";
import { mergeValues, parseImport, previewLines } from "./versions.ts";

describe("parseImport .env (ADR 22)", () => {
  it("reads KEY=value, export, quotes, empty values and skips comments", () => {
    const text = [
      "# a comment",
      "A=1",
      "export B=two",
      'C="with spaces"',
      "D='single'",
      "E=",
      "   F = spaced  ",
      "",
    ].join("\n");
    expect(parseImport(text, "env")).toEqual({
      A: "1",
      B: "two",
      C: "with spaces",
      D: "single",
      E: "",
      F: "spaced",
    });
  });
  it("refuses names that are not valid", () => {
    expect(() => parseImport('{"1BAD": "x"}', "json")).toThrow();
    expect(() => parseImport('{"__proto__": "x"}', "json")).toThrow();
  });
});

describe("parseImport JSON (ADR 22)", () => {
  it("keeps strings, turns booleans and numbers into their text", () => {
    expect(
      parseImport('{"NAME":"x","DEBUG":true,"OFF":false,"PORT":8080,"RATE":0.5}', "json"),
    ).toEqual({ NAME: "x", DEBUG: "true", OFF: "false", PORT: "8080", RATE: "0.5" });
  });
  it("accepts only a flat object", () => {
    expect(() => parseImport("[1,2]", "json")).toThrow();
    expect(() => parseImport("null", "json")).toThrow();
    expect(() => parseImport('{"A":{"nested":1}}', "json")).toThrow();
    expect(() => parseImport('{"A":null}', "json")).toThrow();
    expect(() => parseImport('{"A":["x"]}', "json")).toThrow();
    expect(() => parseImport("{nope", "json")).toThrow();
  });
});

describe("mergeValues (ADR 22 merge strategies)", () => {
  const current = { KEEP: "1", SAME: "s", CHANGE: "old", GONE: "g" };
  const incoming = { SAME: "s", CHANGE: "new", NEW: "n" };

  it("add: only new names, existing values stay", () => {
    const m = mergeValues(current, incoming, "add");
    expect(m.result).toEqual({ KEEP: "1", SAME: "s", CHANGE: "old", GONE: "g", NEW: "n" });
    expect(m.added).toEqual(["NEW"]);
    expect(m.kept).toEqual(["CHANGE"]);
    expect(m.unchanged).toEqual(["SAME"]);
    expect(m.removed).toEqual([]);
  });
  it("overwrite: incoming wins, other names stay", () => {
    const m = mergeValues(current, incoming, "overwrite");
    expect(m.result).toEqual({ KEEP: "1", SAME: "s", CHANGE: "new", GONE: "g", NEW: "n" });
    expect(m.changed).toEqual(["CHANGE"]);
    expect(m.removed).toEqual([]);
  });
  it("replace: the result is exactly the incoming set", () => {
    const m = mergeValues(current, incoming, "replace");
    expect(m.result).toEqual({ SAME: "s", CHANGE: "new", NEW: "n" });
    expect(m.removed).toEqual(["GONE", "KEEP"]);
  });
  it("treats inherited property names like constructor as new names", () => {
    const m = mergeValues({}, JSON.parse('{"constructor":"x"}'), "add");
    expect(m.added).toEqual(["constructor"]);
    expect(Object.hasOwn(m.result, "constructor")).toBe(true);
  });
});

describe("preview (ADR 22: names only, never values)", () => {
  it("shows names and counts, not values", () => {
    const secretValue = "sk_live_PREVIEW_MARKER_77";
    const m = mergeValues({ OLD: "v" }, { NEW: secretValue, OLD: "w" }, "overwrite");
    const text = previewLines(m).join("\n");
    expect(text).toContain("+ NEW");
    expect(text).toContain("~ OLD");
    expect(text).not.toContain(secretValue);
    expect(text).not.toContain("=");
  });
});

describe("fingerprints in the CLI (ADR 22 shared vector)", () => {
  it("matches the shared test vector", async () => {
    const key = Uint8Array.from(
      vector.groupKeyHex.match(/../g)?.map((b) => Number.parseInt(b, 16)) ?? [],
    );
    const cases = vector.cases as {
      path: string;
      values: Record<string, string>;
      fps: Record<string, string>;
    }[];
    for (const c of cases) {
      expect(await fingerprints(key, c.path, c.values)).toEqual(c.fps);
    }
  });
  it("a diff between two versions names changes without any value", async () => {
    const key = Uint8Array.from(
      vector.groupKeyHex.match(/../g)?.map((b) => Number.parseInt(b, 16)) ?? [],
    );
    const a = await fingerprints(key, "pay/prod", { KEY: "one", GONE: "x", SAME: "s" });
    const b = await fingerprints(key, "pay/prod", {
      KEY: "two",
      NEW: "sk_live_DIFF_MARKER",
      SAME: "s",
    });
    const d = diffFingerprints(a, b);
    expect(d).toEqual({ added: ["NEW"], changed: ["KEY"], removed: ["GONE"] });
    expect(JSON.stringify(d)).not.toContain("DIFF_MARKER");
  });
});
