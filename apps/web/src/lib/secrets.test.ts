import { describe, expect, it } from "vitest";
import type { SecretSummary } from "./api.ts";
import {
  diffRows,
  fieldsFromValues,
  filterSecrets,
  groupCounts,
  mergeValues,
  NAME_RE,
  parseEnv,
  parseImportText,
  parseJsonValues,
  relativeTime,
  rotationStatus,
  todayIso,
  toEnvText,
  toJsonText,
  typeOf,
  validName,
  validSecretPath,
  valuesFromFields,
} from "./secrets.ts";

describe("value types", () => {
  it("types exact booleans and canonical numbers, and leaves everything else as text", () => {
    expect(typeOf("true")).toBe("boolean");
    expect(typeOf("false")).toBe("boolean");
    expect(typeOf("True")).toBe("text");
    expect(typeOf("20")).toBe("number");
    expect(typeOf("-1.5")).toBe("number");
    expect(typeOf("007")).toBe("text");
    expect(typeOf("1e3")).toBe("text");
    expect(typeOf("0.10")).toBe("text");
    expect(typeOf(" 4")).toBe("text");
    expect(typeOf("")).toBe("text");
    expect(typeOf("sk_live_1")).toBe("text");
  });

  it("accepts the same key names as the API, and the same secret paths", () => {
    expect(NAME_RE.test("DATABASE_URL")).toBe(true);
    expect(validName("1ABC")).toBe(false);
    expect(validName("A-B")).toBe(false);
    expect(validSecretPath("myapp/dev")).toBe(true);
    expect(validSecretPath("backend/payments/prod")).toBe(true);
    expect(validSecretPath("myapp//dev")).toBe(false);
    expect(validSecretPath("Myapp/dev ")).toBe(false);
    expect(validSecretPath("a".repeat(201))).toBe(false);
  });
});

describe("parseEnv", () => {
  it("reads KEY=value, export, comments, quotes and trailing comments", () => {
    const text = [
      "# a comment",
      "",
      'DATABASE_URL="postgres://app:s3cr3t@db/app"',
      "export API_KEY='sk_live_1'",
      "DEBUG_MODE=true # set while debugging",
      "MAX=20",
      "PATHY=/usr/bin#not-a-comment",
      'ESC="line1\\nline2 \\"q\\""',
    ].join("\n");
    const { values, empty, errors } = parseEnv(text);
    expect(errors).toEqual([]);
    expect(empty).toEqual([]);
    expect(values).toEqual({
      DATABASE_URL: "postgres://app:s3cr3t@db/app",
      API_KEY: "sk_live_1",
      DEBUG_MODE: "true",
      MAX: "20",
      PATHY: "/usr/bin#not-a-comment",
      ESC: 'line1\nline2 "q"',
    });
  });

  it("reports empty values as skipped, and lines it cannot read", () => {
    const { values, empty, errors } = parseEnv('EMPTY_VAR=\nNOPE\nOPEN="abc\nGOOD=1');
    expect(values).toEqual({ GOOD: "1" });
    expect(empty).toEqual(["EMPTY_VAR"]);
    expect(errors).toEqual([
      { line: 2, reason: "not KEY=value" },
      { line: 3, reason: "unclosed quote" },
    ]);
  });

  it("keeps the last value of a repeated name", () => {
    expect(parseEnv("A=1\nA=2").values).toEqual({ A: "2" });
  });

  it("round trips through toEnvText, including values that need quotes", () => {
    const values = {
      PLAIN: "abc",
      SPACED: "a b",
      HASH: "x#y",
      MULTI: "one\ntwo",
      QUOTE: 'say "hi"',
    };
    expect(parseEnv(toEnvText(values)).values).toEqual(values);
  });
});

describe("JSON values and the typed JSON tab", () => {
  it("stores booleans and numbers as their text, and keeps strings as they are", () => {
    expect(parseJsonValues('{"A": true, "B": false, "C": 20, "D": "20", "E": "text"}')).toEqual({
      ok: true,
      values: { A: "true", B: "false", C: "20", D: "20", E: "text" },
    });
  });

  it("refuses nested values, arrays, null and non-objects", () => {
    for (const bad of ['{"A": {"x": 1}}', '{"A": [1]}', '{"A": null}', "[1]", "42", "{nope"]) {
      expect(parseJsonValues(bad).ok).toBe(false);
    }
  });

  it("shows typed values without quotes, and reads them back to the same strings", () => {
    const values = {
      DEBUG_MODE: "true",
      FEATURE_BETA: "false",
      MAX_CONNECTIONS: "20",
      PORT_TEXT: "007",
      WORD: "hello",
      QUOTED: "1e3",
      EMPTY: "",
    };
    const text = toJsonText(values);
    expect(text).toContain('"DEBUG_MODE": true');
    expect(text).toContain('"MAX_CONNECTIONS": 20');
    expect(text).toContain('"PORT_TEXT": "007"');
    expect(text).toContain('"WORD": "hello"');
    const back = parseJsonValues(text);
    expect(back).toEqual({ ok: true, values });
  });

  it("writes an empty object for no values", () => {
    expect(toJsonText({})).toBe("{}");
    expect(parseJsonValues("{}")).toEqual({ ok: true, values: {} });
  });

  it("reads an uploaded file as JSON when it starts with an object, otherwise as .env", () => {
    const json = parseImportText('{"A": 1, "B": ""}');
    expect(json).toMatchObject({ source: "json", values: { A: "1" }, empty: ["B"] });
    const env = parseImportText("A=1\nB=");
    expect(env).toMatchObject({ source: "env", values: { A: "1" }, empty: ["B"], errors: [] });
    expect(parseImportText("{bad")).toEqual({
      source: "json",
      error: expect.any(String),
    });
  });
});

describe("fields tab", () => {
  it("round trips values through the fields rows", () => {
    const values = { DEBUG_MODE: "true", MAX: "20", NAME: "web" };
    const fields = fieldsFromValues(values);
    expect(fields.map((f) => f.type)).toEqual(["boolean", "number", "text"]);
    expect(valuesFromFields(fields)).toEqual({ ok: true, values });
  });

  it("explains the first problem", () => {
    const bad = (rows: Parameters<typeof valuesFromFields>[0]) => valuesFromFields(rows);
    expect(bad([{ id: 1, name: "1X", type: "text", value: "a" }])).toMatchObject({
      ok: false,
      field: 1,
    });
    expect(
      bad([
        { id: 1, name: "A", type: "text", value: "a" },
        { id: 2, name: "A", type: "text", value: "b" },
      ]),
    ).toMatchObject({ ok: false, field: 2 });
    expect(bad([{ id: 3, name: "N", type: "number", value: "abc" }])).toMatchObject({
      ok: false,
      field: 3,
    });
    expect(bad([{ id: 4, name: "B", type: "boolean", value: "yes" }])).toMatchObject({
      ok: false,
      field: 4,
    });
  });
});

describe("merge strategies", () => {
  const current = { A: "1", B: "2", KEEP: "k" };
  const incoming = { A: "1", B: "changed", NEW: "n" };

  it("add only: adds new names and keeps existing values", () => {
    const { result, rows } = mergeValues(current, incoming, "add");
    expect(result).toEqual({ A: "1", B: "2", KEEP: "k", NEW: "n" });
    expect(rows).toEqual([
      { name: "A", status: "same" },
      { name: "B", status: "kept" },
      { name: "NEW", status: "new" },
    ]);
  });

  it("overwrite: replaces names in the file and keeps the rest", () => {
    const { result, rows } = mergeValues(current, incoming, "overwrite");
    expect(result).toEqual({ A: "1", B: "changed", KEEP: "k", NEW: "n" });
    expect(rows.map((r) => r.status)).toEqual(["same", "replaced", "new"]);
  });

  it("replace all: the result is exactly the file, and missing names are removed", () => {
    const { result, rows } = mergeValues(current, incoming, "replace");
    expect(result).toEqual({ A: "1", B: "changed", NEW: "n" });
    expect(rows).toContainEqual({ name: "KEEP", status: "removed" });
    expect(rows.find((r) => r.name === "B")?.status).toBe("replaced");
  });

  it("starts from nothing for a new secret", () => {
    expect(mergeValues({}, incoming, "add").rows.every((r) => r.status === "new")).toBe(true);
  });
});

describe("diff view model between versions", () => {
  const fps = (o: Record<string, string>) => o;

  it("lists added, changed, removed and same names, sorted, with no values", () => {
    const rows = diffRows(
      fps({ API_KEY: "aaaa", DEBUG: "bbbb", SENTRY: "cccc", DB: "dddd" }),
      fps({ API_KEY: "ffff", DEBUG: "bbbb", MAX: "eeee", DB: "dddd" }),
    );
    expect(rows).toEqual([
      { name: "API_KEY", kind: "changed" },
      { name: "DB", kind: "same" },
      { name: "DEBUG", kind: "same" },
      { name: "MAX", kind: "added" },
      { name: "SENTRY", kind: "removed" },
    ]);
  });

  it("is null when a version has no fingerprints", () => {
    expect(diffRows(null, { A: "1" })).toBeNull();
    expect(diffRows({ A: "1" }, undefined)).toBeNull();
  });
});

describe("list helpers", () => {
  const list: SecretSummary[] = [
    { path: "myapp/dev", version: 1, updatedAt: 1, names: ["A"], meta: {} },
    { path: "myapp/prod", version: 1, updatedAt: 1, names: ["A", "B"], meta: {} },
    { path: "infra/cloudflare", version: 1, updatedAt: 1, names: [], meta: {} },
  ];

  it("filters by group and by text, case-insensitively", () => {
    expect(filterSecrets(list, { group: "myapp" }).map((s) => s.path)).toEqual([
      "myapp/dev",
      "myapp/prod",
    ]);
    expect(filterSecrets(list, { query: "PROD" }).map((s) => s.path)).toEqual(["myapp/prod"]);
    expect(filterSecrets(list, { query: "x", group: "infra" })).toEqual([]);
  });

  it("counts the groups in name order", () => {
    expect(groupCounts(list)).toEqual([
      { group: "infra", count: 1 },
      { group: "myapp", count: 2 },
    ]);
  });

  it("flags rotation dates that have passed", () => {
    expect(rotationStatus({}, "2026-11-21")).toBeNull();
    expect(rotationStatus({ rotateBy: "2026-11-01" }, "2026-11-21")).toBe("overdue");
    expect(rotationStatus({ rotateBy: "2026-12-01" }, "2026-11-21")).toBe("due");
  });

  it("writes relative times in both languages", () => {
    const now = Date.UTC(2026, 10, 21, 12);
    const twoHoursAgo = now / 1000 - 2 * 3600;
    expect(relativeTime(twoHoursAgo, now, "en")).toBe("2 hours ago");
    expect(relativeTime(twoHoursAgo, now, "id")).toBe("2 jam yang lalu");
    expect(todayIso(now)).toBe("2026-11-21");
  });
});
