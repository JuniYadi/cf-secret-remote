import { describe, expect, it } from "vitest";
import {
  draftBody,
  extraNames,
  hasChanges,
  MAX_ENVS,
  removalsOf,
  resultTone,
  rowsFrom,
  validateDraft,
} from "./collections.ts";

// ADR 36: the forms check names, labels and paths, and never ask for or show a value.

const env = (label: string, path: string) => ({ label, path });
const key = (name: string, description = "") => ({ name, description });

describe("collection form checks", () => {
  it("accepts a named collection with environments and keys", () => {
    const r = validateDraft(
      "myapp",
      [env("dev", "myapp/dev"), env("prod", "myapp/prod")],
      [key("API_KEY")],
    );
    expect(r.valid).toBe(true);
  });

  it("refuses an empty name, the reserved name new, and a bad shape", () => {
    expect(validateDraft("", [env("dev", "a/b")], []).errors.name).toBe("empty");
    expect(validateDraft("new", [env("dev", "a/b")], []).errors.name).toBe("reserved");
    expect(validateDraft("my app", [env("dev", "a/b")], []).errors.name).toBe("shape");
  });

  it("needs one environment, unique labels and unique paths", () => {
    expect(validateDraft("x", [], []).errors.noEnvs).toBe(true);
    expect(
      validateDraft("x", [env("dev", "a/b"), env("dev", "a/c")], []).errors.duplicateLabels,
    ).toBe(true);
    expect(
      validateDraft("x", [env("dev", "a/b"), env("stg", "a/b")], []).errors.duplicatePaths,
    ).toBe(true);
  });

  it("flags a bad path and a bad key name on the row they belong to", () => {
    const r = validateDraft("x", [env("dev", "../etc")], [key("lower-case")]);
    expect(r.valid).toBe(false);
    expect(r.errors.envs[0]?.path).toBe("shape");
    expect(r.errors.keys[0]?.name).toBe("shape");
  });

  it("ignores blank rows, so an unused row never blocks the form", () => {
    const r = validateDraft("x", [env("dev", "a/b"), env("", "")], [key(""), key("A")]);
    expect(r.valid).toBe(true);
    expect(draftBody([env("dev", " a/b "), env("", "")], [key(""), key(" A ", " ")])).toEqual({
      envs: [{ label: "dev", path: "a/b" }],
      keys: [{ name: "A", description: null }],
    });
  });

  it("limits the number of environments", () => {
    const many = Array.from({ length: MAX_ENVS + 1 }, (_, i) => env(`e${i}`, `a/e${i}`));
    expect(validateDraft("x", many, []).errors.tooManyEnvs).toBe(true);
  });

  it("refuses a description over 200 characters", () => {
    const r = validateDraft("x", [env("dev", "a/b")], [key("A", "x".repeat(201))]);
    expect(r.errors.keys[0]?.description).toBe("tooLong");
  });
});

describe("removals and rows", () => {
  const before = {
    envs: [env("dev", "a/dev"), env("prod", "a/prod")],
    keys: [
      { name: "A", description: null },
      { name: "B", description: null },
    ],
  };
  it("rebuilds the edit rows from the stored definition", () => {
    expect(rowsFrom(before)).toEqual({
      envs: [env("dev", "a/dev"), env("prod", "a/prod")],
      keys: [key("A"), key("B")],
    });
  });

  it("lists removals exactly, for the confirmation", () => {
    const diff = {
      addedKeys: [],
      removedKeys: ["B"],
      changedKeys: [],
      addedEnvs: [],
      removedEnvs: ["prod"],
      changedEnvs: [],
    };
    expect(hasChanges(diff)).toBe(true);
    expect(removalsOf(diff)).toEqual({ keys: ["B"], envs: ["prod"] });
    expect(hasChanges({ ...diff, removedKeys: [], removedEnvs: [] })).toBe(false);
  });
});

describe("reconcile candidates", () => {
  it("lists each extra name once, with the environments that hold it, sorted", () => {
    const cmp = {
      name: "x",
      revision: 1,
      observedAt: 0,
      result: "drift" as const,
      envs: [
        { label: "dev", path: "a/dev", status: "ok" as const, extra: ["ZED", "MID"] },
        { label: "prod", path: "a/prod", status: "ok" as const, extra: ["MID"] },
        { label: "stg", path: "a/stg", status: "inaccessible" as const },
      ],
    };
    expect(extraNames(cmp)).toEqual([
      { name: "MID", labels: ["dev", "prod"] },
      { name: "ZED", labels: ["dev"] },
    ]);
  });

  it("maps results to a tone that never says ok for incomplete", () => {
    expect(resultTone("clean")).toBe("ok");
    expect(resultTone("drift")).toBe("warn");
    expect(resultTone("incomplete")).toBe("bad");
  });
});
