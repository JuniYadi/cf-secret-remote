import { describe, expect, it } from "vitest";
import {
  describeRules,
  type RuleDraft,
  rulesAsText,
  toggleCap,
  toRules,
  validateGlob,
  validatePermissionSet,
} from "./permissions.ts";

// ADR 5: path globs and capabilities. The server's glob matches "*" against any characters, including "/".

describe("glob validation", () => {
  it("accepts folders, secret paths and wildcards", () => {
    for (const glob of ["myapp/*", "*", "backend/payments/dev", "myapp/prod.v2", "data_1/*/x"]) {
      expect(validateGlob(glob), glob).toBeNull();
    }
  });

  it("refuses empty, too long, and malformed globs", () => {
    expect(validateGlob("")).toBe("empty");
    expect(validateGlob("   ")).toBe("empty");
    expect(validateGlob("/myapp")).toBe("shape");
    expect(validateGlob("myapp/")).toBe("shape");
    expect(validateGlob("myapp//dev")).toBe("shape");
    expect(validateGlob("my app/*")).toBe("shape");
    expect(validateGlob("a".repeat(201))).toBe("tooLong");
  });
});

describe("permission set validation", () => {
  const ok: RuleDraft[] = [{ path: "myapp/*", caps: ["read", "list"] }];

  it("passes a named set with one granting rule", () => {
    expect(validatePermissionSet("Myapp access", ok).valid).toBe(true);
  });

  it("needs a name and at least one rule", () => {
    expect(validatePermissionSet("  ", ok).errors.name).toBe("empty");
    expect(validatePermissionSet("x".repeat(81), ok).errors.name).toBe("tooLong");
    expect(validatePermissionSet("Name", []).errors.rulesEmpty).toBe(true);
  });

  it("needs at least one capability on every rule", () => {
    const res = validatePermissionSet("Name", [{ path: "myapp/*", caps: [] }]);
    expect(res.valid).toBe(false);
    expect(res.errors.rules[0]?.caps).toBe("none");
  });

  it("reports a bad path on the row it belongs to", () => {
    const res = validatePermissionSet("Name", [
      { path: "myapp/*", caps: ["read"] },
      { path: "/bad", caps: ["read"] },
    ]);
    expect(res.errors.rules[0]?.path).toBeUndefined();
    expect(res.errors.rules[1]?.path).toBe("shape");
  });

  it("refuses two rows with the same path, since they would read as one", () => {
    const res = validatePermissionSet("Name", [
      { path: "myapp/*", caps: ["read"] },
      { path: "myapp/*", caps: ["list"] },
    ]);
    expect(res.errors.duplicate).toBe(true);
    expect(res.valid).toBe(false);
  });
});

describe("rules as the API stores them", () => {
  it("trims paths and keeps capabilities in the canonical order", () => {
    expect(toRules([{ path: "  myapp/* ", caps: ["list", "read"] }])).toEqual([
      { path: "myapp/*", caps: ["read", "list"] },
    ]);
  });

  it("toggles a capability without changing the input array", () => {
    const before = ["read" as const];
    expect(toggleCap(before, "list")).toEqual(["read", "list"]);
    expect(toggleCap(["read", "list"], "read")).toEqual(["list"]);
    expect(before).toEqual(["read"]);
  });

  it("describes only rules that grant something, in plain words", () => {
    const lines = describeRules([
      { path: "backend/*", caps: ["read", "list"] },
      { path: "backend/payments/prod", caps: [] },
    ]);
    expect(lines).toEqual(["View values, See names: backend/*"]);
  });

  it("prints the technical rule text for the details block", () => {
    expect(rulesAsText([{ path: "backend/*", caps: ["read", "list"] }])).toBe(
      'path "backend/*" {\n  capabilities = ["read", "list"]\n}',
    );
  });
});
