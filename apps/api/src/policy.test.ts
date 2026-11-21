import { describe, expect, it } from "vitest";
import { can, globMatch, prefixOf, validPath } from "./policy.ts";

describe("policy", () => {
  const rules = [{ path: "payments/*", caps: ["read" as const, "list" as const] }];
  it("is default deny", () => {
    expect(can([], "payments/prod", "read")).toBe(false);
    expect(can(rules, "payments/prod", "read")).toBe(true);
    expect(can(rules, "payments/prod", "update")).toBe(false);
    expect(can(rules, "billing/prod", "read")).toBe(false);
  });
  it("globs are anchored and escape regex characters", () => {
    expect(globMatch("a.b/*", "a.b/x")).toBe(true);
    expect(globMatch("a.b/*", "aXb/x")).toBe(false);
    expect(globMatch("payments", "payments/prod")).toBe(false);
  });
  it("validates paths", () => {
    expect(validPath("payments/prod")).toBe(true);
    expect(validPath("../etc")).toBe(false);
    expect(validPath("a//b")).toBe(false);
    expect(prefixOf("payments/prod")).toBe("payments");
  });
});
