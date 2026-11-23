import { describe, expect, it } from "vitest";
import { isReservedGroupName, isReservedSecretPath } from "./route-names.ts";

describe("reserved web route names", () => {
  it("reserves fixed secret names and final page suffixes only", () => {
    for (const path of [
      "new",
      "import",
      "import/review",
      "team/edit",
      "team/versions",
      "team/history",
    ])
      expect(isReservedSecretPath(path)).toBe(true);
    for (const path of ["team/new", "team/import", "team/edit/dev", "New"])
      expect(isReservedSecretPath(path)).toBe(false);
  });
  it("reserves group routes case sensitively", () => {
    for (const name of ["new", "offboard", "regrant"]) expect(isReservedGroupName(name)).toBe(true);
    expect(isReservedGroupName("Offboard")).toBe(false);
  });
});
