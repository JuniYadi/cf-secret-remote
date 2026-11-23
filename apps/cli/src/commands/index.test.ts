import { describe, expect, it } from "bun:test";
import { isVersionRestore } from "./index.ts";

describe("cfs restore dispatch", () => {
  it("treats <secret> <version> as a version restore (ADR 22)", () => {
    expect(isVersionRestore(["team/app", "1"])).toBe(true);
    expect(isVersionRestore(["team/app", "12", "--yes"])).toBe(true);
  });

  it("treats a file and backup flags as a backup restore (ADR 23)", () => {
    expect(isVersionRestore(["backup.cfsbackup"])).toBe(false);
    expect(isVersionRestore(["backup.cfsbackup", "--check"])).toBe(false);
    expect(isVersionRestore(["--passphrase-env", "1"])).toBe(false);
    expect(isVersionRestore(["team/app", "0"])).toBe(false);
    expect(isVersionRestore([])).toBe(false);
  });
});
