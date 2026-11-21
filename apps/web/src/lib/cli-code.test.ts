import { describe, expect, it } from "vitest";
import { isCompleteCode, normalizeUserCode } from "./cli-code.ts";

describe("CLI code normalisation (ADR 11)", () => {
  it("upper-cases and adds the hyphen after four characters", () => {
    expect(normalizeUserCode("abcd2efg")).toBe("ABCD-2EFG");
  });

  it("accepts the hyphen, spaces and mixed case as typed", () => {
    expect(normalizeUserCode("abcd-2efg")).toBe("ABCD-2EFG");
    expect(normalizeUserCode(" ab cd 2e fg ")).toBe("ABCD-2EFG");
    expect(normalizeUserCode("ABCD-2EFG")).toBe("ABCD-2EFG");
  });

  it("leaves a short input upper-cased and trimmed, so it fails the check", () => {
    expect(normalizeUserCode(" abc ")).toBe("ABC");
    expect(isCompleteCode("abc")).toBe(false);
  });

  it("recognises a complete code in any input form", () => {
    expect(isCompleteCode("abcd2efg")).toBe(true);
    expect(isCompleteCode("ABCD-2EFG")).toBe(true);
    expect(isCompleteCode("ABCD-2EF")).toBe(false);
  });
});
