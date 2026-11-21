import { describe, expect, it } from "bun:test";
import { formatVerify, type VerifyResult } from "./audit.ts";

const good: VerifyResult = {
  ok: true,
  rows: 3,
  firstBad: null,
  firstBadSeq: null,
  head: "h3",
  base: null,
  checkpoints: { stored: 1, verified: 1, pruned: 0, mismatched: [] },
};

describe("cfs audit verify output (ADR 19)", () => {
  it("prints ok and the checkpoint summary when the chain holds", () => {
    expect(formatVerify(good)).toEqual([
      "ok: 3 rows checked, head h3",
      "checkpoints: 1 verified, 0 pruned, 1 stored",
    ]);
  });

  it("names the first bad row and the mismatched checkpoint", () => {
    const lines = formatVerify({
      ...good,
      ok: false,
      firstBad: 1,
      firstBadSeq: 7,
      checkpoints: { stored: 1, verified: 0, pruned: 0, mismatched: ["2026-11-20"] },
    });
    expect(lines[0]).toBe("bad: row seq 7 (position 1) does not match its hash");
    expect(lines[1]).toBe("bad: checkpoint 2026-11-20 does not match the chain");
    expect(lines[2]).toBe("FAILED: 3 rows checked, head h3");
  });

  it("says where verification started after pruning", () => {
    const lines = formatVerify({ ...good, base: { seq: 40, hash: "b" } });
    expect(lines[0]).toBe("ok: 3 rows checked, from pruned base seq 40, head h3");
  });
});
