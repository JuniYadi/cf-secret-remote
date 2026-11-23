import { describe, expect, it } from "vitest";
import { runVectorChecks, type Vectors } from "../browser-test/checks.ts";
import audit from "../test-vectors/audit-chain.json";
import backupSeal from "../test-vectors/backup-seal.json";
import envelope from "../test-vectors/envelope.json";
import fingerprint from "../test-vectors/fingerprint.json";
import kit from "../test-vectors/kit.json";
import login from "../test-vectors/login.json";
import recovery from "../test-vectors/recovery.json";
import secret from "../test-vectors/secret.json";
import wrappedKey from "../test-vectors/wrapped-key.json";

// ADR 26: every shared vector through the same checks the browser runs (browser-test/vectors.pw.ts).
const vectors = {
  envelope,
  wrappedKey,
  kit,
  fingerprint,
  recovery,
  auditChain: audit,
  secret,
  backupSeal,
  login,
} as unknown as Vectors;

describe("shared test vectors", () => {
  it("all pass in this runtime", async () => {
    const results = await runVectorChecks(vectors);
    expect(results.filter((r) => !r.ok)).toEqual([]);
    expect(results.length).toBeGreaterThanOrEqual(20);
  });
});
