import { describe, expect, it } from "bun:test";
import { runVectorChecks, type Vectors } from "../../../packages/core/browser-test/checks.ts";
import audit from "../../../packages/core/test-vectors/audit-chain.json";
import backupSeal from "../../../packages/core/test-vectors/backup-seal.json";
import envelope from "../../../packages/core/test-vectors/envelope.json";
import fingerprint from "../../../packages/core/test-vectors/fingerprint.json";
import kit from "../../../packages/core/test-vectors/kit.json";
import login from "../../../packages/core/test-vectors/login.json";
import recovery from "../../../packages/core/test-vectors/recovery.json";
import secret from "../../../packages/core/test-vectors/secret.json";
import wrappedKey from "../../../packages/core/test-vectors/wrapped-key.json";

// Run the same shared format checks in the CLI runtime as in core and the browser.
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
