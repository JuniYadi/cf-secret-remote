import { describe, expect, it } from "vitest";
import { createRecoveryKey, createVault, lockRecovery, unlockVault } from "./vault.ts";

// The real @cfs/core primitives, run under Node's WebCrypto. PBKDF2 at 600k iterations takes a moment.
const PASSWORD = "coffee-rain-bicycle-blue";

describe("vault crypto steps (@cfs/core)", () => {
  it("locks the private key with the password and opens it again", async () => {
    const vault = await createVault(PASSWORD);
    expect(vault.lockedKey.startsWith("p1.")).toBe(true);
    expect(vault.lockedKey).not.toContain(vault.privateKey);
    expect(await unlockVault(vault.lockedKey, PASSWORD)).toBe(vault.privateKey);
  });

  it("rejects a wrong password", async () => {
    const vault = await createVault(PASSWORD);
    await expect(unlockVault(vault.lockedKey, "coffee-rain-bicycle-bleu")).rejects.toThrow();
  });

  it("makes a 24-word recovery phrase and seals the key under it", async () => {
    const vault = await createVault(PASSWORD);
    const recovery = await createRecoveryKey();
    expect(recovery.phrase.split(" ")).toHaveLength(24);
    expect(recovery.entropy).toHaveLength(32);
    const sealed = await lockRecovery(vault.privateKey, recovery.entropy);
    expect(sealed.startsWith("rk1.")).toBe(true);
    expect(sealed).not.toContain(vault.privateKey);
  });
});
