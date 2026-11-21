import { describe, expect, it } from "vitest";
import vector from "../test-vectors/recovery.json";
import {
  fingerprint,
  fingerprintWords,
  generateKeyPair,
  isPrivateKeyLock,
  isRecoveryLockedKey,
  lockPrivateKey,
  lockWithRecoveryKey,
  newRecoveryKey,
  normalizeWords,
  recoveryEntropy,
  recoveryPhrase,
  unlockWithRecoveryKey,
} from "./index.ts";

const hexBytes = (hex: string) =>
  Uint8Array.from(hex.match(/../g)?.map((b) => Number.parseInt(b, 16)) ?? []);

describe("recovery phrase (ADR 20)", () => {
  it("matches the shared test vector in both directions", async () => {
    for (const c of vector.mnemonic) {
      const entropy = hexBytes(c.entropyHex);
      expect(await recoveryPhrase(entropy)).toBe(c.words);
      expect(await recoveryEntropy(c.words)).toEqual(entropy);
    }
  });

  it("round-trips a fresh random key and accepts sloppy typing", async () => {
    const e = newRecoveryKey();
    const phrase = await recoveryPhrase(e);
    expect(phrase.split(" ")).toHaveLength(24);
    expect(await recoveryEntropy(`  ${phrase.toUpperCase().replaceAll(" ", "   ")} `)).toEqual(e);
  });

  it("rejects a wrong word count, an unknown word and a bad checksum", async () => {
    const good = vector.mnemonic[0]?.words as string;
    await expect(recoveryEntropy(good.split(" ").slice(0, 23).join(" "))).rejects.toThrow(
      "24 words",
    );
    const unknown = good.replace("art", "artz");
    await expect(recoveryEntropy(unknown)).rejects.toThrow("not in the list");
    // Swapping the last word for another valid word changes the checksum bits.
    const badChecksum = good.replace(/art$/, "abandon");
    await expect(recoveryEntropy(badChecksum)).rejects.toThrow("checksum");
    // The error must not echo the phrase.
    await expect(recoveryEntropy(unknown)).rejects.not.toThrow(/artz/);
  });

  it("locks the private key with the recovery key and unlocks it with the same bytes only", async () => {
    const kp = await generateKeyPair();
    const e = newRecoveryKey();
    const locked = await lockWithRecoveryKey(kp.privateKey, e);
    expect(isRecoveryLockedKey(locked)).toBe(true);
    expect(await unlockWithRecoveryKey(locked, e)).toBe(kp.privateKey);
    await expect(unlockWithRecoveryKey(locked, newRecoveryKey())).rejects.toThrow();
  });
});

describe("fingerprint words (ADR 20)", () => {
  it("matches the shared test vector", async () => {
    for (const c of vector.fingerprint) {
      expect(await fingerprintWords(c.publicKey)).toBe(c.words);
    }
  });

  it("is four words from the list and depends on the key", async () => {
    const a = await generateKeyPair();
    const b = await generateKeyPair();
    const w = (await fingerprintWords(a.publicKey)).split(" ");
    expect(w).toHaveLength(4);
    expect(await fingerprintWords(a.publicKey)).toBe(w.join(" "));
    expect(await fingerprintWords(b.publicKey)).not.toBe(w.join(" "));
  });

  it("keeps the old hex fingerprint working", async () => {
    const k = await generateKeyPair();
    expect(await fingerprint(k.publicKey)).toMatch(/^([0-9A-F]{4}-){3}[0-9A-F]{4}$/);
  });

  it("normalizes typed words", () => {
    expect(normalizeWords("  Anchor\tVELVET  kiwi ")).toBe("anchor velvet kiwi");
  });
});

describe("locked key formats (ADR 20)", () => {
  it("accepts what lockPrivateKey produces and rejects other shapes", async () => {
    const kp = await generateKeyPair();
    const locked = await lockPrivateKey(kp.privateKey, "pw", 100_000);
    expect(isPrivateKeyLock(locked)).toBe(true);
    expect(isPrivateKeyLock("p1.1000.short.v1.x.y")).toBe(false);
    expect(
      isPrivateKeyLock(`p1.10.${locked.split(".")[2]}.${locked.split(".").slice(3).join(".")}`),
    ).toBe(false);
    expect(isPrivateKeyLock(undefined)).toBe(false);
    expect(isRecoveryLockedKey("rk1.v1.short.short")).toBe(false);
    expect(isRecoveryLockedKey("p1.v1.x.y")).toBe(false);
  });
});
