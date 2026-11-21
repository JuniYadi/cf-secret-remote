import { describe, expect, it } from "vitest";
import {
  chainHash,
  decodeKit,
  encodeKit,
  fingerprint,
  GENESIS,
  generateDek,
  generateKeyPair,
  lockPrivateKey,
  normalizeFingerprint,
  openText,
  sealText,
  unlockPrivateKey,
  unwrapDek,
  verifyChain,
  wrapDek,
} from "./index.ts";

describe("envelope", () => {
  it("round-trips and binds aad", async () => {
    const dek = await generateDek();
    const env = await sealText(dek, "sk-live-123", "secret:a:v1");
    expect(await openText(dek, env, "secret:a:v1")).toBe("sk-live-123");
    await expect(openText(dek, env, "secret:a:v2")).rejects.toThrow();
    await expect(openText(await generateDek(), env, "secret:a:v1")).rejects.toThrow();
  });
});

describe("key wrapping", () => {
  it("only the recipient can unwrap", async () => {
    const a = await generateKeyPair();
    const b = await generateKeyPair();
    const dek = await generateDek();
    const w = await wrapDek(dek, a.publicKey, "keyring:x:v1");
    expect(await unwrapDek(w, a.privateKey, a.publicKey, "keyring:x:v1")).toEqual(dek);
    await expect(unwrapDek(w, b.privateKey, b.publicKey, "keyring:x:v1")).rejects.toThrow();
    await expect(unwrapDek(w, a.privateKey, a.publicKey, "keyring:y:v1")).rejects.toThrow();
  });
  it("vault password locks the private key", async () => {
    const k = await generateKeyPair();
    const locked = await lockPrivateKey(k.privateKey, "correct horse", 1000);
    expect(await unlockPrivateKey(locked, "correct horse")).toBe(k.privateKey);
    await expect(unlockPrivateKey(locked, "wrong")).rejects.toThrow();
  });
});

describe("kit", () => {
  it("round-trips and validates", () => {
    const kit = { host: "https://s.example.com", roleId: "r", secretId: "s", privateKey: "k" };
    expect(decodeKit(encodeKit(kit))).toEqual(kit);
    expect(() => decodeKit("nope")).toThrow();
  });
});

describe("fingerprint", () => {
  it("is stable and normalizes typed input", async () => {
    const k = await generateKeyPair();
    const f = await fingerprint(k.publicKey);
    expect(f).toMatch(/^([0-9A-F]{4}-){3}[0-9A-F]{4}$/);
    expect(normalizeFingerprint(f.toLowerCase().replaceAll("-", " "))).toBe(f);
  });
});

describe("audit chain", () => {
  it("detects tampering", async () => {
    const entries = [
      { who: "a", what: "read", name: "x" },
      { who: "b", what: "read", name: "y" },
      { who: "a", what: "set", name: "x" },
    ];
    const rows = [];
    let prev = GENESIS;
    for (const entry of entries) {
      const hash = await chainHash(prev, entry);
      rows.push({ entry, hash });
      prev = hash;
    }
    expect(await verifyChain(rows)).toBe(-1);
    rows[1] = { ...rows[1]!, entry: { who: "z", what: "read", name: "y" } };
    expect(await verifyChain(rows)).toBe(1);
  });
});

import { newGroupKey, openSecret, sealSecret, unwrapGroupKey, wrapGroupKey } from "./index.ts";

describe("secret hierarchy", () => {
  it("round-trips and is bound to path and version", async () => {
    const m = await generateKeyPair();
    const gk = await newGroupKey();
    const wrapped = await wrapGroupKey(gk, m.publicKey, "payments", 1);
    const opened = await unwrapGroupKey(wrapped, m.privateKey, m.publicKey, "payments", 1);
    const s = await sealSecret(opened, "payments/prod", 3, { A: "1", B: "two" });
    expect(await openSecret(gk, "payments/prod", 3, s.wrappedDek, s.ciphertext)).toEqual({
      A: "1",
      B: "two",
    });
    await expect(openSecret(gk, "payments/prod", 4, s.wrappedDek, s.ciphertext)).rejects.toThrow();
    await expect(openSecret(gk, "payments/dev", 3, s.wrappedDek, s.ciphertext)).rejects.toThrow();
    await expect(
      unwrapGroupKey(wrapped, m.privateKey, m.publicKey, "payments", 2),
    ).rejects.toThrow();
  });
});
