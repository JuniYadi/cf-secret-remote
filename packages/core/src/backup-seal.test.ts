import { describe, expect, it } from "vitest";
import vector from "../test-vectors/backup-seal.json";
import {
  BACKUP_SEAL_ITERATIONS,
  isSealedBackup,
  MIN_BACKUP_PASSPHRASE,
  openBackup,
  sealBackup,
} from "./index.ts";

const hex = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (h) => Number.parseInt(h, 16));
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const utf8 = (s: string) => new TextEncoder().encode(s);
const text = (b: Uint8Array) => new TextDecoder().decode(b);

describe("ADR 23: backup passphrase seal", () => {
  it("matches the shared test vector (AES-GCM, PBKDF2-SHA256)", async () => {
    const sealed = await sealBackup(utf8(vector.plaintext), vector.passphrase, {
      iterations: vector.iterations,
      salt: hex(vector.salt),
      iv: hex(vector.iv),
    });
    expect(toHex(sealed)).toBe(vector.sealed);
    expect(text(await openBackup(hex(vector.sealed), vector.passphrase))).toBe(vector.plaintext);
  });

  it("round-trips with a fresh salt and iv each time", async () => {
    const a = await sealBackup(utf8("same"), "long enough pass");
    const b = await sealBackup(utf8("same"), "long enough pass");
    expect(toHex(a)).not.toBe(toHex(b));
    expect(text(await openBackup(a, "long enough pass"))).toBe("same");
    expect(isSealedBackup(a)).toBe(true);
    expect(BACKUP_SEAL_ITERATIONS).toBe(600_000);
  });

  it("refuses a wrong passphrase", async () => {
    const sealed = hex(vector.sealed);
    await expect(openBackup(sealed, "wrong passphrase")).rejects.toThrow(
      "wrong passphrase or damaged file",
    );
  });

  it("refuses a changed byte in the ciphertext", async () => {
    const sealed = hex(vector.sealed);
    sealed[sealed.length - 1] = (sealed[sealed.length - 1] as number) ^ 1;
    await expect(openBackup(sealed, vector.passphrase)).rejects.toThrow();
  });

  it("binds the iteration count and salt as AAD, so a changed header fails", async () => {
    const sealed = hex(vector.sealed);
    sealed[11] = (sealed[11] as number) ^ 1; // iterations: 600000 -> 600001
    await expect(openBackup(sealed, vector.passphrase)).rejects.toThrow();
    const salted = hex(vector.sealed);
    salted[12] = (salted[12] as number) ^ 1;
    await expect(openBackup(salted, vector.passphrase)).rejects.toThrow();
  });

  it("refuses iteration counts outside the allowed range", async () => {
    const low = hex(vector.sealed);
    low.set([0, 0, 0x01, 0x00], 8); // 256 iterations
    await expect(openBackup(low, vector.passphrase)).rejects.toThrow("bad seal parameters");
  });

  it("refuses a short passphrase when sealing", async () => {
    await expect(sealBackup(utf8("x"), "x".repeat(MIN_BACKUP_PASSPHRASE - 1))).rejects.toThrow(
      "at least 8",
    );
  });

  it("tells a sealed file from a plain gzip file", () => {
    expect(isSealedBackup(hex(vector.sealed))).toBe(true);
    expect(isSealedBackup(Uint8Array.from([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3]))).toBe(false);
  });
});
