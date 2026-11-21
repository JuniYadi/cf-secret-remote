import { randomBytes, utf8 } from "./encoding.ts";

// ADR 23: optional passphrase seal for backup files. WebCrypto only.
// Layout (binary):
//   "CFSSEAL1" (8 bytes) | iterations, uint32 big-endian (4) | PBKDF2 salt (16) | AES-GCM iv (12) | ciphertext + tag
// Key = PBKDF2-SHA256(passphrase, salt, iterations) -> AES-256-GCM. The first 28 bytes (magic, iterations, salt)
// are the AAD, so changing the iteration count or salt makes decryption fail.

export const SEAL_MAGIC = "CFSSEAL1";
export const MIN_BACKUP_PASSPHRASE = 8;
export const BACKUP_SEAL_ITERATIONS = 600_000;
const MIN_ITERATIONS = 100_000;
const MAX_ITERATIONS = 2_000_000;
const HEAD = 28; // magic + iterations + salt
const IV = 12;
const MAGIC = utf8(SEAL_MAGIC);

export interface SealOptions {
  iterations?: number;
  /** Fixed salt and iv for the shared test vector only. Leave unset in production. */
  salt?: Uint8Array;
  iv?: Uint8Array;
}

/** True when the bytes start with the seal magic. A gzip file starts with 0x1f 0x8b instead. */
export function isSealedBackup(bytes: Uint8Array): boolean {
  if (bytes.length < HEAD + IV + 16) return false;
  return MAGIC.every((b, i) => bytes[i] === b);
}

async function deriveKey(passphrase: string, salt: Uint8Array, iterations: number) {
  const base = await crypto.subtle.importKey(
    "raw",
    utf8(passphrase) as BufferSource,
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Seals a backup file. Throws if the passphrase is shorter than MIN_BACKUP_PASSPHRASE. */
export async function sealBackup(
  plain: Uint8Array,
  passphrase: string,
  opts: SealOptions = {},
): Promise<Uint8Array> {
  if (passphrase.length < MIN_BACKUP_PASSPHRASE)
    throw new Error(`passphrase must be at least ${MIN_BACKUP_PASSPHRASE} characters`);
  const iterations = opts.iterations ?? BACKUP_SEAL_ITERATIONS;
  const salt = opts.salt ?? randomBytes(16);
  const iv = opts.iv ?? randomBytes(IV);
  const head = new Uint8Array(HEAD);
  head.set(MAGIC, 0);
  head[8] = (iterations >>> 24) & 0xff;
  head[9] = (iterations >>> 16) & 0xff;
  head[10] = (iterations >>> 8) & 0xff;
  head[11] = iterations & 0xff;
  head.set(salt, 12);
  const key = await deriveKey(passphrase, salt, iterations);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv as BufferSource, additionalData: head as BufferSource },
      key,
      plain as BufferSource,
    ),
  );
  const out = new Uint8Array(HEAD + IV + ct.length);
  out.set(head, 0);
  out.set(iv, HEAD);
  out.set(ct, HEAD + IV);
  return out;
}

/** Opens a sealed backup. A wrong passphrase and a damaged file give the same error on purpose. */
export async function openBackup(sealed: Uint8Array, passphrase: string): Promise<Uint8Array> {
  if (!isSealedBackup(sealed)) throw new Error("not a sealed backup");
  const iterations =
    ((sealed[8] as number) * 0x1000000 +
      (((sealed[9] as number) << 16) | ((sealed[10] as number) << 8) | (sealed[11] as number))) >>>
    0;
  if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS)
    throw new Error("bad seal parameters");
  const head = sealed.slice(0, HEAD);
  const salt = sealed.slice(12, HEAD);
  const iv = sealed.slice(HEAD, HEAD + IV);
  const ct = sealed.slice(HEAD + IV);
  const key = await deriveKey(passphrase, salt, iterations);
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv as BufferSource, additionalData: head as BufferSource },
        key,
        ct as BufferSource,
      ),
    );
  } catch {
    throw new Error("wrong passphrase or damaged file");
  }
}
