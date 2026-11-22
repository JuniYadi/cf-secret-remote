import { b64uDecode, fromUtf8, utf8 } from "./encoding.ts";
import { generateDek, open, seal } from "./envelope.ts";
import { fingerprints, newGroupKey, wrapGroupKey } from "./secret.ts";

/** Login fields are encrypted together, including the name and URL. */
export interface Login {
  v: 1;
  name: string;
  url: string;
  environment: string;
  role: string;
  username: string;
  password: string;
  totp: string;
  notes: string;
}

export const LOGIN_CIPHERTEXT_LIMIT = 64 * 1024;
const fields = [
  "name",
  "url",
  "environment",
  "role",
  "username",
  "password",
  "totp",
  "notes",
] as const;
const dekAad = (id: string, version: number) => `login-dek:${id}:v${version}`;
const loginAad = (id: string, version: number) => `login:${id}:v${version}`;

function validateLogin(value: unknown): asserts value is Login {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("bad login");
  const v = value as Record<string, unknown>;
  if (
    v.v !== 1 ||
    Object.keys(v).length !== fields.length + 1 ||
    fields.some((f) => typeof v[f] !== "string")
  )
    throw new Error("bad login");
}

export async function sealLogin(groupKey: Uint8Array, id: string, version: number, login: Login) {
  validateLogin(login);
  const plaintext = utf8(JSON.stringify(login));
  if (plaintext.length + 16 > LOGIN_CIPHERTEXT_LIMIT) throw new Error("login ciphertext too large");
  const dek = await generateDek();
  return {
    wrappedDek: await seal(groupKey, dek, dekAad(id, version)),
    ciphertext: await seal(dek, plaintext, loginAad(id, version)),
  };
}

export async function openLogin(
  groupKey: Uint8Array,
  id: string,
  version: number,
  wrappedDek: string,
  ciphertext: string,
): Promise<Login> {
  const parts = ciphertext.split(".");
  if (parts.length !== 3 || !parts[2] || b64uDecode(parts[2]).length > LOGIN_CIPHERTEXT_LIMIT)
    throw new Error("bad login ciphertext");
  const dek = await open(groupKey, wrappedDek, dekAad(id, version));
  const value: unknown = JSON.parse(fromUtf8(await open(dek, ciphertext, loginAad(id, version))));
  validateLogin(value);
  return value;
}

/** Make a new version with a fresh DEK when moving between keyrings. */
export async function moveLogin(
  sourceKey: Uint8Array,
  destinationKey: Uint8Array,
  id: string,
  version: number,
  wrappedDek: string,
  ciphertext: string,
) {
  return sealLogin(
    destinationKey,
    id,
    version + 1,
    await openLogin(sourceKey, id, version, wrappedDek, ciphertext),
  );
}

export function loginFingerprints(groupKey: Uint8Array, id: string, login: Login) {
  validateLogin(login);
  return fingerprints(groupKey, id, Object.fromEntries(fields.map((f) => [f, login[f]])));
}

/** Generate a personal keyring key and its client-side wrapped copy. */
export async function createPersonalKeyring(publicKey: string, prefix: string) {
  const key = await newGroupKey();
  return { key, wrappedKey: await wrapGroupKey(key, publicKey, prefix, 1) };
}

/** Canonical web origin, including non-default port. Invalid and non-HTTP URLs do not match. */
export function loginOrigin(value: string): string | null {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:" ? url.origin : null;
  } catch {
    return null;
  }
}
export function sameLoginOrigin(a: string, b: string): boolean {
  const origin = loginOrigin(a);
  return origin !== null && origin === loginOrigin(b);
}

function base32(seed: string): Uint8Array {
  const s = seed.replace(/\s/g, "").toUpperCase();
  if (!/^[A-Z2-7]+={0,6}$/.test(s)) throw new Error("bad base32 seed");
  const unpadded = s.replace(/=+$/, "");
  if (![0, 2, 4, 5, 7].includes(unpadded.length % 8) || (s.includes("=") && s.length % 8 !== 0))
    throw new Error("bad base32 seed");
  let bits = 0,
    value = 0;
  const out: number[] = [];
  for (const ch of unpadded) {
    value = (value << 5) | "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 255);
    }
  }
  if (bits && value & ((1 << bits) - 1)) throw new Error("bad base32 seed");
  return new Uint8Array(out);
}

/** RFC 6238. `time` is Unix time in seconds. */
export async function totp(input: string, time = Date.now() / 1000): Promise<string> {
  let seed = input,
    algorithm = "SHA-1",
    digits = 6,
    period = 30;
  if (input.toLowerCase().startsWith("otpauth://")) {
    const uri = new URL(input);
    if (uri.protocol !== "otpauth:" || uri.hostname !== "totp") throw new Error("bad TOTP URI");
    seed = uri.searchParams.get("secret") ?? "";
    const alg = (uri.searchParams.get("algorithm") ?? "SHA1").toUpperCase();
    algorithm =
      ({ SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" } as Record<string, string>)[alg] ??
      "";
    digits = Number(uri.searchParams.get("digits") ?? 6);
    period = Number(uri.searchParams.get("period") ?? 30);
  }
  if (
    !algorithm ||
    !Number.isInteger(digits) ||
    digits < 6 ||
    digits > 8 ||
    !Number.isSafeInteger(period) ||
    period < 1 ||
    !Number.isFinite(time) ||
    time < 0
  )
    throw new Error("bad TOTP parameters");
  const counter = Math.floor(time / period);
  if (!Number.isSafeInteger(counter)) throw new Error("bad TOTP time");
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(counter));
  const key = await crypto.subtle.importKey(
    "raw",
    base32(seed) as BufferSource,
    { name: "HMAC", hash: algorithm },
    false,
    ["sign"],
  );
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, bytes));
  const offset = (mac[mac.length - 1] as number) & 15;
  const binary = new DataView(mac.buffer).getUint32(offset) & 0x7fffffff;
  return String(binary % 10 ** digits).padStart(digits, "0");
}
