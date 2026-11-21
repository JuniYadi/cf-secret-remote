import { b64uDecode, b64uEncode, randomBytes, utf8 } from "./encoding.ts";
import { open, seal } from "./envelope.ts";

// Identity keys are ECDH P-256. Public = SPKI, private = PKCS8, both base64url.
// A DEK is wrapped to a recipient with ephemeral ECDH + HKDF-SHA256 + AES-GCM (ECIES style).

export interface KeyPairB64 {
  publicKey: string;
  privateKey: string;
}

// Runtimes (DOM, Workers, Bun) type a few SubtleCrypto calls differently; the behaviour is identical.
// biome-ignore lint/suspicious/noExplicitAny: see above
const subtle: any = crypto.subtle;

const ECDH = { name: "ECDH", namedCurve: "P-256" } as const;

export async function generateKeyPair(): Promise<KeyPairB64> {
  const kp = (await subtle.generateKey(ECDH, true, ["deriveBits"])) as CryptoKeyPair;
  return {
    publicKey: b64uEncode(new Uint8Array(await subtle.exportKey("spki", kp.publicKey))),
    privateKey: b64uEncode(new Uint8Array(await subtle.exportKey("pkcs8", kp.privateKey))),
  };
}

const importPub = (b64: string) =>
  crypto.subtle.importKey("spki", b64uDecode(b64) as BufferSource, ECDH, true, []);
const importPriv = (b64: string) =>
  crypto.subtle.importKey("pkcs8", b64uDecode(b64) as BufferSource, ECDH, false, ["deriveBits"]);

async function wrapKey(
  priv: CryptoKey,
  pub: CryptoKey,
  epk: string,
  recipientPub: string,
): Promise<Uint8Array> {
  const shared = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256));
  const hkdf = await crypto.subtle.importKey("raw", shared as BufferSource, "HKDF", false, [
    "deriveBits",
  ]);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(0),
        info: utf8(`cfs-wrap-v1|${epk}|${recipientPub}`) as BufferSource,
      },
      hkdf,
      256,
    ),
  );
}

/** Wrap `dek` so that only the holder of `recipientPublicKey`'s private key can unwrap it. Returns "<epk>.<envelope>". */
export async function wrapDek(
  dek: Uint8Array,
  recipientPublicKey: string,
  aad: string,
): Promise<string> {
  const eph = (await subtle.generateKey(ECDH, true, ["deriveBits"])) as CryptoKeyPair;
  const epk = b64uEncode(new Uint8Array(await subtle.exportKey("spki", eph.publicKey)));
  const key = await wrapKey(
    eph.privateKey,
    await importPub(recipientPublicKey),
    epk,
    recipientPublicKey,
  );
  return `${epk}.${await seal(key, dek, aad)}`;
}

export async function unwrapDek(
  wrapped: string,
  privateKey: string,
  publicKey: string,
  aad: string,
): Promise<Uint8Array> {
  const i = wrapped.indexOf(".");
  if (i < 0) throw new Error("bad wrapped key");
  const epk = wrapped.slice(0, i);
  const key = await wrapKey(await importPriv(privateKey), await importPub(epk), epk, publicKey);
  return open(key, wrapped.slice(i + 1), aad);
}

// --- Vault password: protects the private key at rest on the server ---

export const PBKDF2_ITERATIONS = 600_000;

async function passwordKey(
  password: string,
  salt: Uint8Array,
  iterations: number,
): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey(
    "raw",
    utf8(password) as BufferSource,
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations },
      base,
      256,
    ),
  );
}

/** Returns "p1.<iterations>.<salt>.<envelope>". */
export async function lockPrivateKey(
  privateKey: string,
  password: string,
  iterations = PBKDF2_ITERATIONS,
): Promise<string> {
  const salt = randomBytes(16);
  const key = await passwordKey(password, salt, iterations);
  return `p1.${iterations}.${b64uEncode(salt)}.${await seal(key, b64uDecode(privateKey), "cfs-private-key")}`;
}

export async function unlockPrivateKey(locked: string, password: string): Promise<string> {
  const [tag, it, salt, ...rest] = locked.split(".");
  if (tag !== "p1" || !it || !salt) throw new Error("bad locked key");
  const key = await passwordKey(password, b64uDecode(salt), Number(it));
  return b64uEncode(await open(key, rest.join("."), "cfs-private-key"));
}
