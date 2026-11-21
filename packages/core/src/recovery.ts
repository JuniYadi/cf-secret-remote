import { b64uDecode, b64uEncode, randomBytes, utf8 } from "./encoding.ts";
import { open, seal } from "./envelope.ts";
import { BIP39_ENGLISH } from "./words.ts";

// ADR 20. Recovery key: 32 random bytes, shown once as a 24-word BIP-39 phrase (256 bits + 8-bit checksum).
// The recovery key locks the private key with a key derived by HKDF-SHA256 from those bytes.

export const RECOVERY_BYTES = 32;
const WORD_INDEX = new Map(BIP39_ENGLISH.map((w, i) => [w, i]));

const sha256 = async (b: Uint8Array) =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", b as BufferSource));

export const newRecoveryKey = (): Uint8Array => randomBytes(RECOVERY_BYTES);

/** 32 bytes to 24 words. Entropy plus the first byte of SHA-256(entropy) is 264 bits, 11 bits per word. */
export async function recoveryPhrase(entropy: Uint8Array): Promise<string> {
  if (entropy.length !== RECOVERY_BYTES) throw new Error("a recovery key is 32 bytes");
  const checksum = (await sha256(entropy))[0] as number;
  const bytes = [...entropy, checksum];
  const words: string[] = [];
  for (let w = 0; w < 24; w++) {
    let index = 0;
    for (let bit = 0; bit < 11; bit++) {
      const pos = w * 11 + bit;
      const byte = bytes[pos >> 3] as number;
      index = index * 2 + ((byte >> (7 - (pos & 7))) & 1);
    }
    words.push(BIP39_ENGLISH[index] as string);
  }
  return words.join(" ");
}

/** 24 words to the 32 bytes. Rejects a wrong word count, an unknown word, or a bad checksum. */
export async function recoveryEntropy(phrase: string): Promise<Uint8Array> {
  const words = phrase.trim().toLowerCase().split(/\s+/);
  if (words.length !== 24) throw new Error("a recovery key has 24 words");
  const bytes = new Uint8Array(33);
  for (let w = 0; w < 24; w++) {
    // Unknown words are not echoed back: the phrase is a secret.
    const index = WORD_INDEX.get(words[w] as string);
    if (index === undefined) throw new Error(`word ${w + 1} is not in the list`);
    for (let bit = 0; bit < 11; bit++) {
      const pos = w * 11 + bit;
      if ((index >> (10 - bit)) & 1) (bytes[pos >> 3] as number) |= 1 << (7 - (pos & 7));
    }
  }
  const entropy = bytes.slice(0, RECOVERY_BYTES);
  if ((await sha256(entropy))[0] !== bytes[32])
    throw new Error("the recovery key checksum is wrong");
  return entropy;
}

const recoveryWrapKey = async (entropy: Uint8Array): Promise<Uint8Array> => {
  const base = await crypto.subtle.importKey("raw", entropy as BufferSource, "HKDF", false, [
    "deriveBits",
  ]);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(0),
        info: utf8("cfs-recovery-key-v1") as BufferSource,
      },
      base,
      256,
    ),
  );
};

/** Returns "rk1.<envelope>". The envelope is the private key (PKCS8, base64url) sealed under the recovery key. */
export async function lockWithRecoveryKey(
  privateKey: string,
  entropy: Uint8Array,
): Promise<string> {
  const key = await recoveryWrapKey(entropy);
  return `rk1.${await seal(key, b64uDecode(privateKey), "cfs-recovery-private-key")}`;
}

export async function unlockWithRecoveryKey(locked: string, entropy: Uint8Array): Promise<string> {
  if (!isRecoveryLockedKey(locked)) throw new Error("bad recovery locked key");
  const key = await recoveryWrapKey(entropy);
  return b64uEncode(await open(key, locked.slice(4), "cfs-recovery-private-key"));
}

// Format checks for the server and clients. They check shape only; the server cannot check the key inside.
const B64U = "[A-Za-z0-9_-]";
const PRIVATE_LOCK_RE = new RegExp(
  `^p1\\.(\\d{6,8})\\.${B64U}{22}\\.v1\\.${B64U}{16}\\.${B64U}{16,}$`,
);
const RECOVERY_LOCK_RE = new RegExp(`^rk1\\.v1\\.${B64U}{16}\\.${B64U}{16,}$`);

/** Vault password lock: "p1.<iterations>.<salt 16 bytes>.v1.<iv 12 bytes>.<ciphertext>". */
export function isPrivateKeyLock(s: unknown): s is string {
  if (typeof s !== "string" || !PRIVATE_LOCK_RE.test(s)) return false;
  const it = Number(s.split(".")[1]);
  return it >= 100_000 && it <= 10_000_000;
}

/** Recovery key lock: "rk1.v1.<iv>.<ciphertext>". */
export const isRecoveryLockedKey = (s: unknown): s is string =>
  typeof s === "string" && RECOVERY_LOCK_RE.test(s);
