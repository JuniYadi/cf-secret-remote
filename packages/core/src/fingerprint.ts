import { b64uDecode } from "./encoding.ts";
import { BIP39_ENGLISH } from "./words.ts";

/** Short code of a public key, e.g. "3FA9-81C2-D07B-6E54". Typed by an admin to confirm a recovery. */
export async function fingerprint(publicKey: string): Promise<string> {
  const h = new Uint8Array(
    await crypto.subtle.digest("SHA-256", b64uDecode(publicKey) as BufferSource),
  );
  const hex = Array.from(h.slice(0, 8), (b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
  return hex.match(/.{4}/g)!.join("-");
}

export const normalizeFingerprint = (s: string): string => {
  const hex = s.replace(/[^0-9a-fA-F]/g, "").toUpperCase();
  return hex.match(/.{1,4}/g)?.join("-") ?? "";
};

/**
 * ADR 20 fingerprint code: the first 44 bits of SHA-256 of the public key (SPKI bytes), as four words
 * from the BIP-39 English list, 11 bits each. E.g. "anchor velvet kiwi sixty".
 */
export async function fingerprintWords(publicKey: string): Promise<string> {
  const h = new Uint8Array(
    await crypto.subtle.digest("SHA-256", b64uDecode(publicKey) as BufferSource),
  );
  // Six bytes is 48 bits, which fits a double exactly; the low 4 bits are dropped to leave 44.
  let v = 0;
  for (let i = 0; i < 6; i++) v = v * 256 + (h[i] as number);
  v = Math.floor(v / 16);
  const words: string[] = [];
  for (let i = 3; i >= 0; i--) {
    const index = Math.floor(v / 2 ** (11 * i)) % 2048;
    words.push(BIP39_ENGLISH[index] as string);
  }
  return words.join(" ");
}

/** Normalizes typed words: lower case, single spaces. */
export const normalizeWords = (s: string): string => s.trim().toLowerCase().split(/\s+/).join(" ");
