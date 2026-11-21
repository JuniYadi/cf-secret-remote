import { b64uDecode } from "./encoding.ts";

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
