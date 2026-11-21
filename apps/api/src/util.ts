import { b64uEncode, randomBytes } from "@cfs/core";

export const now = () => Math.floor(Date.now() / 1000);
export const newId = () => b64uEncode(randomBytes(12));
export const newToken = (prefix: string) => `${prefix}_${b64uEncode(randomBytes(32))}`;

export async function sha256Hex(s: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
  return Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
}
