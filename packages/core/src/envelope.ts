import { b64uDecode, b64uEncode, fromUtf8, randomBytes, utf8 } from "./encoding.ts";

// Envelope string: "v1.<iv>.<ciphertext>" (base64url). AES-256-GCM, 12-byte IV.
// `aad` binds a ciphertext to its place (e.g. "secret:<id>:v<version>"), so a row cannot be swapped.

export async function generateDek(): Promise<Uint8Array> {
  return randomBytes(32);
}

const importAes = (raw: Uint8Array, usage: "encrypt" | "decrypt") =>
  crypto.subtle.importKey("raw", raw as BufferSource, "AES-GCM", false, [usage]);

export async function seal(key: Uint8Array, plaintext: Uint8Array, aad: string): Promise<string> {
  const iv = randomBytes(12);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv as BufferSource, additionalData: utf8(aad) as BufferSource },
      await importAes(key, "encrypt"),
      plaintext as BufferSource,
    ),
  );
  return `v1.${b64uEncode(iv)}.${b64uEncode(ct)}`;
}

export async function open(key: Uint8Array, envelope: string, aad: string): Promise<Uint8Array> {
  const [v, iv, ct, extra] = envelope.split(".");
  if (v !== "v1" || !iv || !ct || extra !== undefined) throw new Error("bad envelope");
  return new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: b64uDecode(iv) as BufferSource,
        additionalData: utf8(aad) as BufferSource,
      },
      await importAes(key, "decrypt"),
      b64uDecode(ct) as BufferSource,
    ),
  );
}

export const sealText = (key: Uint8Array, text: string, aad: string) => seal(key, utf8(text), aad);
export const openText = async (key: Uint8Array, env: string, aad: string) =>
  fromUtf8(await open(key, env, aad));
