import { fromUtf8, utf8 } from "./encoding.ts";
import { generateDek, open, seal } from "./envelope.ts";
import { unwrapDek, wrapDek } from "./keys.ts";

// ADR 10: group key -> DEK per version -> ciphertext. AADs bind each layer to its place.
export type Values = Record<string, string>;

export const groupAad = (prefix: string, keyringVersion: number) =>
  `keyring:${prefix}:v${keyringVersion}`;
const dekAad = (path: string, version: number) => `dek:${path}:v${version}`;
const valAad = (path: string, version: number) => `secret:${path}:v${version}`;

export const newGroupKey = generateDek;

export const wrapGroupKey = (
  groupKey: Uint8Array,
  memberPublicKey: string,
  prefix: string,
  keyringVersion: number,
) => wrapDek(groupKey, memberPublicKey, groupAad(prefix, keyringVersion));

export const unwrapGroupKey = (
  wrapped: string,
  privateKey: string,
  publicKey: string,
  prefix: string,
  keyringVersion: number,
) => unwrapDek(wrapped, privateKey, publicKey, groupAad(prefix, keyringVersion));

export async function sealSecret(
  groupKey: Uint8Array,
  path: string,
  version: number,
  values: Values,
) {
  const dek = await generateDek();
  return {
    wrappedDek: await seal(groupKey, dek, dekAad(path, version)),
    ciphertext: await seal(dek, utf8(JSON.stringify(values)), valAad(path, version)),
  };
}

export async function openSecret(
  groupKey: Uint8Array,
  path: string,
  version: number,
  wrappedDek: string,
  ciphertext: string,
): Promise<Values> {
  const dek = await open(groupKey, wrappedDek, dekAad(path, version));
  return JSON.parse(fromUtf8(await open(dek, ciphertext, valAad(path, version)))) as Values;
}
