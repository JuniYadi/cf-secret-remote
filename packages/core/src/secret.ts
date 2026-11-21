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

// ADR 22: per-name fingerprints let the UI show added, changed and removed names between versions
// without showing values. A fingerprint needs the group key to check or to guess, so it is computed
// on the client only. The server stores it as-is.
export type Fingerprints = Record<string, string>;

/** `{ NAME: hex(HMAC-SHA256(groupKey, "fp|<path>|<NAME>|<value>")[0..8]) }`. */
export async function fingerprints(
  groupKey: Uint8Array,
  path: string,
  values: Values,
): Promise<Fingerprints> {
  const key = await crypto.subtle.importKey(
    "raw",
    groupKey as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const entries: [string, string][] = [];
  for (const [name, value] of Object.entries(values)) {
    const mac = new Uint8Array(
      await crypto.subtle.sign("HMAC", key, utf8(`fp|${path}|${name}|${value}`) as BufferSource),
    );
    entries.push([
      name,
      Array.from(mac.slice(0, 8), (b) => b.toString(16).padStart(2, "0")).join(""),
    ]);
  }
  return Object.fromEntries(entries);
}

export interface FingerprintDiff {
  added: string[];
  changed: string[];
  removed: string[];
}

/** Compares two fingerprint maps. `from` is the older version, `to` the newer. Names only, sorted. */
export function diffFingerprints(from: Fingerprints, to: Fingerprints): FingerprintDiff {
  const names = (o: Fingerprints) => Object.keys(o).sort();
  const added = names(to).filter((n) => !Object.hasOwn(from, n));
  const removed = names(from).filter((n) => !Object.hasOwn(to, n));
  const changed = names(to).filter((n) => Object.hasOwn(from, n) && from[n] !== to[n]);
  return { added, changed, removed };
}
