// Reads and writes secret versions for the screens. The browser does every seal and open, with @cfs/core
// (ADR 10, ADR 22). The server gets sealed envelopes and cleartext names, metadata and fingerprints only.
// Values and the group key stay in this module's call stack and the screen state, never in storage or a URL.

import { fingerprints, openSecret, sealSecret, unwrapGroupKey, type Values } from "@cfs/core";
import { ApiError, api, type SecretRecord, type SecretWrite } from "./api.ts";
import { getPrivateKey, getPublicKey } from "./keystore.ts";
import { groupOf } from "./secrets.ts";

/** Thrown when the vault is locked, so there is no private key to open a group key with. */
export class VaultLockedError extends Error {
  constructor() {
    super("locked");
    this.name = "VaultLockedError";
  }
}

/** A version the person can read: values are opened and the group key is in hand for a save. */
export interface OpenedSecret {
  path: string;
  version: number;
  names: string[];
  values: Values;
  groupKey: Uint8Array;
  /** The keyring version of the group key. A save must send this value (the server checks it). */
  keyVersion: number;
}

/** GET /secret. Throws ApiError for denied (403), not found (404), and network problems. */
export const fetchSecret = (path: string, version?: number): Promise<SecretRecord> =>
  api.secret(path, version);

/**
 * The group key for a group, unwrapped with the person's private key. A missing key is an ApiError
 * "not-found" (the person is not in the group); an expired one is "forbidden".
 */
export async function groupKeyFor(
  prefix: string,
): Promise<{ groupKey: Uint8Array; keyVersion: number }> {
  const priv = getPrivateKey();
  const pub = getPublicKey();
  if (priv === null || pub === null) throw new VaultLockedError();
  const key = await api.groupKey(prefix);
  const groupKey = await unwrapGroupKey(key.wrappedKey, priv, pub, prefix, key.version);
  return { groupKey, keyVersion: key.version };
}

/** Opens a fetched version with the group key of its group. */
export async function openFetched(record: SecretRecord): Promise<OpenedSecret> {
  const { groupKey, keyVersion } = await groupKeyFor(groupOf(record.path));
  const values = await openSecret(
    groupKey,
    record.path,
    record.version,
    record.wrappedDek,
    record.ciphertext,
  );
  return {
    path: record.path,
    version: record.version,
    names: record.names,
    values,
    groupKey,
    keyVersion,
  };
}

/** Fetch and open in one step. */
export async function loadSecret(path: string, version?: number): Promise<OpenedSecret> {
  return openFetched(await fetchSecret(path, version));
}

/**
 * Seals values as the next version and writes it. `currentVersion` is the version the person saw, so the
 * server accepts only currentVersion + 1 (a 409 means someone else wrote first). Fingerprints are computed
 * here with the group key (ADR 22).
 */
export async function saveValues(input: {
  path: string;
  values: Values;
  currentVersion: number;
  groupKey: Uint8Array;
  keyVersion: number;
}): Promise<{ path: string; version: number }> {
  const version = input.currentVersion + 1;
  const sealed = await sealSecret(input.groupKey, input.path, version, input.values);
  const fps = await fingerprints(input.groupKey, input.path, input.values);
  const body: SecretWrite = {
    path: input.path,
    names: Object.keys(input.values),
    wrappedDek: sealed.wrappedDek,
    ciphertext: sealed.ciphertext,
    keyringVersion: input.keyVersion,
    version,
    fps,
  };
  return api.writeSecret(body);
}

/** True when the server refused a write because the secret or the group moved on (ADR 10). */
export const isConflict = (err: unknown): boolean =>
  err instanceof ApiError && err.kind === "conflict";

/** True when the person has no key for this group (GET /keyrings/:prefix/key answered 404). */
export const isNoKey = (err: unknown): boolean =>
  err instanceof ApiError && err.kind === "not-found";
