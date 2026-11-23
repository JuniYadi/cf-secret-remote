// Groups: create, add member, and the staged re-key when a member is removed (ADR 3, ADR 14).
// The browser does all the crypto with @cfs/core. The server gets wrapped keys and ciphertext only.
// Group keys and values are kept in local variables for the duration of one call and never stored.

import {
  isReservedGroupName,
  loginFingerprints,
  newGroupKey,
  openLogin,
  openSecret,
  sealLogin,
  sealSecret,
  unwrapGroupKey,
  type Values,
  wrapGroupKey,
} from "@cfs/core";
import {
  type GroupMember,
  type Identity,
  type RotateSecret,
  api as realApi,
  type SecretListRow,
} from "./api.ts";
import { getPrivateKey, getPublicKey } from "./keystore.ts";

/** Same as the server's CHUNK_SIZE (membership.ts). A chunk request above it is refused with 400. */
export const CHUNK_SIZE = 50;

/** A person or bot the group key can be wrapped to. */
export interface PersonKey {
  identityId: string;
  name: string;
  publicKey: string;
}

/** Thrown when an operation needs the unlocked key and the vault is locked. */
export class VaultLockedError extends Error {
  constructor() {
    super("vault locked");
    this.name = "VaultLockedError";
  }
}

/** Splits a list into pieces of at most `size` items. Keeps order. */
export function chunk<T>(items: readonly T[], size: number = CHUNK_SIZE): T[][] {
  if (!Number.isInteger(size) || size < 1) throw new RangeError("chunk size must be 1 or more");
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

/**
 * Active admins who hold a vault (ADR 20, two-admin rule). The Groups page warns below two.
 * The server refuses a demotion that would leave fewer than two, so this is a warning, not a gate.
 */
export function adminsWithVault(identities: readonly Identity[]): number {
  return identities.filter(
    (i) => i.kind === "user" && i.role === "admin" && i.status === "active" && i.publicKey !== null,
  ).length;
}

/** A group name is the first path segment (ADR 3): letters, digits, dots, dashes and underscores. */
const PREFIX_RE = /^[a-z0-9][a-z0-9._-]*$/i;

/** Trims spaces and one trailing slash, so "data/" (as the board shows it) becomes "data". */
export function normalizePrefix(raw: string): string {
  return raw.trim().replace(/\/$/, "");
}

export type PrefixError = "empty" | "shape" | "exists" | "reserved";

/** Checks a group name. `existing` is the list of groups already made, to refuse duplicates early. */
export function validatePrefix(raw: string, existing: readonly string[] = []): PrefixError | null {
  const value = normalizePrefix(raw);
  if (value === "") return "empty";
  if (value.length > 64 || !PREFIX_RE.test(value)) return "shape";
  if (isReservedGroupName(value)) return "reserved";
  if (existing.includes(value)) return "exists";
  return null;
}

/** The secrets a group holds, by path. Only paths under `prefix/` belong to it. */
export function groupSecrets(all: readonly SecretListRow[], prefix: string): SecretListRow[] {
  return all.filter((s) => s.path.startsWith(`${prefix}/`));
}

export type RemovalPlan =
  | { ok: true; remaining: PersonKey[] }
  | { ok: false; reason: "self" | "notMember" | "noKey"; name?: string };

/**
 * Who stays after removing `removeId`. Every person who stays needs a public key, because the new group key
 * is wrapped to each of them. The rotating admin cannot remove themselves (the server refuses it too).
 */
export function planRemoval(
  members: readonly GroupMember[],
  identities: readonly Identity[],
  removeId: string,
  myId: string,
): RemovalPlan {
  if (removeId === myId) return { ok: false, reason: "self" };
  const target = members.find((m) => m.identityId === removeId);
  if (!target) return { ok: false, reason: "notMember" };
  const byId = new Map(identities.map((i) => [i.id, i]));
  const remaining: PersonKey[] = [];
  for (const m of members) {
    if (m.identityId === removeId) continue;
    const who = byId.get(m.identityId);
    if (!who?.publicKey) return { ok: false, reason: "noKey", name: m.name };
    remaining.push({ identityId: m.identityId, name: m.name, publicKey: who.publicKey });
  }
  return { ok: true, remaining };
}

/** Per-secret progress for the re-locking screen. Names only, never values. */
export type RelockState = "waiting" | "now" | "done";

export interface RelockProgress {
  total: number;
  done: number;
  /** Path of the secret being re-locked, or null before the first and after the last. */
  current: string | null;
  /** One entry per path, in order. */
  items: { path: string; state: RelockState }[];
}

export function initialProgress(paths: readonly string[]): RelockProgress {
  return {
    total: paths.length,
    done: 0,
    current: null,
    items: paths.map((path) => ({ path, state: "waiting" })),
  };
}

/** Sets one path's state and recounts. Pure: returns a new object, the input is not changed. */
export function setState(
  progress: RelockProgress,
  path: string,
  state: RelockState,
): RelockProgress {
  const items = progress.items.map((item) =>
    item.path === path ? { path: item.path, state } : { ...item },
  );
  return {
    total: progress.total,
    done: items.filter((i) => i.state === "done").length,
    current: state === "now" ? path : progress.current === path ? null : progress.current,
    items,
  };
}

export interface RotationInput {
  prefix: string;
  /** Keyring version the admin holds the old key for. */
  currentVersion: number;
  removeIdentityId: string;
  remaining: readonly PersonKey[];
  /** The group key at currentVersion, opened from the admin's wrapped copy. */
  oldKey: Uint8Array;
  /** The group's secrets (names and paths). */
  secrets: readonly SecretListRow[];
  onProgress?: (progress: RelockProgress) => void;
}

export class RotationError extends Error {
  readonly stage: "start" | "secrets" | "commit";
  constructor(stage: "start" | "secrets" | "commit", cause: unknown) {
    super(stage);
    this.name = "RotationError";
    this.stage = stage;
    this.cause = cause;
  }
}

/**
 * Staged re-key (ADR 14): start, re-encrypt each secret's current version under a new group key in chunks
 * of at most 50, then commit. Any failure after start calls abort, so the group stays on the old version.
 * The removed person's access ends at start, so an abort cannot give it back; the UI says so.
 */
export async function runRotation(input: RotationInput, api = realApi): Promise<RelockProgress> {
  const next = input.currentVersion + 1;
  const newKey = await newGroupKey();
  const wrapped = await Promise.all(
    input.remaining.map(async (m) => ({
      identityId: m.identityId,
      wrappedKey: await wrapGroupKey(newKey, m.publicKey, input.prefix, next),
    })),
  );

  let progress = initialProgress(input.secrets.map((s) => s.path));
  input.onProgress?.(progress);

  try {
    await api.rotateStart(input.prefix, input.removeIdentityId, wrapped);
  } catch (err) {
    throw new RotationError("start", err);
  }

  try {
    for (const paths of chunk(input.secrets.map((s) => s.path))) {
      const batch: RotateSecret[] = [];
      for (const path of paths) {
        progress = setState(progress, path, "now");
        input.onProgress?.(progress);
        const row = await api.secretVersion(path);
        const values: Values = await openSecret(
          input.oldKey,
          path,
          row.version,
          row.wrappedDek,
          row.ciphertext,
        );
        const sealed = await sealSecret(newKey, path, row.version + 1, values);
        batch.push({
          path,
          names: Object.keys(values),
          wrappedDek: sealed.wrappedDek,
          ciphertext: sealed.ciphertext,
          version: row.version + 1,
        });
      }
      await api.rotateChunk(input.prefix, next, batch);
      for (const item of batch) progress = setState(progress, item.path, "done");
      input.onProgress?.(progress);
    }
    const logins = await api.rotateLogins(input.prefix);
    for (const part of chunk(logins)) {
      const batch = await Promise.all(
        part.map(async (row) => {
          const value = await openLogin(
            input.oldKey,
            row.id,
            row.version,
            row.wrappedDek,
            row.ciphertext,
          );
          return {
            id: row.id,
            version: row.version + 1,
            ...(await sealLogin(newKey, row.id, row.version + 1, value)),
            fps: await loginFingerprints(newKey, row.id, value),
          };
        }),
      );
      await api.rotateLoginChunk(input.prefix, next, batch);
    }
  } catch (err) {
    await abortQuietly(input.prefix, api);
    throw new RotationError("secrets", err);
  }

  try {
    await api.rotateCommit(input.prefix);
  } catch (err) {
    await abortQuietly(input.prefix, api);
    throw new RotationError("commit", err);
  }
  return progress;
}

async function abortQuietly(prefix: string, client: typeof realApi): Promise<void> {
  try {
    await client.rotateAbort(prefix);
  } catch {
    // The abort itself failed. The group stays rotating until someone retries, and the UI says so.
  }
}

/** The group key at the admin's current version, unwrapped in the browser. */
export async function openMyGroupKey(
  prefix: string,
  client = realApi,
): Promise<{ key: Uint8Array; version: number }> {
  const priv = getPrivateKey();
  const pub = getPublicKey();
  if (priv === null || pub === null) throw new VaultLockedError();
  const { wrappedKey, version } = await client.myGroupKey(prefix);
  const key = await unwrapGroupKey(wrappedKey, priv, pub, prefix, version);
  return { key, version };
}

/** Creates a group. The browser makes the key and wraps it to each person, including the creator. */
export async function createGroup(
  prefix: string,
  people: readonly PersonKey[],
  client = realApi,
): Promise<void> {
  if (getPrivateKey() === null) throw new VaultLockedError();
  const key = await newGroupKey();
  const members = await Promise.all(
    people.map(async (p) => ({
      identityId: p.identityId,
      wrappedKey: await wrapGroupKey(key, p.publicKey, prefix, 1),
    })),
  );
  await client.createKeyring(prefix, members);
}

/** Adds one person to a group. The admin unwraps the current key, then wraps it to the new person. */
export async function addPersonToGroup(
  prefix: string,
  person: PersonKey,
  client = realApi,
): Promise<void> {
  const { key, version } = await openMyGroupKey(prefix, client);
  const wrappedKey = await wrapGroupKey(key, person.publicKey, prefix, version);
  await client.addGroupMember(prefix, person.identityId, wrappedKey);
}
