// Login envelopes are cached only in memory. Plaintext is opened by the caller's key resolver.
import { type Login, openLogin, unwrapGroupKey } from "@cfs/core";
import { API_BASE, ApiError, api, type FetchLike, request, send } from "./api.ts";
import { getPrivateKey, getPublicKey, subscribeKeys } from "./keystore.ts";
import { VaultLockedError } from "./secret-store.ts";

export interface LoginRecord {
  id: string;
  keyringId: string;
  keyringVersion: number;
  version: number;
  wrappedDek: string;
  ciphertext: string;
  fps: Record<string, string>;
  createdAt: number;
  updatedAt: number;
  size: number;
}
export interface LoginWrite {
  keyringId: string;
  keyringVersion: number;
  version: number;
  wrappedDek: string;
  ciphertext: string;
  fps: Record<string, string>;
}
export interface LoginVersion {
  version: number;
  keyringId: string;
  keyringVersion: number;
  fps: Record<string, string>;
  createdAt: number;
}
const path = (id: string) => `/logins/${encodeURIComponent(id)}`;

/** The cache belongs to this client, and contains ciphertext only. */
export function createLoginClient(fetchImpl?: FetchLike) {
  let etag: string | null = null;
  let cached: LoginRecord[] | null = null;
  const fetcher: FetchLike = fetchImpl ?? ((input, init) => fetch(input, init));
  const req = <T>(method: "GET" | "POST" | "PUT" | "DELETE", url: string, body?: unknown) =>
    request<T>(method, url, body, fetcher);
  return {
    list: async (): Promise<LoginRecord[]> => {
      // send normally rejects 304. Translate it only when this client has a matching cached response.
      const conditional: FetchLike = async (url, init) => {
        const res = await fetcher(url, init);
        if (res.status === 304 && cached !== null) {
          return new Response(JSON.stringify(cached), {
            status: 200,
            headers: { ETag: etag ?? "" },
          });
        }
        return res;
      };
      const res = await send(
        "GET",
        `${API_BASE}/logins`,
        undefined,
        conditional,
        etag && cached ? { "If-None-Match": etag } : {},
      );
      const rows = (await res.json()) as LoginRecord[];
      if (!Array.isArray(rows)) throw new Error("bad login list");
      cached = rows;
      etag = res.headers.get("ETag");
      return rows;
    },
    get: (id: string) => req<LoginRecord>("GET", path(id)),
    create: (id: string, body: LoginWrite) =>
      req<{ id: string; version: number }>("POST", "/logins", { id, ...body }),
    update: (id: string, body: LoginWrite) =>
      req<{ id: string; version: number }>("PUT", path(id), body),
    versions: (id: string) => req<LoginVersion[]>("GET", `${path(id)}/versions`),
    version: (id: string, version: number) =>
      req<LoginRecord>("GET", `${path(id)}/versions/${version}`),
    restore: (id: string, version: number, body: LoginWrite) =>
      req<{ id: string; version: number }>("POST", `${path(id)}/versions/${version}/restore`, body),
    delete: (id: string) => req<{ ok: true }>("DELETE", path(id)),
    undelete: (id: string) => req<{ ok: true }>("POST", `${path(id)}/undelete`),
    move: (id: string, body: LoginWrite) =>
      req<{ id: string; version: number }>("POST", `${path(id)}/move`, body),
    reveal: (id: string, body: { field?: keyof Omit<Login, "v">; purpose?: string } = {}) =>
      req<{ ok: true }>("POST", `${path(id)}/reveal`, body),
    fill: (id: string, body: { field?: keyof Omit<Login, "v">; purpose?: string } = {}) =>
      req<{ ok: true }>("POST", `${path(id)}/fill`, body),
  };
}
export const loginClient = createLoginClient();

// Unwrapped keys for this unlock only, so a list of N logins costs a few requests, not 3N.
const keyCache = new Map<string, Promise<Uint8Array>>();
subscribeKeys(() => keyCache.clear());

/** Resolve a login's keyring ID to the key for the version that sealed it. */
export function loginKeyFor(id: string, version: number): Promise<Uint8Array> {
  if (getPrivateKey() === null || getPublicKey() === null)
    return Promise.reject(new VaultLockedError());
  const k = `${id}:${version}`;
  const hit = keyCache.get(k);
  if (hit) return hit;
  const p = resolveLoginKey(id, version);
  keyCache.set(k, p);
  p.catch(() => keyCache.delete(k));
  return p;
}

async function resolveLoginKey(id: string, version: number): Promise<Uint8Array> {
  const priv = getPrivateKey();
  const pub = getPublicKey();
  if (priv === null || pub === null) throw new VaultLockedError();
  const [personal, groups] = await Promise.all([api.personalKeyring(), api.keyrings()]);
  if (personal?.id === id) {
    if (personal.version !== version) throw new Error("personal key version unavailable");
    return unwrapGroupKey(personal.wrappedKey, priv, pub, personal.prefix, version);
  }
  const group = groups.find((row) => row.id === id);
  if (!group) throw new Error("keyring unavailable");
  const key = await api.groupKey(group.prefix, version);
  if (key.version !== version) throw new Error("key version mismatch");
  return unwrapGroupKey(key.wrappedKey, priv, pub, group.prefix, version);
}

/** Only keyrings whose current key the caller can retrieve are valid write targets. */
export async function loginTargets(): Promise<
  { id: string; prefix: string; version: number; personal: boolean }[]
> {
  const [personal, groups] = await Promise.all([api.personalKeyring(), api.keyrings()]);
  const available = await Promise.all(
    groups.map(async (group) => {
      try {
        const key = await api.groupKey(group.prefix);
        return key.version === group.version ? { ...group, personal: false } : null;
      } catch (error) {
        if (error instanceof ApiError && (error.kind === "not-found" || error.kind === "forbidden"))
          return null;
        throw error;
      }
    }),
  );
  return [
    ...(personal
      ? [{ id: personal.id, prefix: personal.prefix, version: personal.version, personal: true }]
      : []),
    ...available.filter((group) => group !== null),
  ];
}
export interface OpenedLogin {
  record: LoginRecord;
  login: Login;
}
export async function decryptLoginList(
  rows: LoginRecord[],
  keyFor: (id: string, version: number) => Promise<Uint8Array>,
): Promise<OpenedLogin[]> {
  return Promise.all(
    rows.map(async (record) => ({
      record,
      login: await openLogin(
        await keyFor(record.keyringId, record.keyringVersion),
        record.id,
        record.version,
        record.wrappedDek,
        record.ciphertext,
      ),
    })),
  );
}
export function filterLogins(
  rows: OpenedLogin[],
  filters: { query?: string; keyring?: string; environment?: string; role?: string },
): OpenedLogin[] {
  const q = filters.query?.trim().toLocaleLowerCase() ?? "";
  return rows.filter(
    ({ record, login }) =>
      (!filters.keyring || record.keyringId === filters.keyring) &&
      (!filters.environment || login.environment === filters.environment) &&
      (!filters.role || login.role === filters.role) &&
      (!q ||
        [login.name, login.url, login.environment, login.role, login.username].some((s) =>
          s.toLocaleLowerCase().includes(q),
        )),
  );
}
