import { unlockPrivateKey } from "@cfs/core";

export interface LoginRow {
  id: string;
  version: number;
  keyringId: string;
  keyringVersion: number;
  wrappedDek: string;
  ciphertext: string;
}
export interface Session {
  token: string;
  tokenExpires: number;
  privateKey?: string;
  publicKey?: string;
  unlockExpires?: number;
}
export interface Cache {
  host: string;
  etag?: string;
  logins?: LoginRow[];
}

export function normalizeHost(value: string): string {
  const url = new URL(value);
  if (
    (url.protocol !== "https:" &&
      !(url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname))) ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  )
    throw new Error("Invalid host");
  return url.origin;
}
export async function request(host: string, path: string, options: RequestInit = {}) {
  const res = await fetch(`${host}/api/v1${path}`, options);
  if (!res.ok && res.status !== 304 && res.status !== 202)
    throw new Error(`Request failed (${res.status})`);
  return res;
}
export const json = (body: unknown, token?: string): RequestInit => ({
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  },
  body: JSON.stringify(body),
});
export const auth = (token: string) => ({ Authorization: `Bearer ${token}` });
export async function sync(host: string, token: string): Promise<LoginRow[]> {
  const cache = (await chrome.storage.local.get(["host", "etag", "logins"])) as Cache;
  const headers: Record<string, string> = auth(token);
  if (cache.host === host && cache.etag && cache.logins) headers["If-None-Match"] = cache.etag;
  const res = await request(host, "/logins", { headers });
  if (res.status === 304) return cache.logins ?? [];
  const logins = (await res.json()) as LoginRow[];
  await chrome.storage.local.set({ host, etag: res.headers.get("ETag"), logins });
  return logins;
}
export async function unlock(host: string, session: Session, password: string): Promise<Session> {
  const me = (await (await request(host, "/whoami", { headers: auth(session.token) })).json()) as {
    lockedKey: string | null;
    publicKey: string | null;
  };
  if (!me.lockedKey || !me.publicKey) throw new Error("Vault is not set up");
  const privateKey = await unlockPrivateKey(me.lockedKey, password);
  const next = {
    ...session,
    privateKey,
    publicKey: me.publicKey,
    unlockExpires: Date.now() + 3600000,
  };
  await sync(host, session.token);
  await chrome.storage.session.set({ session: next });
  return next;
}
export async function getSession(): Promise<Session | undefined> {
  const { session } = (await chrome.storage.session.get("session")) as { session?: Session };
  if (!session) return;
  if (session.tokenExpires <= Date.now()) {
    await chrome.storage.session.remove("session");
    return;
  }
  if (session.unlockExpires && session.unlockExpires <= Date.now()) {
    delete session.privateKey;
    delete session.publicKey;
    delete session.unlockExpires;
    await chrome.storage.session.set({ session });
  }
  return session;
}

export async function openLogins(
  host: string,
  session: Session,
): Promise<{ id: string; login: import("@cfs/core").Login }[]> {
  if (
    !session.privateKey ||
    !session.publicKey ||
    !session.unlockExpires ||
    session.unlockExpires <= Date.now()
  )
    throw new Error("Locked");
  const { openLogin, unwrapGroupKey } = await import("@cfs/core");
  const headers = auth(session.token);
  const [groups, personal, cache] = await Promise.all([
    request(host, "/keyrings", { headers }).then((r) => r.json()) as Promise<
      { id: string; prefix: string }[]
    >,
    request(host, "/me/personal-keyring", { headers }).then((r) => r.json()) as Promise<{
      id: string;
      prefix: string;
      version: number;
      wrappedKey: string;
    } | null>,
    chrome.storage.local.get("logins") as Promise<{ logins?: LoginRow[] }>,
  ]);
  const keys = new Map<string, Uint8Array>();
  const out: { id: string; login: import("@cfs/core").Login }[] = [];
  for (const row of cache.logins ?? []) {
    const group =
      groups.find((g) => g.id === row.keyringId) ??
      (personal?.id === row.keyringId ? personal : undefined);
    if (!group) continue;
    const cacheKey = `${row.keyringId}:${row.keyringVersion}`;
    let key = keys.get(cacheKey);
    if (!key) {
      const wrapped =
        personal?.id === row.keyringId && personal.version === row.keyringVersion
          ? personal
          : ((await request(
              host,
              `/keyrings/${encodeURIComponent(group.prefix)}/key?version=${row.keyringVersion}`,
              { headers },
            ).then((r) => r.json())) as { wrappedKey: string });
      key = await unwrapGroupKey(
        wrapped.wrappedKey,
        session.privateKey,
        session.publicKey,
        group.prefix,
        row.keyringVersion,
      );
      keys.set(cacheKey, key);
    }
    out.push({
      id: row.id,
      login: await openLogin(key, row.id, row.version, row.wrappedDek, row.ciphertext),
    });
  }
  return out;
}
