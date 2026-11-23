import {
  decodeKit,
  fingerprints,
  type Kit,
  openSecret,
  sealSecret,
  unwrapGroupKey,
  type Values,
} from "@cfs/core";
import {
  CliError,
  ensureTrusted,
  loadSession,
  normalizeHost,
  resolveHost,
  type TrustDeps,
} from "./config.ts";
import { loadUnlock, pickStore } from "./keychain.ts";
import { confirm } from "./prompt.ts";
import { checkServer } from "./server.ts";
import { signIn } from "./signin.ts";

export { CliError };

export interface Client {
  host: string;
  privateKey?: string;
  call<T = unknown>(
    method: string,
    path: string,
    body?: unknown,
    headers?: Record<string, string>,
  ): Promise<{ status: number; body: T }>;
  /** Like call, with extra request headers (ADR 23: the backup passphrase travels in a header only). */
  send<T = unknown>(
    method: string,
    path: string,
    body?: unknown,
    headers?: Record<string, string>,
  ): Promise<{ status: number; body: T }>;
  /** A binary GET. On a refusal, `error` holds the server's message. */
  download(
    path: string,
    headers?: Record<string, string>,
  ): Promise<{ status: number; bytes: Uint8Array; error?: string }>;
}

async function raw<T>(
  host: string,
  method: string,
  path: string,
  body?: unknown,
  token?: string,
  headers: Record<string, string> = {},
) {
  let r: Response;
  try {
    r = await fetch(`${host}/api/v1${path}`, {
      method,
      headers: {
        "content-type": "application/json",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...headers,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new CliError(`Cannot reach ${host}. Check the host and your network.`);
  }
  return { status: r.status, body: (await r.json().catch(() => ({}))) as T };
}

async function rawBytes(
  host: string,
  path: string,
  token: string | undefined,
  extra: Record<string, string> = {},
) {
  let r: Response;
  try {
    r = await fetch(`${host}/api/v1${path}`, {
      headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...extra },
    });
  } catch {
    throw new CliError(`Cannot reach ${host}. Check the host and your network.`);
  }
  const bytes = new Uint8Array(await r.arrayBuffer());
  let error: string | undefined;
  if (r.status !== 200) {
    try {
      error = (JSON.parse(new TextDecoder().decode(bytes)) as { error?: string }).error;
    } catch {
      error = undefined;
    }
  }
  return { status: r.status, bytes, error };
}

/** A client that sends `token` with every request. */
function signed(host: string, token: string, privateKey?: string): Client {
  return {
    host,
    privateKey,
    call: (m, p, b, h) => raw(host, m, p, b, token, h),
    send: (m, p, b, h) => raw(host, m, p, b, token, h),
    download: (p, h) => rawBytes(host, p, token, h),
  };
}

export const anonymous = (host: string) => ({
  call: <T = unknown>(method: string, path: string, body?: unknown) =>
    raw<T>(host, method, path, body),
});

/** Asks the user on the terminal before trusting a new host (ADR 25). */
export const terminalTrust = (): TrustDeps => ({
  interactive: Boolean(process.stdin.isTTY),
  confirm: (q) => confirm(q),
  signIn: (host) => signIn(host, new URL(host).hostname),
});

/** A signed-in client: CFS_KIT (apps) or the saved session (people). */
export async function connect(
  hostFlag?: string,
  trust: TrustDeps = terminalTrust(),
): Promise<Client> {
  const kitStr = process.env.CFS_KIT;
  if (kitStr) {
    const kit: Kit = decodeKit(kitStr);
    const host = normalizeHost(kit.host);
    await checkServer(host);
    const r = await raw<{ token?: string }>(host, "POST", "/auth/approle/login", {
      roleId: kit.roleId,
      secretId: kit.secretId,
    });
    if (!r.body.token)
      throw new CliError("The access kit was refused. It may be revoked or expired.");
    return signed(host, r.body.token, kit.privateKey);
  }
  const resolved = resolveHost(hostFlag);
  if (!resolved)
    throw new CliError(
      "No server set. Run: cfs login --host https://your-server, or add .cfs.json with a host.",
    );
  await ensureTrusted(resolved, trust);
  const host = resolved.host;
  const s = loadSession();
  if (!s) throw new CliError(`You are not signed in to ${host}. Run: cfs login --host ${host}`);
  if (s.host !== host)
    throw new CliError(
      `You are signed in to ${s.host}, not ${host}. Run: cfs login --host ${host}`,
    );
  await checkServer(host);
  return signed(host, s.token, await loadUnlock(pickStore(), host));
}

function fail(status: number, body: unknown, what: string): never {
  const msg = (body as { error?: string })?.error ?? `status ${status}`;
  if (status === 401) throw new CliError("Your session ended. Run: cfs login");
  if (status === 403) throw new CliError(`Not allowed: ${what}. Ask an admin for access.`);
  throw new CliError(`${what}: ${msg}`);
}

/** The group key for `prefix` at the current version. Exported for the agent proxy (ADR 17). */
export async function groupKey(
  c: Client,
  prefix: string,
): Promise<{ key: Uint8Array; version: number }> {
  if (!c.privateKey) throw new CliError("Your vault is locked. Run: cfs unlock");
  const [me, k] = await Promise.all([
    c.call<{ publicKey: string }>("GET", "/whoami"),
    c.call<{ wrappedKey: string; version: number }>("GET", `/keyrings/${prefix}/key`),
  ]);
  if (k.status === 404)
    throw new CliError(`You are not in the "${prefix}" group, so you cannot open its secrets.`);
  if (k.status !== 200) fail(k.status, k.body, "load group key");
  return {
    key: await unwrapGroupKey(
      k.body.wrappedKey,
      c.privateKey,
      me.body.publicKey,
      prefix,
      k.body.version,
    ),
    version: k.body.version,
  };
}

interface SealedVersion {
  version: number;
  keyringVersion: number;
  wrappedDek: string;
  ciphertext: string;
}

/** Fetches one version (the current one if omitted). Each fetch is audited as an open (ADR 22). */
async function fetchVersion(c: Client, path: string, version?: number, merge = false) {
  const q = version ? `&version=${version}` : "";
  return c.call<SealedVersion>(
    "GET",
    `/secret?path=${encodeURIComponent(path)}${q}${merge ? "&merge=1" : ""}`,
  );
}

export async function readSecret(
  c: Client,
  path: string,
  version?: number,
): Promise<{ values: Values; version: number }> {
  const r = await fetchVersion(c, path, version);
  if (r.status === 404)
    throw new CliError(version ? `No version ${version} of "${path}".` : `No secret at "${path}".`);
  if (r.status !== 200) fail(r.status, r.body, `read ${path}`);
  const prefix = path.split("/")[0] as string;
  const { key } = await groupKey(c, prefix);
  return {
    values: await openSecret(key, path, r.body.version, r.body.wrappedDek, r.body.ciphertext),
    version: r.body.version,
  };
}

/**
 * Saves the next version of a secret. `next` receives the current values and returns the new ones.
 * The client seals the values and computes the per-name fingerprints (ADR 22), so the server never sees them in clear.
 */
export async function saveVersion(
  c: Client,
  path: string,
  next: (current: Values) => Values,
): Promise<number> {
  const prefix = path.split("/")[0] as string;
  const { key, version: keyringVersion } = await groupKey(c, prefix);
  const probe = await fetchVersion(c, path, undefined, true);
  let current: { values: Values; version: number } = { values: {}, version: 0 };
  if (probe.status === 200)
    current = {
      values: await openSecret(
        key,
        path,
        probe.body.version,
        probe.body.wrappedDek,
        probe.body.ciphertext,
      ),
      version: probe.body.version,
    };
  else if (probe.status !== 404) fail(probe.status, probe.body, `read ${path}`);
  const values = next(current.values);
  const version = current.version + 1;
  const sealed = await sealSecret(key, path, version, values);
  const w = await c.call<{ version: number }>("PUT", "/secret", {
    path,
    names: Object.keys(values),
    keyringVersion,
    version,
    fps: await fingerprints(key, path, values),
    ...sealed,
  });
  if (w.status !== 200 && w.status !== 201) fail(w.status, w.body, `write ${path}`);
  return version;
}

/** Current values of a secret, or none if it does not exist yet. */
export async function currentValues(
  c: Client,
  path: string,
): Promise<{ values: Values; version: number }> {
  const r = await fetchVersion(c, path);
  if (r.status === 404) return { values: {}, version: 0 };
  if (r.status !== 200) fail(r.status, r.body, `read ${path}`);
  const { key } = await groupKey(c, path.split("/")[0] as string);
  return {
    values: await openSecret(key, path, r.body.version, r.body.wrappedDek, r.body.ciphertext),
    version: r.body.version,
  };
}

export async function writeSecret(c: Client, path: string, change: Values): Promise<number> {
  return saveVersion(c, path, (current) => ({ ...current, ...change }));
}
