import {
  decodeKit,
  type Kit,
  openSecret,
  sealSecret,
  unwrapGroupKey,
  type Values,
} from "@cfs/core";
import { loadSession } from "./config.ts";

export class CliError extends Error {}

export interface Client {
  host: string;
  privateKey?: string;
  call<T = unknown>(
    method: string,
    path: string,
    body?: unknown,
    token?: string,
  ): Promise<{ status: number; body: T }>;
}

async function raw<T>(host: string, method: string, path: string, body?: unknown, token?: string) {
  let r: Response;
  try {
    r = await fetch(`${host}/api/v1${path}`, {
      method,
      headers: {
        "content-type": "application/json",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new CliError(`Cannot reach ${host}. Check the host and your network.`);
  }
  return { status: r.status, body: (await r.json().catch(() => ({}))) as T };
}

export const anonymous = (host: string) => ({
  call: <T = unknown>(method: string, path: string, body?: unknown) =>
    raw<T>(host, method, path, body),
});

/** A signed-in client: CFS_KIT (apps) or the saved session (people). */
export async function connect(hostFlag?: string): Promise<Client> {
  const kitStr = process.env.CFS_KIT;
  if (kitStr) {
    const kit: Kit = decodeKit(kitStr);
    const host = kit.host.replace(/\/+$/, "");
    const r = await raw<{ token?: string }>(host, "POST", "/auth/approle/login", {
      roleId: kit.roleId,
      secretId: kit.secretId,
    });
    if (!r.body.token)
      throw new CliError("The access kit was refused. It may be revoked or expired.");
    const token = r.body.token;
    return { host, privateKey: kit.privateKey, call: (m, p, b) => raw(host, m, p, b, token) };
  }
  const s = loadSession();
  if (!s) throw new CliError("You are not signed in. Run: cfs login --host <url>");
  if (hostFlag && hostFlag.replace(/\/+$/, "") !== s.host)
    throw new CliError(
      `You are signed in to ${s.host}, not ${hostFlag}. Run: cfs login --host ${hostFlag}`,
    );
  return {
    host: s.host,
    privateKey: s.privateKey,
    call: (m, p, b) => raw(s.host, m, p, b, s.token),
  };
}

function fail(status: number, body: unknown, what: string): never {
  const msg = (body as { error?: string })?.error ?? `status ${status}`;
  if (status === 401) throw new CliError("Your session ended. Run: cfs login");
  if (status === 403) throw new CliError(`Not allowed: ${what}. Ask an admin for access.`);
  throw new CliError(`${what}: ${msg}`);
}

async function groupKey(c: Client, prefix: string): Promise<{ key: Uint8Array; version: number }> {
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

export async function readSecret(
  c: Client,
  path: string,
): Promise<{ values: Values; version: number }> {
  const r = await c.call<{
    version: number;
    keyringVersion: number;
    wrappedDek: string;
    ciphertext: string;
  }>("GET", `/secret?path=${encodeURIComponent(path)}`);
  if (r.status === 404) throw new CliError(`No secret at "${path}".`);
  if (r.status !== 200) fail(r.status, r.body, `read ${path}`);
  const prefix = path.split("/")[0] as string;
  const { key } = await groupKey(c, prefix);
  return {
    values: await openSecret(key, path, r.body.version, r.body.wrappedDek, r.body.ciphertext),
    version: r.body.version,
  };
}

export async function writeSecret(c: Client, path: string, change: Values): Promise<number> {
  const prefix = path.split("/")[0] as string;
  const { key, version: keyringVersion } = await groupKey(c, prefix);
  let current: { values: Values; version: number } = { values: {}, version: 0 };
  const probe = await c.call("GET", `/secret?path=${encodeURIComponent(path)}`);
  if (probe.status === 200) current = await readSecret(c, path);
  else if (probe.status !== 404) fail(probe.status, probe.body, `read ${path}`);
  const values = { ...current.values, ...change };
  const version = current.version + 1;
  const sealed = await sealSecret(key, path, version, values);
  const w = await c.call<{ version: number }>("PUT", "/secret", {
    path,
    names: Object.keys(values),
    keyringVersion,
    version,
    ...sealed,
  });
  if (w.status !== 200 && w.status !== 201) fail(w.status, w.body, `write ${path}`);
  return version;
}
