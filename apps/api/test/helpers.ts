import { env, SELF } from "cloudflare:test";
import { sha256Hex } from "../src/util.ts";

export interface Res<T = any> {
  status: number;
  body: T;
}

/** Calls the Worker in-process. `token` is a cfs_ bearer token. */
export async function api<T = any>(
  method: string,
  path: string,
  token?: string | null,
  body?: unknown,
  extraHeaders: Record<string, string> = {},
): Promise<Res<T>> {
  const r = await SELF.fetch(`http://t.test/api/v1${path}`, {
    method,
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...extraHeaders,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: r.status, body: (await r.json().catch(() => null)) as T };
}

let n = 0;
/** Inserts an identity plus a live session and returns its token. */
export async function makeIdentity(
  opts: {
    name?: string;
    kind?: "user" | "app";
    role?: "admin" | "member";
    publicKey?: string;
  } = {},
) {
  const id = `id${++n}_${Math.random().toString(36).slice(2, 8)}`;
  const name = opts.name ?? `${id}@test.dev`;
  const token = `cfs_${id}`;
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO identity (id, kind, name, role, public_key, created_at) VALUES (?, ?, ?, ?, ?, 1)",
    ).bind(id, opts.kind ?? "user", name, opts.role ?? "member", opts.publicKey ?? null),
    env.DB.prepare(
      "INSERT INTO session (token_hash, identity_id, kind, created_at, expires_at) VALUES (?, ?, 'cli', 1, 9999999999)",
    ).bind(await sha256Hex(token), id),
  ]);
  return { id, name, token };
}

export const admin = (publicKey?: string) => makeIdentity({ role: "admin", publicKey });
