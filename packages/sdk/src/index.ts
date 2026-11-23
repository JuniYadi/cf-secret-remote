import { readFile } from "node:fs/promises";
import { decodeKit, openLogin, totp, unwrapGroupKey } from "@cfs/core";

export interface AccountOptions {
  name: string;
  env?: string;
  role?: string;
  purpose?: string;
  kitPath?: string;
}
export interface Account {
  username: string;
  password: string;
  totp(): Promise<string>;
}
type Ring = { id: string; prefix: string; version: number };
type Row = {
  id: string;
  keyringId: string;
  version: number;
  wrappedDek: string;
  ciphertext: string;
};

/** Reads an account using an AppRole kit. Credentials belong in the test runner, not an LLM. */
export async function getAccount(options: AccountOptions): Promise<Account> {
  const kitText = options.kitPath ? await readFile(options.kitPath, "utf8") : process.env.CFS_KIT;
  if (!kitText) throw new Error("Set CFS_KIT or pass kitPath.");
  const kit = decodeKit(kitText.trim());
  const host = kit.host.replace(/\/$/, "");
  async function call<T>(method: string, path: string, body?: unknown, token?: string): Promise<T> {
    const r = await fetch(`${host}/api/v1${path}`, {
      method,
      headers: {
        "content-type": "application/json",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (!r.ok) throw new Error(`CFS ${method} ${path}: status ${r.status}`);
    return (await r.json()) as T;
  }
  const auth = await call<{ token: string }>("POST", "/auth/approle/login", {
    roleId: kit.roleId,
    secretId: kit.secretId,
  });
  const [rows, groups, me] = await Promise.all([
    call<Row[]>("GET", "/logins", undefined, auth.token),
    call<Ring[]>("GET", "/keyrings", undefined, auth.token),
    call<{ publicKey: string }>("GET", "/whoami", undefined, auth.token),
  ]);
  const keys = new Map<string, Uint8Array>();
  const matches: { row: Row; login: Awaited<ReturnType<typeof openLogin>>; ring: Ring }[] = [];
  for (const row of rows) {
    const ring = groups.find((r) => r.id === row.keyringId);
    if (!ring) throw new Error(`Cannot find keyring for account ${row.id}.`);
    let key = keys.get(ring.id);
    if (!key) {
      const wrapped = await call<{ wrappedKey: string; version: number }>(
        "GET",
        `/keyrings/${encodeURIComponent(ring.prefix)}/key`,
        undefined,
        auth.token,
      );
      key = await unwrapGroupKey(
        wrapped.wrappedKey,
        kit.privateKey,
        me.publicKey,
        ring.prefix,
        wrapped.version,
      );
      keys.set(ring.id, key);
    }
    const login = await openLogin(key, row.id, row.version, row.wrappedDek, row.ciphertext);
    if (
      login.name === options.name &&
      (options.env === undefined || login.environment === options.env) &&
      (options.role === undefined || login.role === options.role)
    )
      matches.push({ row, login, ring });
  }
  if (!matches.length) throw new Error(`No account found for "${options.name}".`);
  if (matches.length > 1)
    throw new Error(
      `Ambiguous account "${options.name}": ${matches.map(({ login, ring }) => `env=${login.environment || "-"}, role=${login.role || "-"}, keyring=${ring.prefix}`).join("; ")}`,
    );
  const { row, login } = matches[0] as (typeof matches)[number];
  async function audit(field?: string) {
    await call(
      "POST",
      `/logins/${encodeURIComponent(row.id)}/reveal`,
      {
        ...(field ? { field } : {}),
        ...(options.purpose !== undefined ? { purpose: options.purpose } : {}),
      },
      auth.token,
    );
  }
  await audit();
  return {
    username: login.username,
    password: login.password,
    async totp() {
      if (!login.totp) throw new Error("This account has no TOTP seed.");
      await audit("totp");
      return totp(login.totp);
    },
  };
}
