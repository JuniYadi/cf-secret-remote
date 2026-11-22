import {
  createPersonalKeyring,
  type Login,
  loginFingerprints,
  openLogin,
  sealLogin,
  totp,
  unwrapGroupKey,
} from "@cfs/core";
import { flag } from "../args.ts";
import { CliError, type Client, connect, groupKey } from "../client.ts";
import { askHidden } from "../prompt.ts";
import type { Commands } from "./types.ts";

type Row = {
  id: string;
  keyringId: string;
  keyringVersion: number;
  version: number;
  wrappedDek: string;
  ciphertext: string;
};
type Ring = { id: string; prefix: string; version: number; wrappedKey?: string };
export type Account = { row: Row; login: Login; key: Uint8Array; ring: Ring };
const error = (what: string, r: { status: number; body: unknown }): never => {
  throw new CliError(`${what}: ${(r.body as { error?: string })?.error ?? `status ${r.status}`}`);
};
async function rings(c: Client) {
  if (!c.privateKey) throw new CliError("Your vault is locked. Run: cfs unlock");
  const [g, p, me] = await Promise.all([
    c.call<Ring[]>("GET", "/keyrings"),
    c.call<Ring | null>("GET", "/me/personal-keyring"),
    c.call<{ publicKey: string }>("GET", "/whoami"),
  ]);
  if (g.status !== 200) error("Load keyrings", g);
  if (p.status !== 200) error("Load personal keyring", p);
  if (me.status !== 200) error("Load identity", me);
  return { groups: g.body, personal: p.body, publicKey: me.body.publicKey };
}
async function ringKey(c: Client, ring: Ring, publicKey: string) {
  if (ring.wrappedKey)
    return {
      key: await unwrapGroupKey(
        ring.wrappedKey,
        c.privateKey as string,
        publicKey,
        ring.prefix,
        ring.version,
      ),
      version: ring.version,
    };
  return groupKey(c, ring.prefix);
}
export async function accounts(c: Client): Promise<Account[]> {
  const [r, rs] = await Promise.all([c.call<Row[]>("GET", "/logins"), rings(c)]);
  if (r.status !== 200) error("List accounts", r);
  const all = [...rs.groups, ...(rs.personal ? [rs.personal] : [])];
  const keys = new Map<string, Uint8Array>();
  const result: Account[] = [];
  for (const row of r.body) {
    const ring = all.find((x) => x.id === row.keyringId);
    if (!ring) throw new CliError(`Cannot find keyring for account ${row.id}.`);
    let key = keys.get(ring.id);
    if (!key) {
      key = (await ringKey(c, ring, rs.publicKey)).key;
      keys.set(ring.id, key);
    }
    result.push({
      row,
      ring,
      key,
      login: await openLogin(key, row.id, row.version, row.wrappedDek, row.ciphertext),
    });
  }
  return result;
}
export function findAccount(items: Account[], name: string, env?: string, role?: string): Account {
  const matches = items.filter(
    ({ login }) =>
      login.name === name &&
      (env === undefined || login.environment === env) &&
      (role === undefined || login.role === role),
  );
  if (!matches.length) throw new CliError(`No account found for "${name}".`);
  if (matches.length > 1)
    throw new CliError(
      `Ambiguous account "${name}": ${matches.map(({ login, ring }) => `${login.name} (env=${login.environment || "-"}, role=${login.role || "-"}, keyring=${ring.prefix})`).join("; ")}`,
    );
  return matches[0] as Account;
}
export async function reveal(c: Client, item: Account, purpose?: string, field?: string) {
  const r = await c.call("POST", `/logins/${encodeURIComponent(item.row.id)}/reveal`, {
    ...(field ? { field } : {}),
    ...(purpose !== undefined ? { purpose } : {}),
  });
  if (r.status !== 200) error("Reveal account", r);
}
async function target(c: Client, prefix?: string) {
  const rs = await rings(c);
  if (prefix) {
    const ring = rs.groups.find((x) => x.prefix === prefix);
    if (!ring) throw new CliError(`No group "${prefix}".`);
    return { ring, ...(await ringKey(c, ring, rs.publicKey)) };
  }
  let ring = rs.personal;
  if (!ring) {
    const prefix = `personal-${crypto.randomUUID()}`;
    const created = await createPersonalKeyring(rs.publicKey, prefix);
    const r = await c.call<Ring>("POST", "/me/personal-keyring", {
      prefix,
      wrappedKey: created.wrappedKey,
    });
    if (r.status !== 200 && r.status !== 201) error("Create personal keyring", r);
    if (r.status === 201) return { ring: r.body, key: created.key, version: 1 };
    const reload = await c.call<Ring>("GET", "/me/personal-keyring");
    if (reload.status !== 200 || !reload.body) error("Load personal keyring", reload);
    ring = reload.body;
  }
  return { ring, ...(await ringKey(c, ring, rs.publicKey)) };
}
function switchFlag(a: string[], name: string) {
  const i = a.indexOf(name);
  if (i < 0) return false;
  a.splice(i, 1);
  return true;
}
export const account: Commands = {
  account: {
    help: "cfs account list|get|add|edit|rm|totp    manage encrypted logins",
    run: async (a, host) => {
      const action = a.shift();
      const env = flag(a, "--env"),
        role = flag(a, "--role"),
        purpose = flag(a, "--purpose"),
        group = flag(a, "--group");
      const json = switchFlag(a, "--json"),
        show = switchFlag(a, "--show");
      const url = flag(a, "--url"),
        username = flag(a, "--username"),
        seed = flag(a, "--totp"),
        notes = flag(a, "--notes");
      const name = a.shift();
      if (
        !action ||
        !["list", "get", "add", "edit", "rm", "totp"].includes(action) ||
        (action !== "list" && !name) ||
        a.length
      )
        throw new CliError(
          "Usage: cfs account list | get|add|edit|rm|totp <name> [--env E] [--role R]",
        );
      const c = await connect(host);
      if (action === "list") {
        for (const { login } of await accounts(c))
          console.log(`${login.name}  ${login.environment}  ${login.role}  ${login.username}`);
        return;
      }
      if (action === "add") {
        const t = await target(c, group);
        const password = process.stdin.isTTY
          ? await askHidden("Password: ")
          : (await Bun.stdin.text()).replace(/\r?\n$/, "");
        const login: Login = {
          v: 1,
          name: name as string,
          url: url ?? "",
          environment: env ?? "",
          role: role ?? "",
          username: username ?? "",
          password,
          totp: seed ?? "",
          notes: notes ?? "",
        };
        const id = crypto.randomUUID(),
          version = 1;
        const r = await c.call("POST", "/logins", {
          id,
          keyringId: t.ring.id,
          keyringVersion: t.version,
          version,
          ...(await sealLogin(t.key, id, version, login)),
          fps: await loginFingerprints(t.key, id, login),
        });
        if (r.status !== 201) error("Add account", r);
        console.log(`Added ${name}.`);
        return;
      }
      const item = findAccount(await accounts(c), name as string, env, role);
      if (action === "rm") {
        const r = await c.call("DELETE", `/logins/${item.row.id}`);
        if (r.status !== 200) error("Remove account", r);
        console.log(`Removed ${name}.`);
        return;
      }
      if (action === "edit") {
        if (group) throw new CliError("Use the existing keyring when editing an account.");
        const password = process.stdin.isTTY
          ? await askHidden("Password: ")
          : (await Bun.stdin.text()).replace(/\r?\n$/, "");
        const login = {
          ...item.login,
          password,
          ...(url !== undefined ? { url } : {}),
          ...(username !== undefined ? { username } : {}),
          ...(seed !== undefined ? { totp: seed } : {}),
          ...(notes !== undefined ? { notes } : {}),
        };
        const version = item.row.version + 1;
        const r = await c.call("PUT", `/logins/${item.row.id}`, {
          keyringId: item.ring.id,
          keyringVersion: item.ring.version,
          version,
          ...(await sealLogin(item.key, item.row.id, version, login)),
          fps: await loginFingerprints(item.key, item.row.id, login),
        });
        if (r.status !== 200) error("Edit account", r);
        console.log(`Updated ${name}.`);
        return;
      }
      if (action === "totp") {
        if (!item.login.totp) throw new CliError("This account has no TOTP seed.");
        await reveal(c, item, purpose, "totp");
        console.log(await totp(item.login.totp));
        return;
      }
      if (json || show || !process.stdout.isTTY) {
        await reveal(c, item, purpose);
        if (json)
          console.log(
            JSON.stringify({
              username: item.login.username,
              password: item.login.password,
              totp: item.login.totp ? await totp(item.login.totp) : "",
            }),
          );
        else console.log(`${item.login.username}\n${item.login.password}`);
      } else console.log(`${item.login.username}\nUse --show or --json to reveal the password.`);
    },
  },
};
