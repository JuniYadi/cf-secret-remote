import {
  createPersonalKeyring,
  findDuplicates,
  type ImportFormat,
  type ImportMode,
  type Login,
  loginFingerprints,
  openLogin,
  parseLogins,
  planImport,
  sealLogin,
  totp,
  unwrapGroupKey,
} from "@cfs/core";
import { flag } from "../args.ts";
import { CliError, type Client, connect, groupKey } from "../client.ts";
import { askHidden, confirm } from "../prompt.ts";
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
export async function importAccounts(
  c: Client,
  text: string,
  options: { format?: ImportFormat; mode: ImportMode; group?: string; yes: boolean },
) {
  const parsed = parseLogins(text, options.format);
  const [all, rs] = await Promise.all([accounts(c), rings(c)]);
  const ring = options.group ? rs.groups.find((r) => r.prefix === options.group) : rs.personal;
  if (options.group && !ring) throw new CliError(`No group "${options.group}".`);
  const existing = all.filter((item) => item.ring.id === ring?.id);
  const logins = existing.map((item) => item.login);
  const duplicates = findDuplicates(logins, parsed.rows);
  const plan = planImport(logins, parsed.rows, options.mode);
  const duplicateRows = new Set(duplicates.map((d) => d.incomingIndex));
  for (let i = 0; i < parsed.rows.length; i++)
    if (findDuplicates(parsed.rows.slice(0, i), [parsed.rows[i] as Login]).length)
      duplicateRows.add(i);
  console.log(
    `Preview: ${parsed.rows.length} rows, ${duplicateRows.size} duplicates, ${parsed.errors.length} errors. Create ${plan.creates.length}, update ${plan.updates.length}.`,
  );
  for (const issue of parsed.errors) console.log(`Line ${issue.line}: ${issue.message}`);
  if (!options.yes && !(await confirm("Import these logins? [y/N] "))) {
    console.log("Import cancelled.");
    return;
  }
  if (!plan.creates.length && !plan.updates.length) {
    console.log("Nothing to import. Delete the plaintext import file when finished.");
    return;
  }
  const t = await target(c, options.group);
  for (const login of plan.creates) {
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
    if (r.status !== 201) error("Import account", r);
  }
  for (const update of plan.updates) {
    const item = existing[update.existingIndex] as Account,
      version = item.row.version + 1;
    const r = await c.call("PUT", `/logins/${encodeURIComponent(item.row.id)}`, {
      keyringId: item.ring.id,
      keyringVersion: item.ring.version,
      version,
      ...(await sealLogin(item.key, item.row.id, version, update.login)),
      fps: await loginFingerprints(item.key, item.row.id, update.login),
    });
    if (r.status !== 200) error("Import account", r);
  }
  console.log(
    `Imported ${plan.creates.length} new and ${plan.updates.length} updated logins. Delete the plaintext import file when finished.`,
  );
}
/** An empty answer on edit keeps the current password. */
export const keptPassword = (typed: string, current: string) => typed || current;
function switchFlag(a: string[], name: string) {
  const i = a.indexOf(name);
  if (i < 0) return false;
  a.splice(i, 1);
  return true;
}
export const account: Commands = {
  account: {
    help: "cfs account list|get|add|edit|rm|totp|import    manage encrypted logins\n      import <file> [--format csv|chrome|bitwarden] [--group <prefix>] [--mode add|skip|overwrite] [--yes]",
    run: async (a, host) => {
      const action = a.shift();
      const env = flag(a, "--env"),
        role = flag(a, "--role"),
        purpose = flag(a, "--purpose"),
        group = flag(a, "--group");
      const format = flag(a, "--format"),
        mode = flag(a, "--mode"),
        yes = switchFlag(a, "--yes");
      const json = switchFlag(a, "--json"),
        show = switchFlag(a, "--show");
      const url = flag(a, "--url"),
        username = flag(a, "--username"),
        seed = flag(a, "--totp"),
        notes = flag(a, "--notes");
      const name = a.shift();
      if (
        !action ||
        !["list", "get", "add", "edit", "rm", "totp", "import"].includes(action) ||
        (action !== "list" && !name) ||
        a.length
      )
        throw new CliError(
          "Usage: cfs account list | get|add|edit|rm|totp <name> [--env E] [--role R] | import <file> [--format csv|chrome|bitwarden] [--group <prefix>] [--mode add|skip|overwrite] [--yes]",
        );
      if (
        action === "import" &&
        ((format !== undefined && !["csv", "chrome", "bitwarden"].includes(format)) ||
          (mode !== undefined && !["add", "skip", "overwrite"].includes(mode)))
      )
        throw new CliError(
          "Import format must be csv, chrome, or bitwarden; mode must be add, skip, or overwrite.",
        );
      if (action !== "import" && (format !== undefined || mode !== undefined || yes))
        throw new CliError("Import flags require cfs account import.");
      const c = await connect(host);
      if (action === "import") {
        const text = await Bun.file(name as string).text();
        await importAccounts(c, text, {
          format: format as ImportFormat | undefined,
          mode: (mode ?? "skip") as ImportMode,
          group,
          yes,
        });
        return;
      }
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
        // An empty answer keeps the current password, so editing other fields never wipes it.
        const typed = process.stdin.isTTY
          ? await askHidden("Password (empty keeps the current one): ")
          : (await Bun.stdin.text()).replace(/\r?\n$/, "");
        const login = {
          ...item.login,
          password: keptPassword(typed, item.login.password),
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
