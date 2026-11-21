import { newGroupKey, sealSecret, unwrapGroupKey, wrapGroupKey } from "@cfs/core";
import { flagAll } from "../args.ts";
import { CliError, type Client, connect, readSecret } from "../client.ts";
import type { Commands } from "./types.ts";

// ADR 14: group create, add-member, remove-member, list.

/** Secrets per rotation chunk (ADR 14). */
export const CHUNK_SIZE = 50;

/** Members to wrap the new group key for: everyone except the removed identity. */
export function remainingMembers<T extends { identityId: string }>(
  members: T[],
  removeId: string,
): T[] {
  return members.filter((m) => m.identityId !== removeId);
}

/** Splits items into chunks of at most `size`. */
export function chunks<T>(items: T[], size = CHUNK_SIZE): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

const errorOf = (body: unknown, status: number) =>
  (body as { error?: string })?.error ?? `status ${status}`;

interface Identity {
  id: string;
  name: string;
  publicKey: string | null;
  status: string;
}

async function groupCreate(args: string[]) {
  const emails = flagAll(args, "--member").map((e) => e.toLowerCase());
  const prefix = args[0];
  if (!prefix) throw new CliError("Usage: cfs group create <name> [--member <email> ...]");
  const c = await connect();
  if (!c.privateKey) throw new CliError("Your vault is locked. Run: cfs unlock");
  const [me, ids] = await Promise.all([
    c.call<{ name: string }>("GET", "/whoami"),
    c.call<{ id: string; name: string; publicKey: string | null }[]>("GET", "/identities"),
  ]);
  if (ids.status !== 200) throw new CliError("Only admins can create groups.");
  const names = new Set([me.body.name, ...emails]);
  const members = [];
  const gk = await newGroupKey();
  for (const n of names) {
    const m = ids.body.find((i) => i.name === n);
    if (!m) throw new CliError(`${n} is not invited yet.`);
    if (!m.publicKey) throw new CliError(`${n} has not set up a vault yet.`);
    members.push({ identityId: m.id, wrappedKey: await wrapGroupKey(gk, m.publicKey, prefix, 1) });
  }
  const r = await c.call("POST", "/keyrings", { prefix, members });
  if (r.status !== 201)
    throw new CliError(
      `Could not create the group: ${(r.body as { error?: string }).error ?? r.status}`,
    );
  console.log(`Group "${prefix}" created with ${members.length} member(s).`);
}

/** The caller's group key at the current version. Needs an unlocked vault and membership. */
async function myGroupKey(c: Client, prefix: string) {
  if (!c.privateKey) throw new CliError("Your vault is locked. Run: cfs unlock");
  const [me, k] = await Promise.all([
    c.call<{ publicKey: string | null }>("GET", "/whoami"),
    c.call<{ wrappedKey: string; version: number }>("GET", `/keyrings/${prefix}/key`),
  ]);
  if (k.status === 404) throw new CliError(`You are not in the "${prefix}" group.`);
  if (k.status !== 200 || !me.body.publicKey)
    throw new CliError(`Could not load the "${prefix}" key: ${errorOf(k.body, k.status)}`);
  const key = await unwrapGroupKey(
    k.body.wrappedKey,
    c.privateKey,
    me.body.publicKey,
    prefix,
    k.body.version,
  );
  return { key, version: k.body.version };
}

/** Admin-only directory. */
async function directory(c: Client): Promise<Identity[]> {
  const r = await c.call<Identity[]>("GET", "/identities");
  if (r.status === 403) throw new CliError("Only admins can change group membership.");
  if (r.status !== 200) throw new CliError(`Could not load people: ${errorOf(r.body, r.status)}`);
  return r.body;
}

async function identityByEmail(c: Client, email: string): Promise<Identity> {
  const found = (await directory(c)).find((i) => i.name === email);
  if (!found) throw new CliError(`${email} is not invited yet.`);
  return found;
}

async function groupMembers(c: Client, prefix: string) {
  const r = await c.call<{ identityId: string; name: string }[]>(
    "GET",
    `/keyrings/${prefix}/members`,
  );
  if (r.status !== 200)
    throw new CliError(`Could not list "${prefix}": ${errorOf(r.body, r.status)}`);
  return r.body;
}

async function groupAdd(prefix: string, email: string) {
  const c = await connect();
  const mine = await myGroupKey(c, prefix);
  const target = await identityByEmail(c, email.toLowerCase());
  if (!target.publicKey) throw new CliError(`${email} has not set up a vault yet.`);
  const wrappedKey = await wrapGroupKey(mine.key, target.publicKey, prefix, mine.version);
  const r = await c.call("POST", `/keyrings/${prefix}/members`, {
    identityId: target.id,
    wrappedKey,
  });
  if (r.status !== 201) throw new CliError(`Could not add ${email}: ${errorOf(r.body, r.status)}`);
  console.log(`${email} added to "${prefix}".`);
}

// Removal: the server ends the removed person's access, then the secrets are re-encrypted under a
// new group key in chunks. Any failure after the start aborts the rotation.
async function groupRemove(prefix: string, email: string) {
  const c = await connect();
  const mine = await myGroupKey(c, prefix);
  const target = await identityByEmail(c, email.toLowerCase());
  const members = await groupMembers(c, prefix);
  if (!members.some((m) => m.identityId === target.id))
    throw new CliError(`${email} is not in the "${prefix}" group.`);

  // Wrap the new key for everyone who stays, before anything changes on the server.
  const keys = new Map((await directory(c)).map((i) => [i.id, i.publicKey]));
  const newVersion = mine.version + 1;
  const newKey = await newGroupKey();
  const wrapped = [];
  for (const m of remainingMembers(members, target.id)) {
    const pk = keys.get(m.identityId);
    if (!pk) throw new CliError(`${m.name} has not set up a vault yet.`);
    wrapped.push({
      identityId: m.identityId,
      wrappedKey: await wrapGroupKey(newKey, pk, prefix, newVersion),
    });
  }

  const start = await c.call("POST", `/keyrings/${prefix}/rotate/start`, {
    removeIdentityId: target.id,
    members: wrapped,
  });
  if (start.status !== 200)
    throw new CliError(`Could not start the rotation: ${errorOf(start.body, start.status)}`);

  let count = 0;
  try {
    const listed = await c.call<{ path: string }[]>("GET", "/secrets");
    const paths = listed.body.map((s) => s.path).filter((p) => p.split("/")[0] === prefix);
    count = paths.length;
    const items = [];
    for (const path of paths) {
      // The old key is still ours until commit, so the current values open here.
      const cur = await readSecret(c, path);
      items.push({
        path,
        names: Object.keys(cur.values),
        version: cur.version + 1,
        ...(await sealSecret(newKey, path, cur.version + 1, cur.values)),
      });
    }
    for (const part of chunks(items)) {
      const r = await c.call("POST", `/keyrings/${prefix}/rotate/chunk`, {
        keyringVersion: newVersion,
        secrets: part,
      });
      if (r.status !== 200) throw new CliError(`Chunk refused: ${errorOf(r.body, r.status)}`);
    }
    const done = await c.call("POST", `/keyrings/${prefix}/rotate/commit`, {});
    if (done.status !== 200)
      throw new CliError(`Commit refused: ${errorOf(done.body, done.status)}`);
  } catch (e) {
    await c.call("POST", `/keyrings/${prefix}/rotate/abort`, {});
    throw e;
  }
  console.log(
    `${email} removed from "${prefix}". ${count} secret(s) re-encrypted under key version ${newVersion}.`,
  );
}

async function groupList(prefix: string | undefined) {
  const c = await connect();
  if (!prefix) {
    const r = await c.call<{ prefix: string; version: number }[]>("GET", "/keyrings");
    if (r.status !== 200) throw new CliError(`Could not list groups: ${errorOf(r.body, r.status)}`);
    for (const g of r.body) console.log(`${g.prefix}\tkey version ${g.version}`);
    return;
  }
  for (const m of await groupMembers(c, prefix)) console.log(m.name);
}

const USAGE = [
  "Usage: cfs group create <name> [--member <email> ...]",
  "       cfs group add-member <name> <email>",
  "       cfs group remove-member <name> <email>",
  "       cfs group list [<name>]",
].join("\n");

export const group: Commands = {
  group: {
    help: "cfs group create|add-member|remove-member|list ...",
    run: async (a) => {
      const sub = a.shift();
      if (sub === "create") return groupCreate(a);
      if (sub === "add-member" && a[0] && a[1]) return groupAdd(a[0], a[1]);
      if (sub === "remove-member" && a[0] && a[1]) return groupRemove(a[0], a[1]);
      if (sub === "list") return groupList(a[0]);
      throw new CliError(USAGE);
    },
  },
};
