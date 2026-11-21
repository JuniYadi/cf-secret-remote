import { env } from "cloudflare:test";
import {
  generateKeyPair,
  newGroupKey,
  openSecret,
  sealSecret,
  unwrapGroupKey,
  type Values,
  wrapGroupKey,
} from "@cfs/core";
import { describe, expect, it } from "vitest";
import { countAdminsWithVault } from "../src/routes/membership.ts";
import { api, makeIdentity } from "./helpers.ts";

// ADR 14 rules, one test each. Helpers build real wrapped keys and ciphertext with @cfs/core.

let seq = 0;
const prefixName = (tag: string) => `grp${tag}${++seq}`;

type KeyPair = { publicKey: string; privateKey: string };
type Person = { id: string; name: string; token: string; kp: KeyPair };

async function person(opts: { role?: "admin" | "member"; vault?: boolean } = {}): Promise<Person> {
  const kp = await generateKeyPair();
  const p = await makeIdentity({
    role: opts.role,
    publicKey: opts.vault === false ? undefined : kp.publicKey,
  });
  return { ...p, kp };
}

/** Creates a group with `owner` (an admin) and `others` as members, all holding key version 1. */
async function makeGroup(prefix: string, owner: Person, others: Person[] = []) {
  const gk = await newGroupKey();
  const members = await Promise.all(
    [owner, ...others].map(async (m) => ({
      identityId: m.id,
      wrappedKey: await wrapGroupKey(gk, m.kp.publicKey, prefix, 1),
    })),
  );
  const r = await api("POST", "/keyrings", owner.token, { prefix, members });
  expect(r.status).toBe(201);
  return gk;
}

/** The person's group key at the latest version, unwrapped with their private key. */
async function keyOf(p: Person, prefix: string) {
  const r = await api("GET", `/keyrings/${prefix}/key`, p.token);
  expect(r.status).toBe(200);
  const key = await unwrapGroupKey(
    r.body.wrappedKey,
    p.kp.privateKey,
    p.kp.publicKey,
    prefix,
    r.body.version,
  );
  return { key, version: r.body.version as number };
}

async function write(
  p: Person,
  gk: Uint8Array,
  path: string,
  values: Values,
  keyringVersion = 1,
  version = 1,
) {
  const sealed = await sealSecret(gk, path, version, values);
  return api("PUT", "/secret", p.token, {
    path,
    names: Object.keys(values),
    keyringVersion,
    version,
    ...sealed,
  });
}

async function startRemove(
  adm: Person,
  prefix: string,
  removeId: string,
  remaining: Person[],
  newGk: Uint8Array,
  newVersion: number,
) {
  return api("POST", `/keyrings/${prefix}/rotate/start`, adm.token, {
    removeIdentityId: removeId,
    members: await Promise.all(
      remaining.map(async (m) => ({
        identityId: m.id,
        wrappedKey: await wrapGroupKey(newGk, m.kp.publicKey, prefix, newVersion),
      })),
    ),
  });
}

/** Opens each current version with the old key and seals it under the new key, as the CLI does. */
async function reencrypt(
  adm: Person,
  oldGk: Uint8Array,
  newGk: Uint8Array,
  newVersion: number,
  paths: string[],
) {
  const items = [];
  for (const path of paths) {
    const got = await api("GET", `/secret?path=${path}`, adm.token);
    expect(got.status).toBe(200);
    const values = await openSecret(
      oldGk,
      path,
      got.body.version,
      got.body.wrappedDek,
      got.body.ciphertext,
    );
    const sealed = await sealSecret(newGk, path, got.body.version + 1, values);
    items.push({
      path,
      names: Object.keys(values),
      version: got.body.version + 1,
      keyringVersion: newVersion,
      ...sealed,
    });
  }
  return items;
}

const chunk = (adm: Person, prefix: string, keyringVersion: number, secrets: unknown[]) =>
  api("POST", `/keyrings/${prefix}/rotate/chunk`, adm.token, { keyringVersion, secrets });

async function groupRow(prefix: string) {
  return env.DB.prepare("SELECT id, version, status FROM keyring WHERE prefix = ?")
    .bind(prefix)
    .first<{ id: string; version: number; status: string }>();
}

async function countRows(sql: string, ...binds: unknown[]) {
  const row = await env.DB.prepare(`SELECT COUNT(*) AS n FROM (${sql})`)
    .bind(...binds)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

/** Staged rows of one group. Storage is shared by the tests in this file, so counts are scoped. */
async function stagedRows(prefix: string) {
  const row = await groupRow(prefix);
  return {
    versions: await countRows(
      "SELECT v.secret_id FROM secret_version v JOIN secret s ON s.id = v.secret_id WHERE s.keyring_id = ? AND v.keyring_version = 2",
      row?.id,
    ),
    members: await countRows("SELECT 1 FROM keyring_member_staged WHERE keyring_id = ?", row?.id),
  };
}

async function auditEntries(): Promise<Record<string, unknown>[]> {
  const rows = await env.DB.prepare("SELECT entry FROM audit").all<{ entry: string }>();
  return rows.results.map((r) => JSON.parse(r.entry));
}

describe("ADR 14: add member", () => {
  it("an admin in the group wraps the current key to a new member, stored at the current version", async () => {
    const prefix = prefixName("add");
    const adm = await person({ role: "admin" });
    const gk = await makeGroup(prefix, adm);
    const newbie = await person();

    const mine = await keyOf(adm, prefix);
    const wrapped = await wrapGroupKey(mine.key, newbie.kp.publicKey, prefix, mine.version);
    const r = await api("POST", `/keyrings/${prefix}/members`, adm.token, {
      identityId: newbie.id,
      wrappedKey: wrapped,
    });
    expect(r.status).toBe(201);

    const theirs = await keyOf(newbie, prefix);
    expect(theirs.version).toBe(1);
    expect(theirs.key).toEqual(gk);
    const row = await env.DB.prepare(
      "SELECT m.version AS version FROM keyring_member m JOIN keyring k ON k.id = m.keyring_id WHERE k.prefix = ? AND m.identity_id = ?",
    )
      .bind(prefix, newbie.id)
      .first<{ version: number }>();
    expect(row?.version).toBe(1);

    // Adding the same person twice is refused.
    const again = await api("POST", `/keyrings/${prefix}/members`, adm.token, {
      identityId: newbie.id,
      wrappedKey: wrapped,
    });
    expect(again.status).toBe(409);
  });

  it("only a member who is also an admin can add; denials are audited", async () => {
    const prefix = prefixName("auth");
    const adm = await person({ role: "admin" });
    const mem = await person();
    await makeGroup(prefix, adm, [mem]);
    const outsider = await person({ role: "admin" });
    const target = await person();
    const body = { identityId: target.id, wrappedKey: "x.y" };

    // An admin who is not in the group.
    expect((await api("POST", `/keyrings/${prefix}/members`, outsider.token, body)).status).toBe(
      403,
    );
    expect(
      (await auditEntries()).some(
        (e) => e.action === "group.member.add" && e.result === "denied" && e.path === prefix,
      ),
    ).toBe(true);

    // A member who is not an admin.
    expect((await api("POST", `/keyrings/${prefix}/members`, mem.token, body)).status).toBe(403);
  });

  it("a member without a vault, or a disabled identity, cannot be added", async () => {
    const prefix = prefixName("novault");
    const adm = await person({ role: "admin" });
    await makeGroup(prefix, adm);
    const novault = await person({ vault: false });
    const off = await person();
    await api("PATCH", `/identities/${off.id}`, adm.token, { status: "disabled" });

    const r1 = await api("POST", `/keyrings/${prefix}/members`, adm.token, {
      identityId: novault.id,
      wrappedKey: "x.y",
    });
    expect(r1.status).toBe(409);
    const r2 = await api("POST", `/keyrings/${prefix}/members`, adm.token, {
      identityId: off.id,
      wrappedKey: "x.y",
    });
    expect(r2.status).toBe(409);
  });
});

describe("ADR 14: remove member and staged rotation", () => {
  it("removal ends the removed member's access at once and blocks writes while rotating", async () => {
    const prefix = prefixName("rm");
    const adm = await person({ role: "admin" });
    const mem = await person();
    const gone = await person();
    const gk = await makeGroup(prefix, adm, [mem, gone]);
    expect((await write(adm, gk, `${prefix}/one`, { K: "v" })).status).toBe(201);
    expect((await keyOf(gone, prefix)).version).toBe(1);

    const newGk = await newGroupKey();
    const start = await startRemove(adm, prefix, gone.id, [adm, mem], newGk, 2);
    expect(start.status).toBe(200);
    expect(start.body).toEqual({ version: 2, secrets: 1 });

    // Access ends at once: no key and no key rows for the removed member.
    expect((await api("GET", `/keyrings/${prefix}/key`, gone.token)).status).toBe(404);
    expect(await countRows("SELECT 1 FROM keyring_member WHERE identity_id = ?", gone.id)).toBe(0);
    expect((await groupRow(prefix))?.status).toBe("rotating");

    // Writes to the rotating group return 409.
    expect((await write(adm, gk, `${prefix}/one`, { K: "w" }, 1, 2)).status).toBe(409);
    expect((await write(adm, gk, `${prefix}/two`, { K: "w" })).status).toBe(409);
    expect((await api("DELETE", `/secret?path=${prefix}/one`, adm.token)).status).toBe(409);
    const newbie = await person();
    expect(
      (
        await api("POST", `/keyrings/${prefix}/members`, adm.token, {
          identityId: newbie.id,
          wrappedKey: "x.y",
        })
      ).status,
    ).toBe(409);
    expect((await startRemove(adm, prefix, mem.id, [adm], newGk, 2)).status).toBe(409);

    // Reads keep working at the old version while rotating.
    const read = await api("GET", `/secret?path=${prefix}/one`, adm.token);
    expect(read.status).toBe(200);
    expect(read.body.version).toBe(1);
    expect(read.body.keyringVersion).toBe(1);
  });

  it("start validates the removal: no self-removal, exact remaining set, must be a member", async () => {
    const prefix = prefixName("val");
    const adm = await person({ role: "admin" });
    const mem = await person();
    const gone = await person();
    await makeGroup(prefix, adm, [mem, gone]);
    const newGk = await newGroupKey();

    expect((await startRemove(adm, prefix, adm.id, [mem, gone], newGk, 2)).status).toBe(400);
    // Misses a remaining member.
    expect((await startRemove(adm, prefix, gone.id, [adm], newGk, 2)).status).toBe(400);
    // Adds someone who is not a remaining member.
    const outsider = await person();
    expect((await startRemove(adm, prefix, gone.id, [adm, mem, outsider], newGk, 2)).status).toBe(
      400,
    );
    // Duplicates do not count as the full set.
    expect((await startRemove(adm, prefix, gone.id, [adm, adm], newGk, 2)).status).toBe(400);
    // Not in the group.
    expect((await startRemove(adm, prefix, outsider.id, [adm, mem, gone], newGk, 2)).status).toBe(
      404,
    );
    expect((await groupRow(prefix))?.status).toBe("active");
  });

  it("a non-member cannot start a rotation", async () => {
    const prefix = prefixName("nomem");
    const adm = await person({ role: "admin" });
    const mem = await person();
    await makeGroup(prefix, adm, [mem]);
    const outsider = await person({ role: "admin" });
    const newGk = await newGroupKey();
    expect((await startRemove(outsider, prefix, mem.id, [adm], newGk, 2)).status).toBe(403);
    expect((await groupRow(prefix))?.status).toBe("active");
  });

  it("chunks stage invisible versions; commit is refused until every live secret has one", async () => {
    const prefix = prefixName("commit");
    const adm = await person({ role: "admin" });
    const mem = await person();
    const gone = await person();
    const gk = await makeGroup(prefix, adm, [mem, gone]);
    for (const n of ["a", "b", "c", "d"])
      expect((await write(adm, gk, `${prefix}/${n}`, { K: n })).status).toBe(201);
    // A deleted secret does not need a new version.
    expect((await api("DELETE", `/secret?path=${prefix}/d`, adm.token)).status).toBe(200);

    const oldGk = (await keyOf(adm, prefix)).key;
    const newGk = await newGroupKey();
    expect((await startRemove(adm, prefix, gone.id, [adm, mem], newGk, 2)).status).toBe(200);
    const items = await reencrypt(adm, oldGk, newGk, 2, [
      `${prefix}/a`,
      `${prefix}/b`,
      `${prefix}/c`,
    ]);

    expect((await chunk(adm, prefix, 2, [items[0]])).status).toBe(200);

    // Staged rows are invisible until commit: current stays at 1.
    expect((await api("GET", `/secret?path=${prefix}/a&version=2`, adm.token)).status).toBe(404);
    const cur = await api("GET", `/secret?path=${prefix}/a`, adm.token);
    expect(cur.body.version).toBe(1);
    const hist = await api("GET", `/secret/versions?path=${prefix}/a`, adm.token);
    expect(hist.body.map((v: { version: number }) => v.version)).toEqual([1]);

    // Commit refused: b and c have no new version.
    const early = await api("POST", `/keyrings/${prefix}/rotate/commit`, adm.token, {});
    expect(early.status).toBe(409);
    expect(early.body.missing).toEqual([`${prefix}/b`, `${prefix}/c`]);
    expect((await groupRow(prefix))?.status).toBe("rotating");

    expect((await chunk(adm, prefix, 2, items.slice(1))).status).toBe(200);
    const done = await api("POST", `/keyrings/${prefix}/rotate/commit`, adm.token, {});
    expect(done.status).toBe(200);
    expect(done.body).toEqual({ version: 2, status: "active" });
    const row = await groupRow(prefix);
    expect(row?.version).toBe(2);
    expect(row?.status).toBe("active");
    const after = await api("GET", `/secret?path=${prefix}/a`, adm.token);
    expect(after.body.version).toBe(2);
    expect(after.body.keyringVersion).toBe(2);
  });

  it("a chunk carries at most 50 secrets", async () => {
    const prefix = prefixName("cap");
    const adm = await person({ role: "admin" });
    await makeGroup(prefix, adm);
    const fake = Array.from({ length: 51 }, (_, i) => ({ path: `${prefix}/s${i}` }));
    expect((await chunk(adm, prefix, 2, fake)).status).toBe(400);
  });

  it("abort discards staged rows and leaves the group as it was", async () => {
    const prefix = prefixName("abort");
    const adm = await person({ role: "admin" });
    const mem = await person();
    const gone = await person();
    const gk = await makeGroup(prefix, adm, [mem, gone]);
    expect((await write(adm, gk, `${prefix}/a`, { K: "a" })).status).toBe(201);
    expect((await write(adm, gk, `${prefix}/b`, { K: "b" })).status).toBe(201);

    const oldGk = (await keyOf(adm, prefix)).key;
    const newGk = await newGroupKey();
    expect((await startRemove(adm, prefix, gone.id, [adm, mem], newGk, 2)).status).toBe(200);
    const items = await reencrypt(adm, oldGk, newGk, 2, [`${prefix}/a`]);
    expect((await chunk(adm, prefix, 2, items)).status).toBe(200);
    expect((await stagedRows(prefix)).versions).toBe(1);

    const abort = await api("POST", `/keyrings/${prefix}/rotate/abort`, adm.token, {});
    expect(abort.status).toBe(200);
    expect(abort.body).toEqual({ version: 1, status: "active" });

    const row = await groupRow(prefix);
    expect(row?.version).toBe(1);
    expect(row?.status).toBe("active");
    expect(await stagedRows(prefix)).toEqual({ versions: 0, members: 0 });
    const cur = await env.DB.prepare("SELECT current FROM secret WHERE path = ?")
      .bind(`${prefix}/a`)
      .first<{ current: number }>();
    expect(cur?.current).toBe(1);

    // The remaining member keeps the old key; writes are allowed again.
    expect((await keyOf(mem, prefix)).version).toBe(1);
    expect((await write(adm, gk, `${prefix}/a`, { K: "a2" }, 1, 2)).status).toBe(200);
    // Abort when not rotating is refused.
    expect((await api("POST", `/keyrings/${prefix}/rotate/abort`, adm.token, {})).status).toBe(409);
  });

  it("full rotation: remaining members get the new key and keep old keys; removed member loses everything", async () => {
    const prefix = prefixName("full");
    const adm = await person({ role: "admin" });
    const mem = await person();
    const gone = await person();
    const gk = await makeGroup(prefix, adm, [mem, gone]);
    const marker = "MARK_K_9f3a";
    const paths: string[] = [];
    for (let i = 0; i < 53; i++) {
      const path = `${prefix}/s${String(i).padStart(2, "0")}`;
      paths.push(path);
      expect((await write(adm, gk, path, { K: i === 7 ? marker : `v${i}` })).status).toBe(201);
    }

    const oldGk = (await keyOf(gone, prefix)).key; // the key the removed member held
    const newGk = await newGroupKey();
    const start = await startRemove(adm, prefix, gone.id, [adm, mem], newGk, 2);
    expect(start.body.secrets).toBe(53);

    const items = await reencrypt(adm, gk, newGk, 2, paths);
    expect((await chunk(adm, prefix, 2, items.slice(0, 50))).status).toBe(200);
    expect((await chunk(adm, prefix, 2, items.slice(50))).status).toBe(200);
    expect((await api("POST", `/keyrings/${prefix}/rotate/commit`, adm.token, {})).status).toBe(
      200,
    );

    // Remaining members get the new key; the group is active at version 2.
    const m = await keyOf(mem, prefix);
    expect(m.version).toBe(2);
    expect(m.key).toEqual(newGk);
    expect((await groupRow(prefix))?.version).toBe(2);

    // Old wrapped keys stay for remaining members so history opens; the old version opens with the old key.
    const old = await env.DB.prepare(
      "SELECT m.wrapped_key AS w FROM keyring_member m JOIN keyring k ON k.id = m.keyring_id WHERE k.prefix = ? AND m.identity_id = ? AND m.version = 1",
    )
      .bind(prefix, mem.id)
      .first<{ w: string }>();
    expect(old).not.toBeNull();
    const oldKey = await unwrapGroupKey(
      old?.w ?? "",
      mem.kp.privateKey,
      mem.kp.publicKey,
      prefix,
      1,
    );
    expect(oldKey).toEqual(gk);
    const hist = await api("GET", `/secret?path=${prefix}/s07&version=1`, adm.token);
    expect(
      await openSecret(oldKey, `${prefix}/s07`, 1, hist.body.wrappedDek, hist.body.ciphertext),
    ).toEqual({ K: marker });

    // The current value opens with the new key, and not with the removed member's key.
    const cur = await api("GET", `/secret?path=${prefix}/s07`, adm.token);
    expect(cur.body.version).toBe(2);
    expect(
      await openSecret(newGk, `${prefix}/s07`, 2, cur.body.wrappedDek, cur.body.ciphertext),
    ).toEqual({ K: marker });
    await expect(
      openSecret(oldGk, `${prefix}/s07`, 2, cur.body.wrappedDek, cur.body.ciphertext),
    ).rejects.toThrow();

    // The removed member has no rows for any version. Staged rows are gone.
    expect(await countRows("SELECT 1 FROM keyring_member WHERE identity_id = ?", gone.id)).toBe(0);
    expect((await stagedRows(prefix)).members).toBe(0);
    expect((await api("GET", `/keyrings/${prefix}/key`, gone.token)).status).toBe(404);

    // Rotation steps are audited with names, paths and versions only; no value or key appears anywhere.
    const entries = await auditEntries();
    const actions = entries.map((e) => e.action);
    expect(actions).toContain("group.rotate.start");
    expect(actions).toContain("group.rotate.commit");
    expect(actions).toContain("secret.rotate");
    const allowed = new Set(["who", "action", "path", "version", "result", "ip", "note", "at"]);
    for (const e of entries) for (const k of Object.keys(e)) expect(allowed.has(k)).toBe(true);
    for (const t of [
      "secret_version",
      "audit",
      "keyring_member",
      "keyring_member_staged",
      "identity",
      "session",
    ]) {
      const rows = await env.DB.prepare(`SELECT * FROM ${t}`).all();
      expect(JSON.stringify(rows.results)).not.toContain(marker);
    }
  });

  it("the group member list shows members to members and admins, not to outsiders", async () => {
    const prefix = prefixName("list");
    const adm = await person({ role: "admin" });
    const mem = await person();
    const gone = await person();
    await makeGroup(prefix, adm, [mem, gone]);
    const list = await api("GET", `/keyrings/${prefix}/members`, mem.token);
    expect(list.status).toBe(200);
    expect(list.body.map((m: { name: string }) => m.name).sort()).toEqual(
      [adm.name, mem.name, gone.name].sort(),
    );
    const outsider = await person();
    expect((await api("GET", `/keyrings/${prefix}/members`, outsider.token)).status).toBe(403);
    const otherAdmin = await person({ role: "admin" });
    expect((await api("GET", `/keyrings/${prefix}/members`, otherAdmin.token)).status).toBe(200);
  });
});

describe("ADR 14: identities and the two-admin guard", () => {
  it("at least two admins must hold a vault; the helper counts them", async () => {
    // Earlier tests in this file leave admins behind; the guard counts the whole database.
    await env.DB.prepare("UPDATE identity SET status = 'disabled' WHERE role = 'admin'").run();
    const a1 = await person({ role: "admin" });
    const a2 = await person({ role: "admin" });
    const a3 = await person({ role: "admin", vault: false });
    const acting = a1;

    // a1 and a2 are the only admins with a vault: neither may be demoted or disabled.
    expect(
      (await api("PATCH", `/identities/${a2.id}`, acting.token, { role: "member" })).status,
    ).toBe(409);
    expect(
      (await api("PATCH", `/identities/${a2.id}`, acting.token, { status: "disabled" })).status,
    ).toBe(409);
    expect(await countAdminsWithVault(env.DB)).toBe(2);
    expect(await countAdminsWithVault(env.DB, a1.id)).toBe(1);

    // An admin without a vault does not count, so it may be disabled.
    expect(
      (await api("PATCH", `/identities/${a3.id}`, acting.token, { status: "disabled" })).status,
    ).toBe(200);

    // With a third admin holding a vault, a2 can be demoted.
    const a4 = await person({ role: "admin" });
    expect(
      (await api("PATCH", `/identities/${a2.id}`, acting.token, { role: "member" })).status,
    ).toBe(200);
    expect(await countAdminsWithVault(env.DB)).toBe(2);
    expect(await countAdminsWithVault(env.DB, a4.id)).toBe(1);
    expect(
      (await api("PATCH", `/identities/${a1.id}`, acting.token, { status: "disabled" })).status,
    ).toBe(409);
  });

  it("disabling ends all sessions and blocks sign-in; enabling restores access; role changes are audited", async () => {
    const adm = await person({ role: "admin" });
    const mem = await person();
    expect((await api("GET", "/whoami", mem.token)).status).toBe(200);

    const off = await api("PATCH", `/identities/${mem.id}`, adm.token, { status: "disabled" });
    expect(off.status).toBe(200);
    expect(off.body).toEqual({ id: mem.id, role: "member", status: "disabled" });
    expect((await api("GET", "/whoami", mem.token)).status).toBe(401);
    expect(await countRows("SELECT 1 FROM session WHERE identity_id = ?", mem.id)).toBe(0);

    const on = await api("PATCH", `/identities/${mem.id}`, adm.token, { status: "active" });
    expect(on.body.status).toBe("active");
    // The sessions were ended, so a fresh token is needed.
    expect((await api("GET", "/whoami", mem.token)).status).toBe(401);

    const promote = await api("PATCH", `/identities/${mem.id}`, adm.token, { role: "admin" });
    expect(promote.body.role).toBe("admin");
    const actions = (await auditEntries()).map((e) => e.action);
    expect(actions).toEqual(
      expect.arrayContaining(["identity.disable", "identity.enable", "identity.role"]),
    );
  });

  it("only admins change identities, and bad values are refused", async () => {
    const adm = await person({ role: "admin" });
    const mem = await person();
    const other = await person();
    expect(
      (await api("PATCH", `/identities/${other.id}`, mem.token, { status: "disabled" })).status,
    ).toBe(403);
    expect((await api("PATCH", `/identities/${other.id}`, adm.token, {})).status).toBe(400);
    expect(
      (await api("PATCH", `/identities/${other.id}`, adm.token, { role: "root" })).status,
    ).toBe(400);
    expect(
      (await api("PATCH", `/identities/${other.id}`, adm.token, { status: "gone" })).status,
    ).toBe(400);
    expect((await api("PATCH", "/identities/nope", adm.token, { role: "member" })).status).toBe(
      404,
    );
  });
});
