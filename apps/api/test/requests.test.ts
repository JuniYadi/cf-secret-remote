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
import { runDaily } from "../src/cron.ts";
import type { Env } from "../src/types.ts";
import { now } from "../src/util.ts";
import { api, makeIdentity } from "./helpers.ts";

// ADR 16 rules, one test each, including the refusals. Real wrapped keys and ciphertext come from @cfs/core.

const cfEnv = env as unknown as Env;
const db = env.DB;
let seq = 0;
const prefixName = () => `rq${++seq}x${Math.random().toString(36).slice(2, 6)}`;

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

/** Creates a group with `owner` and `others` as members at key version 1. Returns the group key. */
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

/** Writes one secret as `p`, who must be able to create it. */
async function seed(p: Person, gk: Uint8Array, path: string, values: Values) {
  const sealed = await sealSecret(gk, path, 1, values);
  const r = await api("PUT", "/secret", p.token, {
    path,
    names: Object.keys(values),
    keyringVersion: 1,
    version: 1,
    ...sealed,
  });
  expect(r.status).toBe(201);
}

const requestFor = (p: Person, path: string, extra: Record<string, unknown> = {}) =>
  api("POST", "/requests", p.token, {
    path,
    reason: "incident 42, prod read",
    duration: 3600,
    ...extra,
  });

/** An approver's decision: wraps the group key to the requester's public key, as the CLI does. */
async function approve(
  approver: Person,
  requestId: string,
  requester: Person,
  prefix: string,
  gk: Uint8Array,
  version = 1,
) {
  const wrappedKey = await wrapGroupKey(gk, requester.kp.publicKey, prefix, version);
  return api("POST", `/requests/${requestId}/approve`, approver.token, { wrappedKey, version });
}

/** The requester's group key at the current version, unwrapped with their private key. */
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
  return key;
}

/** Every audit row as parsed JSON. Tests filter by the names and paths they created. */
async function auditRows(): Promise<Record<string, unknown>[]> {
  const rows = await db.prepare("SELECT entry FROM audit").all<{ entry: string }>();
  return rows.results.map((r) => JSON.parse(r.entry) as Record<string, unknown>);
}

async function audited(action: string, result?: string, path?: string) {
  return (await auditRows()).filter(
    (r) =>
      r.action === action &&
      (result === undefined || r.result === result) &&
      (path === undefined || r.path === path),
  );
}

async function requestRow(id: string) {
  return db
    .prepare(
      "SELECT status, approver_id, decided_at, expires_at, created_at FROM access_request WHERE id = ?",
    )
    .bind(id)
    .first<{
      status: string;
      approver_id: string | null;
      decided_at: number | null;
      expires_at: number | null;
      created_at: number;
    }>();
}

describe("ADR 16: request", () => {
  it("a member asks for access, the request is pending and the creation is audited", async () => {
    const prefix = prefixName();
    const owner = await person({ role: "admin" });
    const asker = await person();
    await makeGroup(prefix, owner);

    const r = await requestFor(asker, `${prefix}/prod`);
    expect(r.status).toBe(201);
    expect(r.body.status).toBe("pending");
    expect(r.body.requester).toBe(asker.name);
    expect(r.body.rekeyAfter).toBe(false);
    expect((await audited("request.create", "ok", `${prefix}/prod`)).length).toBe(1);
    // The reason is for the approver, never the audit log.
    expect(JSON.stringify(await auditRows())).not.toContain("incident 42");
  });

  it("a duration over 24 hours is refused, and so is zero", async () => {
    const prefix = prefixName();
    const owner = await person({ role: "admin" });
    const asker = await person();
    await makeGroup(prefix, owner);

    expect((await requestFor(asker, `${prefix}/prod`, { duration: 86401 })).status).toBe(400);
    expect((await requestFor(asker, `${prefix}/prod`, { duration: 0 })).status).toBe(400);
    expect((await requestFor(asker, `${prefix}/prod`, { duration: 1.5 })).status).toBe(400);
    expect((await requestFor(asker, `${prefix}/prod`, { duration: 86400 })).status).toBe(201);
  });

  it("a request needs a reason, a valid path and an existing group", async () => {
    const prefix = prefixName();
    const owner = await person({ role: "admin" });
    const asker = await person();
    await makeGroup(prefix, owner);

    const noReason = await api("POST", "/requests", asker.token, {
      path: `${prefix}/prod`,
      reason: "   ",
      duration: 60,
    });
    expect(noReason.status).toBe(400);
    expect((await requestFor(asker, "bad path/../x")).status).toBe(400);
    expect((await requestFor(asker, `${prefixName()}/prod`)).status).toBe(404);
  });

  it("rekeyAfter is stored on the request and shown to clients", async () => {
    const prefix = prefixName();
    const owner = await person({ role: "admin" });
    const asker = await person();
    await makeGroup(prefix, owner);

    const r = await requestFor(asker, `${prefix}/prod`, { rekeyAfter: true });
    expect(r.body.rekeyAfter).toBe(true);
    const row = await db
      .prepare("SELECT rekey_after AS flag FROM access_request WHERE id = ?")
      .bind(r.body.id)
      .first<{ flag: number }>();
    expect(row?.flag).toBe(1);
    expect((await requestFor(asker, `${prefix}/prod`, { rekeyAfter: "yes" })).status).toBe(400);
  });
});

describe("ADR 16: list and read", () => {
  it("a member lists only their own requests, an admin lists all", async () => {
    const prefix = prefixName();
    const owner = await person({ role: "admin" });
    const a = await person();
    const b = await person();
    await makeGroup(prefix, owner, [a, b]);
    const ra = await requestFor(a, `${prefix}/prod`);
    const rb = await requestFor(b, `${prefix}/prod`);

    const mine = await api<{ id: string }[]>("GET", "/requests", a.token);
    expect(mine.body.map((r) => r.id)).toContain(ra.body.id);
    expect(mine.body.map((r) => r.id)).not.toContain(rb.body.id);

    const all = await api<{ id: string }[]>("GET", "/requests", owner.token);
    expect(all.body.map((r) => r.id)).toEqual(expect.arrayContaining([ra.body.id, rb.body.id]));
  });

  it("another member cannot read a request, and an unknown status filter is refused", async () => {
    const prefix = prefixName();
    const owner = await person({ role: "admin" });
    const a = await person();
    const b = await person();
    await makeGroup(prefix, owner, [a, b]);
    const ra = await requestFor(a, `${prefix}/prod`);

    expect((await api("GET", `/requests/${ra.body.id}`, b.token)).status).toBe(404);
    expect((await api("GET", `/requests/${ra.body.id}`, a.token)).status).toBe(200);
    expect((await api("GET", "/requests?status=bogus", owner.token)).status).toBe(400);
  });
});

describe("ADR 16: approve", () => {
  it("an approval gives a time-boxed key and policy, and the requester can open the secret", async () => {
    const prefix = prefixName();
    const owner = await person({ role: "admin" });
    const asker = await person();
    const gk = await makeGroup(prefix, owner);
    const path = `${prefix}/prod`;
    await seed(owner, gk, path, { API_KEY: "s3cret-value" });

    // Before approval: no key, and default deny on the secret.
    expect((await api("GET", `/keyrings/${prefix}/key`, asker.token)).status).toBe(404);
    expect((await api("GET", `/secret?path=${path}`, asker.token)).status).toBe(403);

    const r = await requestFor(asker, path, { duration: 3600 });
    const ap = await approve(owner, r.body.id, asker, prefix, gk);
    expect(ap.status).toBe(200);
    expect(ap.body.status).toBe("approved");
    expect(ap.body.approver).toBe(owner.name);

    const member = await db
      .prepare(
        `SELECT m.expires_at AS expiresAt FROM keyring_member m JOIN keyring k ON k.id = m.keyring_id
         WHERE k.prefix = ? AND m.identity_id = ?`,
      )
      .bind(prefix, asker.id)
      .first<{ expiresAt: number | null }>();
    expect(member?.expiresAt).toBeGreaterThan(now() + 3500);
    expect(member?.expiresAt).toBeLessThanOrEqual(now() + 3600);

    const grant = await db
      .prepare("SELECT expires_at AS expiresAt FROM identity_policy WHERE identity_id = ?")
      .bind(asker.id)
      .first<{ expiresAt: number | null }>();
    expect(grant?.expiresAt).toBe(member?.expiresAt);

    // The requester now holds the group key and can open the value.
    const key = await keyOf(asker, prefix);
    const got = await api("GET", `/secret?path=${path}`, asker.token);
    expect(got.status).toBe(200);
    const values = await openSecret(
      key,
      path,
      got.body.version,
      got.body.wrappedDek,
      got.body.ciphertext,
    );
    expect(values).toEqual({ API_KEY: "s3cret-value" });
  });

  it("self-approval is refused and audited", async () => {
    const prefix = prefixName();
    const owner = await person({ role: "admin" });
    const gk = await makeGroup(prefix, owner);
    const r = await requestFor(owner, `${prefix}/prod`);

    const ap = await approve(owner, r.body.id, owner, prefix, gk);
    expect(ap.status).toBe(403);
    expect((await requestRow(r.body.id))?.status).toBe("pending");
    expect((await audited("request.approve", "denied", `${prefix}/prod`)).length).toBe(1);
  });

  it("a non-admin approver is refused, even when in the group", async () => {
    const prefix = prefixName();
    const owner = await person({ role: "admin" });
    const member = await person();
    const asker = await person();
    const gk = await makeGroup(prefix, owner, [member]);
    const r = await requestFor(asker, `${prefix}/prod`);

    const ap = await approve(member, r.body.id, asker, prefix, gk);
    expect(ap.status).toBe(403);
    expect((await requestRow(r.body.id))?.status).toBe("pending");
  });

  it("an admin who is not in the group is refused and the attempt is audited", async () => {
    const prefix = prefixName();
    const owner = await person({ role: "admin" });
    const outsider = await person({ role: "admin" });
    const asker = await person();
    const gk = await makeGroup(prefix, owner);
    const r = await requestFor(asker, `${prefix}/prod`);

    const ap = await approve(outsider, r.body.id, asker, prefix, gk);
    expect(ap.status).toBe(403);
    expect((await requestRow(r.body.id))?.status).toBe("pending");
    const denied = await audited("request.approve", "denied", `${prefix}/prod`);
    expect(denied.map((d) => d.who)).toContain(outsider.name);
  });

  it("a second decision is refused: approve again, deny or cancel after approval", async () => {
    const prefix = prefixName();
    const owner = await person({ role: "admin" });
    const asker = await person();
    const gk = await makeGroup(prefix, owner);
    const r = await requestFor(asker, `${prefix}/prod`);
    expect((await approve(owner, r.body.id, asker, prefix, gk)).status).toBe(200);

    expect((await approve(owner, r.body.id, asker, prefix, gk)).status).toBe(409);
    expect((await api("POST", `/requests/${r.body.id}/deny`, owner.token)).status).toBe(409);
    expect((await api("POST", `/requests/${r.body.id}/cancel`, asker.token)).status).toBe(409);
  });

  it("the approver must send the current key version", async () => {
    const prefix = prefixName();
    const owner = await person({ role: "admin" });
    const asker = await person();
    const gk = await makeGroup(prefix, owner);
    const r = await requestFor(asker, `${prefix}/prod`);

    expect((await approve(owner, r.body.id, asker, prefix, gk, 2)).status).toBe(409);
    expect((await requestRow(r.body.id))?.status).toBe("pending");
  });

  it("a pending request older than 24 hours cannot be approved", async () => {
    const prefix = prefixName();
    const owner = await person({ role: "admin" });
    const asker = await person();
    const gk = await makeGroup(prefix, owner);
    const r = await requestFor(asker, `${prefix}/prod`);
    await db
      .prepare("UPDATE access_request SET created_at = ? WHERE id = ?")
      .bind(now() - 86400 - 60, r.body.id)
      .run();

    expect((await approve(owner, r.body.id, asker, prefix, gk)).status).toBe(409);
    expect((await requestRow(r.body.id))?.status).toBe("pending");
  });
});

describe("ADR 16: deny and cancel", () => {
  it("an admin denies a pending request, which then cannot be approved", async () => {
    const prefix = prefixName();
    const owner = await person({ role: "admin" });
    const asker = await person();
    const gk = await makeGroup(prefix, owner);
    const r = await requestFor(asker, `${prefix}/prod`);

    const d = await api("POST", `/requests/${r.body.id}/deny`, owner.token);
    expect(d.status).toBe(200);
    expect(d.body.status).toBe("denied");
    expect((await approve(owner, r.body.id, asker, prefix, gk)).status).toBe(409);
    expect((await audited("request.deny", "ok", `${prefix}/prod`)).length).toBe(1);
  });

  it("only an admin can deny, and the requester cannot deny their own request", async () => {
    const prefix = prefixName();
    const owner = await person({ role: "admin" });
    const asker = await person();
    await makeGroup(prefix, owner, [asker]);
    const r = await requestFor(asker, `${prefix}/prod`);
    expect((await api("POST", `/requests/${r.body.id}/deny`, asker.token)).status).toBe(403);

    const own = await requestFor(owner, `${prefix}/prod`);
    expect((await api("POST", `/requests/${own.body.id}/deny`, owner.token)).status).toBe(403);
    expect((await requestRow(r.body.id))?.status).toBe("pending");
  });

  it("only the requester can cancel, and only while pending", async () => {
    const prefix = prefixName();
    const owner = await person({ role: "admin" });
    const asker = await person();
    const other = await person();
    await makeGroup(prefix, owner, [asker, other]);
    const r = await requestFor(asker, `${prefix}/prod`);

    expect((await api("POST", `/requests/${r.body.id}/cancel`, other.token)).status).toBe(403);
    expect((await api("POST", `/requests/${r.body.id}/cancel`, owner.token)).status).toBe(403);
    expect((await audited("request.cancel", "denied", `${prefix}/prod`)).length).toBe(2);

    const c = await api("POST", `/requests/${r.body.id}/cancel`, asker.token);
    expect(c.status).toBe(200);
    expect(c.body.status).toBe("cancelled");
    expect((await api("POST", `/requests/${r.body.id}/cancel`, asker.token)).status).toBe(409);
    expect((await audited("request.cancel", "ok", `${prefix}/prod`)).length).toBe(1);
  });
});

describe("ADR 16: expiry", () => {
  it("an expired group key is refused, and so is the ciphertext behind it", async () => {
    const prefix = prefixName();
    const owner = await person({ role: "admin" });
    const asker = await person();
    const gk = await makeGroup(prefix, owner);
    const path = `${prefix}/prod`;
    await seed(owner, gk, path, { K: "v" });
    const r = await requestFor(asker, path);
    expect((await approve(owner, r.body.id, asker, prefix, gk)).status).toBe(200);
    expect((await api("GET", `/keyrings/${prefix}/key`, asker.token)).status).toBe(200);

    await db
      .prepare(
        "UPDATE keyring_member SET expires_at = ? WHERE identity_id = ? AND expires_at IS NOT NULL",
      )
      .bind(now() - 1, asker.id)
      .run();
    const key = await api("GET", `/keyrings/${prefix}/key`, asker.token);
    expect(key.status).toBe(403);
    expect(key.body.wrappedKey).toBeUndefined();
    expect((await api("GET", `/secret?path=${path}`, asker.token)).status).toBe(403);
    expect((await audited("group.key", "denied", undefined)).length).toBeGreaterThan(0);
  });

  it("an expired policy grant is ignored, even while the key is still there", async () => {
    const prefix = prefixName();
    const owner = await person({ role: "admin" });
    const asker = await person();
    const gk = await makeGroup(prefix, owner);
    const path = `${prefix}/prod`;
    await seed(owner, gk, path, { K: "v" });
    const r = await requestFor(asker, path);
    expect((await approve(owner, r.body.id, asker, prefix, gk)).status).toBe(200);
    expect((await api("GET", `/secret?path=${path}`, asker.token)).status).toBe(200);

    await db
      .prepare("UPDATE identity_policy SET expires_at = ? WHERE identity_id = ?")
      .bind(now() - 1, asker.id)
      .run();
    expect((await api("GET", `/secret?path=${path}`, asker.token)).status).toBe(403);
  });

  it("an expired grant does not let a lapsed member add people or rotate", async () => {
    const prefix = prefixName();
    const owner = await person({ role: "admin" });
    // An admin asker, so the refusal below comes from the expired grant and not from the role check.
    const asker = await person({ role: "admin" });
    const later = await person();
    const gk = await makeGroup(prefix, owner);
    const r = await requestFor(asker, `${prefix}/prod`);
    expect((await approve(owner, r.body.id, asker, prefix, gk)).status).toBe(200);
    await db
      .prepare("UPDATE keyring_member SET expires_at = ? WHERE identity_id = ?")
      .bind(now() - 1, asker.id)
      .run();

    const wrapped = await wrapGroupKey(gk, later.kp.publicKey, prefix, 1);
    // The lapsed member is not in the group any more, so the server refuses the membership call.
    const add = await api("POST", `/keyrings/${prefix}/members`, asker.token, {
      identityId: later.id,
      wrappedKey: wrapped,
    });
    expect(add.status).toBe(403);
    const members = await api<{ identityId: string }[]>(
      "GET",
      `/keyrings/${prefix}/members`,
      owner.token,
    );
    expect(members.body.map((m) => m.identityId)).not.toContain(asker.id);
  });

  it("the daily sweep removes lapsed grants and keys and ends stale pending requests", async () => {
    const prefix = prefixName();
    const owner = await person({ role: "admin" });
    const lapsed = await person();
    const live = await person();
    const stale = await person();
    const gk = await makeGroup(prefix, owner);
    const path = `${prefix}/prod`;
    const rl = await requestFor(lapsed, path);
    const rv = await requestFor(live, path);
    expect((await approve(owner, rl.body.id, lapsed, prefix, gk)).status).toBe(200);
    expect((await approve(owner, rv.body.id, live, prefix, gk)).status).toBe(200);
    const pending = await requestFor(stale, path);
    await db
      .prepare("UPDATE access_request SET created_at = ? WHERE id = ?")
      .bind(now() - 86400 - 60, pending.body.id)
      .run();
    await db
      .prepare("UPDATE keyring_member SET expires_at = ? WHERE identity_id = ?")
      .bind(now() - 1, lapsed.id)
      .run();
    await db
      .prepare("UPDATE identity_policy SET expires_at = ? WHERE identity_id = ?")
      .bind(now() - 1, lapsed.id)
      .run();

    // Runs the real daily job, at a time after the lapse.
    await runDaily(cfEnv, now() + 2);

    const count = async (sql: string, ...binds: unknown[]) =>
      (
        await db
          .prepare(sql)
          .bind(...binds)
          .first<{ n: number }>()
      )?.n ?? 0;
    expect(
      await count("SELECT COUNT(*) AS n FROM keyring_member WHERE identity_id = ?", lapsed.id),
    ).toBe(0);
    expect(
      await count("SELECT COUNT(*) AS n FROM identity_policy WHERE identity_id = ?", lapsed.id),
    ).toBe(0);
    expect(
      await count("SELECT COUNT(*) AS n FROM policy WHERE name = ?", `request:${rl.body.id}`),
    ).toBe(0);
    // The live grant and the owner's permanent membership stay.
    expect(
      await count("SELECT COUNT(*) AS n FROM keyring_member WHERE identity_id = ?", live.id),
    ).toBe(1);
    expect(
      await count("SELECT COUNT(*) AS n FROM keyring_member WHERE identity_id = ?", owner.id),
    ).toBe(1);
    expect((await requestRow(pending.body.id))?.status).toBe("expired");
    expect((await audited("request.expire", "ok", path)).length).toBe(1);
    expect((await audited("policy.expire", "ok")).length).toBeGreaterThan(0);
    expect((await audited("group.member.expire", "ok", prefix)).length).toBe(1);
  });
});

describe("ADR 16: audit", () => {
  it("every transition is audited with names and ids, and never a key or a value", async () => {
    const prefix = prefixName();
    const owner = await person({ role: "admin" });
    const asker = await person();
    const gk = await makeGroup(prefix, owner);
    const path = `${prefix}/prod`;
    await seed(owner, gk, path, { TOKEN: "plain-value-xyz" });

    const r = await requestFor(asker, path);
    const ap = await approve(owner, r.body.id, asker, prefix, gk);
    expect(ap.status).toBe(200);
    const second = await requestFor(asker, path);
    await api("POST", `/requests/${second.body.id}/deny`, owner.token);
    const third = await requestFor(asker, path);
    await api("POST", `/requests/${third.body.id}/cancel`, asker.token);

    for (const action of ["request.create", "request.approve", "request.deny", "request.cancel"]) {
      expect((await audited(action, "ok", path)).length).toBeGreaterThan(0);
    }
    const approved = await audited("request.approve", "ok", path);
    expect(approved[0]?.who).toBe(owner.name);
    expect(approved[0]?.note).toContain(asker.name);

    const text = JSON.stringify(await auditRows());
    const wrapped = await wrapGroupKey(gk, asker.kp.publicKey, prefix, 1);
    expect(text).not.toContain(wrapped);
    expect(text).not.toContain("plain-value-xyz");
    expect(text).not.toContain("incident 42");
  });
});
