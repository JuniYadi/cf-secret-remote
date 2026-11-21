import { env } from "cloudflare:test";
import { generateKeyPair, newGroupKey, sealSecret, type Values, wrapGroupKey } from "@cfs/core";
import { describe, expect, it } from "vitest";
import { admin, api, makeIdentity } from "./helpers.ts";

// ADR 21 rules, one test each. Real Workers runtime and D1. Membership removal itself is the client-driven
// rotation tested in membership.test.ts and the CLI tests; here group rows are dropped directly where a
// test needs a person out of a group.

const DAY = 86400;
let seq = 0;
const uniq = (tag: string) => `${tag}${++seq}x${Math.random().toString(36).slice(2, 6)}`;

type Person = {
  id: string;
  name: string;
  token: string;
  kp: { publicKey: string; privateKey: string };
};

async function person(opts: { role?: "admin" | "member"; vault?: boolean } = {}): Promise<Person> {
  const kp = await generateKeyPair();
  const p = await makeIdentity({
    role: opts.role,
    publicKey: opts.vault === false ? undefined : kp.publicKey,
  });
  return { ...p, kp };
}

/** Creates a group with `members` (the admin included in the wrap), and returns the key and keyring id. */
async function group(prefix: string, adm: Person, members: Person[]) {
  const gk = await newGroupKey();
  const r = await api("POST", "/keyrings", adm.token, {
    prefix,
    members: await Promise.all(
      [adm, ...members].map(async (m) => ({
        identityId: m.id,
        wrappedKey: await wrapGroupKey(gk, m.kp.publicKey, prefix, 1),
      })),
    ),
  });
  expect(r.status).toBe(201);
  const row = await env.DB.prepare("SELECT id FROM keyring WHERE prefix = ?")
    .bind(prefix)
    .first<{ id: string }>();
  return { gk, keyringId: row?.id ?? "" };
}

/** Gives a member read and list on a group's paths, through a policy (ADR 5). */
async function grantRead(p: Person, prefix: string) {
  const policyId = uniq("pol");
  await env.DB.batch([
    env.DB.prepare("INSERT INTO policy (id, name, rules) VALUES (?, ?, ?)").bind(
      policyId,
      policyId,
      JSON.stringify([{ path: `${prefix}/*`, caps: ["read", "list"] }]),
    ),
    env.DB.prepare("INSERT INTO identity_policy (identity_id, policy_id) VALUES (?, ?)").bind(
      p.id,
      policyId,
    ),
  ]);
}

async function put(adm: Person, gk: Uint8Array, path: string, values: Values) {
  const sealed = await sealSecret(gk, path, 1, values);
  return api("PUT", "/secret", adm.token, {
    path,
    names: Object.keys(values),
    keyringVersion: 1,
    version: 1,
    ...sealed,
  });
}

/** Moves every read of `path` by `who` back by `days`, as versions.test.ts does for history windows. */
async function ageRead(who: string, path: string, days: number) {
  await env.DB.prepare(
    `UPDATE audit SET at = at - ? WHERE seq = (SELECT MIN(seq) FROM audit
       WHERE who = ? AND json_extract(entry, '$.path') = ? AND json_extract(entry, '$.action') = 'secret.read')`,
  )
    .bind(days * DAY, who, path)
    .run();
}

async function countRows(sql: string, ...binds: unknown[]) {
  const row = await env.DB.prepare(`SELECT COUNT(*) AS n FROM (${sql})`)
    .bind(...binds)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

async function auditFor(
  name: string,
): Promise<{ action: string; result: string; note?: string }[]> {
  const rows = await env.DB.prepare("SELECT entry FROM audit WHERE who = ? ORDER BY seq")
    .bind(name)
    .all<{ entry: string }>();
  return rows.results.map((r) => JSON.parse(r.entry));
}

/** An app owned by `owner`, inserted directly (apps are made by the creator, so the owner is set here). */
async function ownedApp(owner: Person, status: "active" | "disabled" = "active") {
  const id = uniq("app");
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO identity (id, kind, name, role, public_key, status, owner_id, created_at) VALUES (?, 'app', ?, 'member', ?, ?, ?, 1)",
    ).bind(id, `${id}-bot`, `pk-${id}`, status, owner.id),
    env.DB.prepare(
      "INSERT INTO app_role (identity_id, role_id, secret_hash, token_ttl) VALUES (?, ?, 'h', 3600)",
    ).bind(id, `role-${id}`),
  ]);
  return { id, name: `${id}-bot` };
}

describe("ADR 20 and 21: the two-admin guard applies to offboarding", () => {
  // Runs first: it counts every admin in storage, so the other admins are disabled up front.
  it("finish is refused while it would leave fewer than two admins with a vault", async () => {
    await env.DB.prepare("UPDATE identity SET status = 'disabled' WHERE role = 'admin'").run();
    const a1 = await admin("pk-a1");
    const b = await admin("pk-b");

    const refused = await api("POST", `/offboard/${b.id}/finish`, a1.token, {});
    expect(refused.status).toBe(409);
    expect(refused.body.blockers.twoAdmins).toBe(true);
    const plan = await api("GET", `/offboard/${b.id}/plan`, a1.token);
    expect(plan.body.canFinish).toBe(false);
    expect(plan.body.blockers.twoAdmins).toBe(true);
    expect((await api("GET", "/whoami", b.token)).status).toBe(200);

    // An admin without a vault does not count toward the two.
    await admin();
    expect((await api("POST", `/offboard/${b.id}/finish`, a1.token, {})).status).toBe(409);

    // A third admin with a vault: now the offboarding may finish.
    await admin("pk-a3");
    expect((await api("POST", `/offboard/${b.id}/finish`, a1.token, {})).status).toBe(200);
    expect((await api("GET", "/whoami", a1.token)).status).toBe(200);

    const denied = await auditFor(a1.name);
    expect(
      denied.some(
        (e) => e.action === "offboard.finish" && e.result === "denied" && e.note?.includes(b.name),
      ),
    ).toBe(true);
  });
});

describe("ADR 21: only admins plan and finish", () => {
  it("a non-admin is refused on plan, finish and reassign; the target stays active", async () => {
    const mem = await person();
    const target = await person();
    const app = await ownedApp(target);

    expect((await api("GET", `/offboard/${target.id}/plan`, mem.token)).status).toBe(403);
    expect((await api("POST", `/offboard/${target.id}/finish`, mem.token, {})).status).toBe(403);
    expect(
      (
        await api("POST", `/offboard/${target.id}/apps/${app.id}/reassign`, mem.token, {
          ownerId: mem.id,
        })
      ).status,
    ).toBe(403);
    expect((await api("GET", "/whoami", target.token)).status).toBe(200);
  });

  it("unknown people are 404, apps are refused (they use cfs app disable), and nobody offboards themselves", async () => {
    const adm = await admin("pk-adm-y");
    const other = await person();
    const app = await ownedApp(other);
    expect((await api("GET", "/offboard/nope/plan", adm.token)).status).toBe(404);
    expect((await api("GET", `/offboard/${app.id}/plan`, adm.token)).status).toBe(400);
    expect((await api("POST", `/offboard/${app.id}/finish`, adm.token, {})).status).toBe(400);
    expect((await api("POST", `/offboard/${adm.id}/finish`, adm.token, {})).status).toBe(400);
  });
});

describe("ADR 21: the plan", () => {
  it("lists groups, owned apps, sessions and opened secrets from the last 90 days only; never values", async () => {
    const prefix = uniq("plan");
    const adm = await person({ role: "admin" });
    const p = await person();
    const { gk } = await group(prefix, adm, [p]);
    await grantRead(p, prefix);
    const marker = `PLAN_MARKER_${uniq("v")}`;
    const recent = `${prefix}/recent`;
    const old = `${prefix}/old`;
    expect((await put(adm, gk, recent, { DB_PASS: marker, API_KEY: "k2" })).status).toBe(201);
    expect((await put(adm, gk, old, { OLD_NAME: "o" })).status).toBe(201);
    expect((await api("GET", `/secret?path=${recent}`, p.token)).status).toBe(200);
    expect((await api("GET", `/secret?path=${old}`, p.token)).status).toBe(200);
    await ageRead(p.name, old, 100);
    const app = await ownedApp(p);

    const plan = await api("GET", `/offboard/${p.id}/plan`, adm.token);
    expect(plan.status).toBe(200);
    expect(plan.body.groups).toEqual([prefix]);
    expect(plan.body.apps.map((a: { id: string }) => a.id)).toEqual([app.id]);
    expect(plan.body.sessions.length).toBe(1);
    expect(plan.body.sessions[0]).not.toHaveProperty("token_hash");

    // Only the read inside the window is listed; names and versions, not values.
    expect(plan.body.opened.windowDays).toBe(90);
    expect(plan.body.opened.secrets.map((s: { path: string }) => s.path)).toEqual([recent]);
    expect(plan.body.opened.secrets[0].names).toEqual(["API_KEY", "DB_PASS"]);
    expect(plan.body.opened.secrets[0].versions).toEqual([1]);

    const text = JSON.stringify(plan.body);
    expect(text).not.toContain(marker);
    expect(text).not.toMatch(/wrappedDek|ciphertext|wrapped_key|token_hash/);
  });

  it("blocks finish while the person is in a group, including a staged rotation membership", async () => {
    const prefix = uniq("staged");
    const adm = await person({ role: "admin" });
    const p = await person();
    const { keyringId } = await group(prefix, adm, [p]);

    // A rotation in progress stages the person's membership for the next version.
    await env.DB.prepare(
      "INSERT INTO keyring_member_staged (keyring_id, identity_id, version, wrapped_key) VALUES (?, ?, 2, 'x.y')",
    )
      .bind(keyringId, p.id)
      .run();
    const refused = await api("POST", `/offboard/${p.id}/finish`, adm.token, {});
    expect(refused.status).toBe(409);
    expect(refused.body.blockers.groups).toEqual([prefix]);
    expect((await api("GET", `/offboard/${p.id}/plan`, adm.token)).body.canFinish).toBe(false);
  });
});

describe("ADR 21: finish", () => {
  it("is refused while the person owns an active app, but a disabled app does not block", async () => {
    const adm = await admin("pk-own-adm");
    const p = await person();
    const active = await ownedApp(p);
    const off = await ownedApp(p, "disabled");

    const refused = await api("POST", `/offboard/${p.id}/finish`, adm.token, {});
    expect(refused.status).toBe(409);
    expect(refused.body.blockers.apps).toEqual([active.name]);
    expect(refused.body.blockers.groups).toEqual([]);

    // The CLI disables the app with the existing route (ADR 15). Then the block lifts.
    expect((await api("POST", `/apps/${active.id}/disable`, adm.token, {})).status).toBe(200);
    expect(off.id).not.toBe(active.id);
    expect((await api("POST", `/offboard/${p.id}/finish`, adm.token, {})).status).toBe(200);
  });

  it("reassigns an owned app to another active person, once, and audits it", async () => {
    const adm = await admin("pk-re-adm");
    const p = await person();
    const next = await person();
    const app = await ownedApp(p);
    const stranger = await person();

    // Only the owner's app can be moved, and only to an active person who is not the one leaving.
    expect(
      (await api("POST", `/offboard/${p.id}/apps/${app.id}/reassign`, adm.token, { ownerId: p.id }))
        .status,
    ).toBe(400);
    expect(
      (
        await api("POST", `/offboard/${p.id}/apps/${app.id}/reassign`, adm.token, {
          ownerId: "nope",
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await api("POST", `/offboard/${stranger.id}/apps/${app.id}/reassign`, adm.token, {
          ownerId: next.id,
        })
      ).status,
    ).toBe(409);

    const moved = await api("POST", `/offboard/${p.id}/apps/${app.id}/reassign`, adm.token, {
      ownerId: next.id,
    });
    expect(moved.status).toBe(200);
    expect(moved.body.changed).toBe(true);
    const again = await api("POST", `/offboard/${p.id}/apps/${app.id}/reassign`, adm.token, {
      ownerId: next.id,
    });
    expect(again.body.changed).toBe(false);
    expect((await api("POST", `/offboard/${p.id}/finish`, adm.token, {})).status).toBe(200);
    expect(
      (await auditFor(adm.name)).some((e) => e.action === "app.reassign" && e.result === "ok"),
    ).toBe(true);
  });

  it("ends sessions, removes policies, disables the person, and audits each step; re-running changes nothing", async () => {
    const prefix = uniq("fin");
    const adm = await person({ role: "admin" });
    const p = await person();
    const { gk, keyringId } = await group(prefix, adm, [p]);
    await grantRead(p, prefix);
    const marker = `FIN_MARKER_${uniq("v")}`;
    expect((await put(adm, gk, `${prefix}/s`, { K: marker })).status).toBe(201);
    expect((await api("GET", `/secret?path=${prefix}/s`, p.token)).status).toBe(200);
    expect(await countRows("SELECT 1 FROM identity_policy WHERE identity_id = ?", p.id)).toBe(1);

    // Group removal (ADR 14) is done by the client before finish. Here the rows are dropped directly.
    await env.DB.prepare("DELETE FROM keyring_member WHERE keyring_id = ? AND identity_id = ?")
      .bind(keyringId, p.id)
      .run();

    const first = await api("POST", `/offboard/${p.id}/finish`, adm.token, {});
    expect(first.status).toBe(200);
    expect(first.body).toEqual({
      id: p.id,
      status: "disabled",
      changed: { disabled: true, sessionsEnded: 1, policiesRemoved: 1 },
    });

    // Sessions ended and sign-in refused; the policy link and the active state are gone.
    expect((await api("GET", "/whoami", p.token)).status).toBe(401);
    expect(await countRows("SELECT 1 FROM session WHERE identity_id = ?", p.id)).toBe(0);
    expect(await countRows("SELECT 1 FROM identity_policy WHERE identity_id = ?", p.id)).toBe(0);
    const row = await env.DB.prepare("SELECT status FROM identity WHERE id = ?")
      .bind(p.id)
      .first<{ status: string }>();
    expect(row?.status).toBe("disabled");

    // Re-running is safe: same result, nothing changed, and the run is still audited.
    const again = await api("POST", `/offboard/${p.id}/finish`, adm.token, {});
    expect(again.status).toBe(200);
    expect(again.body.changed).toEqual({ disabled: false, sessionsEnded: 0, policiesRemoved: 0 });
    const plan = await api("GET", `/offboard/${p.id}/plan`, adm.token);
    expect(plan.body.person.status).toBe("disabled");
    expect(plan.body.canFinish).toBe(true);

    const actions = (await auditFor(adm.name))
      .filter((e) => e.note?.includes(p.name) || e.note === p.name)
      .map((e) => e.action);
    expect(actions).toEqual(
      expect.arrayContaining([
        "identity.disable",
        "offboard.sessions",
        "offboard.policies",
        "offboard.finish",
      ]),
    );
    expect(actions.filter((a) => a === "offboard.finish").length).toBe(2);
    // Audit rows hold names and counts only, never values.
    const dump = JSON.stringify(await env.DB.prepare("SELECT entry FROM audit").all());
    expect(dump).not.toContain(marker);
  });
});
