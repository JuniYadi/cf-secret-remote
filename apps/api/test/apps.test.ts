import { env, SELF } from "cloudflare:test";
import { generateKeyPair } from "@cfs/core";
import { describe, expect, it } from "vitest";
import { sha256Hex } from "../src/util.ts";
import { admin, api, makeIdentity } from "./helpers.ts";

// ADR 15: apps and bots lifecycle. Every rule has at least one test, including the refusals.

let seq = 0;
const uniq = (s: string) => `${s}-${Date.now().toString(36)}-${++seq}`;

/** Creates an app through the API. The key pair is made here, as the CLI or browser would; only the public key is sent. */
async function newApp(
  adm: { token: string },
  extra: Record<string, unknown> = {},
  name = uniq("bot"),
) {
  const pair = await generateKeyPair();
  const r = await api("POST", "/apps", adm.token, { name, publicKey: pair.publicKey, ...extra });
  return {
    status: r.status,
    body: r.body,
    id: r.body.id as string,
    roleId: r.body.roleId as string,
    secretId: r.body.secretId as string,
    name,
    pair,
  };
}

/** AppRole login. `ip` is set as CF-Connecting-IP, as Cloudflare does in production. */
async function login(roleId: string, secretId: string, ip?: string) {
  const r = await SELF.fetch("http://t.test/api/v1/auth/approle/login", {
    method: "POST",
    headers: { "content-type": "application/json", ...(ip ? { "CF-Connecting-IP": ip } : {}) },
    body: JSON.stringify({ roleId, secretId }),
  });
  return { status: r.status, body: (await r.json()) as { token?: string; expiresIn?: number } };
}

const auditText = async () =>
  (await env.DB.prepare("SELECT entry FROM audit").all<{ entry: string }>()).results
    .map((r) => r.entry)
    .join("\n");

describe("ADR 15: create", () => {
  it("returns role_id and secret_id once, and stores secret_id only as a hash", async () => {
    const adm = await admin();
    const app = await newApp(adm);
    expect(app.status).toBe(201);
    expect(app.secretId).toMatch(/^cfssid_/);

    const row = await env.DB.prepare("SELECT * FROM app_role WHERE role_id = ?")
      .bind(app.roleId)
      .first<{ secret_hash: string }>();
    expect(row?.secret_hash).toBe(await sha256Hex(app.secretId));
    expect(JSON.stringify(row)).not.toContain(app.secretId);

    // Shown once: no read route returns it, and the audit trail does not hold it.
    const show = await api("GET", `/apps/${app.id}`, adm.token);
    expect(show.body).not.toHaveProperty("secretId");
    expect(JSON.stringify(show.body)).not.toContain(app.secretId);
    expect(await auditText()).not.toContain(app.secretId);
  });

  it("stores the public key only, never the private key", async () => {
    const adm = await admin();
    const app = await newApp(adm);
    const ident = await env.DB.prepare("SELECT * FROM identity WHERE id = ?")
      .bind(app.id)
      .first<{ public_key: string }>();
    expect(ident?.public_key).toBe(app.pair.publicKey);
    expect(JSON.stringify(ident)).not.toContain(app.pair.privateKey);
    expect(await auditText()).not.toContain(app.pair.privateKey);
  });

  it("records the creator as owner, and the app starts as waiting for first sign-in", async () => {
    const adm = await admin();
    const app = await newApp(adm);
    const show = await api("GET", `/apps/${app.id}`, adm.token);
    expect(show.body.owner).toBe(adm.name);
    expect(show.body.waiting).toBe(true);
    expect(show.body.firstLoginAt).toBeNull();
    expect(show.body.status).toBe("active");
  });

  it("uses a 1 hour token TTL by default and accepts up to 24 hours", async () => {
    const adm = await admin();
    const def = await newApp(adm);
    expect((await login(def.roleId, def.secretId)).body.expiresIn).toBe(3600);

    const max = await newApp(adm, { tokenTtl: 86400 });
    expect((await login(max.roleId, max.secretId)).body.expiresIn).toBe(86400);
  });

  it("refuses a token TTL over 24 hours or under a minute", async () => {
    const adm = await admin();
    expect((await newApp(adm, { tokenTtl: 86401 })).status).toBe(400);
    expect((await newApp(adm, { tokenTtl: 59 })).status).toBe(400);
  });

  it("refuses bad limits and bad input", async () => {
    const adm = await admin();
    expect((await newApp(adm, { maxUses: 0 })).status).toBe(400);
    expect((await newApp(adm, { maxUses: 1.5 })).status).toBe(400);
    expect((await newApp(adm, { expiresAt: 1000 })).status).toBe(400);
    expect((await newApp(adm, { cidr: "10.0.0.0/33" })).status).toBe(400);
    expect((await newApp(adm, { cidr: "" })).status).toBe(400);
    expect((await newApp(adm, {}, "x".repeat(81))).status).toBe(400);
    const noKey = await api("POST", "/apps", adm.token, { name: uniq("nokey") });
    expect(noKey.status).toBe(400);
    const badKey = await api("POST", "/apps", adm.token, {
      name: uniq("badkey"),
      publicKey: "not a key!",
    });
    expect(badKey.status).toBe(400);
  });

  it("refuses a duplicate name", async () => {
    const adm = await admin();
    const name = uniq("dup");
    expect((await newApp(adm, {}, name)).status).toBe(201);
    expect((await newApp(adm, {}, name)).status).toBe(409);
  });

  it("writes an audit row with the name only", async () => {
    const adm = await admin();
    const name = uniq("audited");
    await newApp(adm, {}, name);
    const rows = await env.DB.prepare("SELECT entry FROM audit WHERE entry LIKE ?")
      .bind(`%"action":"app.create"%`)
      .all<{ entry: string }>();
    const hit = rows.results.map((r) => JSON.parse(r.entry)).find((e) => e.note === name);
    expect(hit).toMatchObject({ who: adm.name, action: "app.create", result: "ok" });
  });
});

describe("ADR 15: list and show", () => {
  it("lists apps without secrets and shows sessions and recent activity", async () => {
    const adm = await admin();
    const app = await newApp(adm);
    await login(app.roleId, app.secretId, "203.0.113.20");

    const list = await api("GET", "/apps", adm.token);
    expect(list.status).toBe(200);
    expect(list.body.map((a: { id: string }) => a.id)).toContain(app.id);
    expect(JSON.stringify(list.body)).not.toContain(app.secretId);

    const show = await api("GET", `/apps/${app.id}`, adm.token);
    expect(show.status).toBe(200);
    expect(show.body.roleId).toBe(app.roleId);
    expect(show.body.lastIp).toBe("203.0.113.20");
    expect(show.body.sessions).toHaveLength(1);
    expect(show.body.activity.map((a: { action: string }) => a.action)).toContain("login.ok");
  });

  it("returns 404 for unknown ids and for people (they are not apps)", async () => {
    const adm = await admin();
    const person = await makeIdentity();
    expect((await api("GET", "/apps/nope", adm.token)).status).toBe(404);
    expect((await api("GET", `/apps/${person.id}`, adm.token)).status).toBe(404);
    expect((await api("POST", `/apps/${person.id}/disable`, adm.token)).status).toBe(404);
  });
});

describe("ADR 15: rotate secret_id", () => {
  it("returns a new secret_id once and invalidates the old one", async () => {
    const adm = await admin();
    const app = await newApp(adm);
    expect((await login(app.roleId, app.secretId)).status).toBe(200);

    const rot = await api("POST", `/apps/${app.id}/rotate`, adm.token);
    expect(rot.status).toBe(200);
    expect(rot.body.roleId).toBe(app.roleId);
    expect(rot.body.secretId).toMatch(/^cfssid_/);
    expect(rot.body.secretId).not.toBe(app.secretId);

    expect((await login(app.roleId, app.secretId)).status).toBe(401);
    expect((await login(app.roleId, rot.body.secretId)).status).toBe(200);
  });

  it("stores the new secret only as a hash and audits the rotation by name", async () => {
    const adm = await admin();
    const app = await newApp(adm);
    const rot = await api("POST", `/apps/${app.id}/rotate`, adm.token);
    const row = await env.DB.prepare("SELECT secret_hash FROM app_role WHERE role_id = ?")
      .bind(app.roleId)
      .first<{ secret_hash: string }>();
    expect(row?.secret_hash).toBe(await sha256Hex(rot.body.secretId));
    expect(await auditText()).not.toContain(rot.body.secretId);
    expect(await auditText()).toContain(`"action":"app.rotate"`);
  });

  it("leaves the key pair alone", async () => {
    const adm = await admin();
    const app = await newApp(adm);
    await api("POST", `/apps/${app.id}/rotate`, adm.token);
    const ident = await env.DB.prepare("SELECT public_key FROM identity WHERE id = ?")
      .bind(app.id)
      .first<{ public_key: string }>();
    expect(ident?.public_key).toBe(app.pair.publicKey);
  });
});

describe("ADR 15: disable", () => {
  it("stops login and ends the app's sessions", async () => {
    const adm = await admin();
    const app = await newApp(adm);
    const ok = await login(app.roleId, app.secretId);
    expect((await api("GET", "/whoami", ok.body.token)).status).toBe(200);

    expect((await api("POST", `/apps/${app.id}/disable`, adm.token)).status).toBe(200);

    expect((await api("GET", "/whoami", ok.body.token)).status).toBe(401);
    const sessions = await env.DB.prepare("SELECT COUNT(*) AS n FROM session WHERE identity_id = ?")
      .bind(app.id)
      .first<{ n: number }>();
    expect(sessions?.n).toBe(0);
    expect((await login(app.roleId, app.secretId)).status).toBe(401);

    const show = await api("GET", `/apps/${app.id}`, adm.token);
    expect(show.body.status).toBe("disabled");
    expect(show.body.activity.map((a: { note: string }) => a.note)).toContain("disabled");
    expect(await auditText()).toContain(`"action":"app.disable"`);
  });

  it("is safe to repeat", async () => {
    const adm = await admin();
    const app = await newApp(adm);
    expect((await api("POST", `/apps/${app.id}/disable`, adm.token)).status).toBe(200);
    expect((await api("POST", `/apps/${app.id}/disable`, adm.token)).status).toBe(200);
  });
});

describe("ADR 15: limits", () => {
  it("max_uses: refuses logins after the limit is used up", async () => {
    const adm = await admin();
    const app = await newApp(adm, { maxUses: 2 });
    expect((await login(app.roleId, app.secretId)).status).toBe(200);
    expect((await login(app.roleId, app.secretId)).status).toBe(200);
    expect((await login(app.roleId, app.secretId)).status).toBe(401);
    const show = await api("GET", `/apps/${app.id}`, adm.token);
    expect(show.body.uses).toBe(2);
    expect(show.body.activity.map((a: { note: string }) => a.note)).toContain("uses exhausted");
  });

  it("max_uses: unlimited when not set", async () => {
    const adm = await admin();
    const app = await newApp(adm);
    for (let i = 0; i < 3; i++) expect((await login(app.roleId, app.secretId)).status).toBe(200);
  });

  it("expires_at: refuses logins once the expiry has passed", async () => {
    const adm = await admin();
    const expiresAt = Math.floor(Date.now() / 1000) + 3600;
    const app = await newApp(adm, { expiresAt });
    expect((await api("GET", `/apps/${app.id}`, adm.token)).body.expiresAt).toBe(expiresAt);
    expect((await login(app.roleId, app.secretId)).status).toBe(200);

    await env.DB.prepare("UPDATE app_role SET expires_at = ? WHERE role_id = ?")
      .bind(Math.floor(Date.now() / 1000) - 10, app.roleId)
      .run();
    expect((await login(app.roleId, app.secretId)).status).toBe(401);
  });
});

describe("ADR 15: network allowlist (IPv4, IPv6, CIDR)", () => {
  const cidr = "203.0.113.0/24, 2001:db8::/32, 198.51.100.4";

  it("allows addresses inside the listed ranges and the exact address", async () => {
    const adm = await admin();
    const app = await newApp(adm, { cidr });
    expect((await api("GET", `/apps/${app.id}`, adm.token)).body.cidr).toEqual([
      "203.0.113.0/24",
      "2001:db8::/32",
      "198.51.100.4",
    ]);
    expect((await login(app.roleId, app.secretId, "203.0.113.7")).status).toBe(200);
    expect((await login(app.roleId, app.secretId, "203.0.113.255")).status).toBe(200);
    expect((await login(app.roleId, app.secretId, "2001:db8::1")).status).toBe(200);
    expect((await login(app.roleId, app.secretId, "198.51.100.4")).status).toBe(200);
  });

  it("denies addresses outside the ranges, a missing address, and other families", async () => {
    const adm = await admin();
    const app = await newApp(adm, { cidr });
    expect((await login(app.roleId, app.secretId, "203.0.114.1")).status).toBe(401);
    expect((await login(app.roleId, app.secretId, "198.51.100.5")).status).toBe(401);
    expect((await login(app.roleId, app.secretId, "2001:db9::1")).status).toBe(401);
    expect((await login(app.roleId, app.secretId)).status).toBe(401);
    const show = await api("GET", `/apps/${app.id}`, adm.token);
    expect(show.body.activity.map((a: { note: string }) => a.note)).toContain(
      "network not allowed",
    );
  });

  it("with no allowlist, any address may log in", async () => {
    const adm = await admin();
    const app = await newApp(adm);
    expect((await login(app.roleId, app.secretId, "192.0.2.1")).status).toBe(200);
  });
});

describe("ADR 15: first and last sign-in", () => {
  it("sets first_login_at once and updates last_login_at and last_ip", async () => {
    const adm = await admin();
    const app = await newApp(adm);
    expect((await api("GET", `/apps/${app.id}`, adm.token)).body.firstLoginAt).toBeNull();

    await login(app.roleId, app.secretId, "203.0.113.9");
    const first = await api("GET", `/apps/${app.id}`, adm.token);
    expect(first.body.firstLoginAt).toEqual(expect.any(Number));
    expect(first.body.lastIp).toBe("203.0.113.9");
    expect(first.body.waiting).toBe(false);

    // Move the first sign-in into the past, then log in again: it must not be overwritten.
    await env.DB.prepare("UPDATE app_role SET first_login_at = 1000 WHERE role_id = ?")
      .bind(app.roleId)
      .run();
    await login(app.roleId, app.secretId, "198.51.100.1");
    const second = await api("GET", `/apps/${app.id}`, adm.token);
    expect(second.body.firstLoginAt).toBe(1000);
    expect(second.body.lastLoginAt).toBeGreaterThan(1000);
    expect(second.body.lastIp).toBe("198.51.100.1");
  });
});

describe("ADR 15: login throttle still applies", () => {
  it("returns 429 after 10 failed logins, even with the right secret", async () => {
    const adm = await admin();
    const app = await newApp(adm);
    const codes = [];
    for (let i = 0; i < 10; i++) codes.push((await login(app.roleId, "wrong")).status);
    expect(codes.every((s) => s === 401)).toBe(true);
    expect((await login(app.roleId, app.secretId)).status).toBe(429);
  });

  it("does not count successful logins", async () => {
    const adm = await admin();
    const app = await newApp(adm);
    for (let i = 0; i < 12; i++) expect((await login(app.roleId, app.secretId)).status).toBe(200);
  });
});

describe("ADR 15: only admins manage apps", () => {
  it("refuses members on every app route, and changes nothing", async () => {
    const adm = await admin();
    const member = await makeIdentity();
    const app = await newApp(adm);
    const name = uniq("member-try");
    const pair = await generateKeyPair();

    expect(
      (await api("POST", "/apps", member.token, { name, publicKey: pair.publicKey })).status,
    ).toBe(403);
    expect((await api("GET", "/apps", member.token)).status).toBe(403);
    expect((await api("GET", `/apps/${app.id}`, member.token)).status).toBe(403);
    expect((await api("POST", `/apps/${app.id}/rotate`, member.token)).status).toBe(403);
    expect((await api("POST", `/apps/${app.id}/disable`, member.token)).status).toBe(403);

    expect((await login(app.roleId, app.secretId)).status).toBe(200);
    const list = await api("GET", "/apps", adm.token);
    expect(list.body.map((a: { name: string }) => a.name)).not.toContain(name);
  });

  it("refuses requests with no token", async () => {
    expect((await api("GET", "/apps", null)).status).toBe(401);
    expect((await api("POST", "/apps", null, { name: "x" })).status).toBe(401);
  });

  it("refuses an app's own token on app routes", async () => {
    const adm = await admin();
    const app = await newApp(adm);
    const ok = await login(app.roleId, app.secretId);
    expect((await api("GET", "/apps", ok.body.token)).status).toBe(403);
  });
});
