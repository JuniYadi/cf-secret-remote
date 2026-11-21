import { env, SELF } from "cloudflare:test";
import { generateKeyPair, newGroupKey, sealSecret, wrapGroupKey } from "@cfs/core";
import { describe, expect, it } from "vitest";
import { admin, api, makeIdentity } from "./helpers.ts";

// ADR 17: agent rules, the agent-safe read path, and their refusals. Real Workers runtime and D1.
// Every rule has at least one test, including the failures.

const db = env.DB;
let seq = 0;
const uniq = (s: string) =>
  `${s}${Date.now().toString(36)}${++seq}`.toLowerCase().replace(/[^a-z0-9]/g, "");
const nowSec = () => Math.floor(Date.now() / 1000);

type Pair = { publicKey: string; privateKey: string };
interface Adm {
  id: string;
  name: string;
  token: string;
  pair: Pair;
}
interface App {
  id: string;
  name: string;
  token: string;
  pair: Pair;
}

/** An admin with a key pair, so the admin can hold a group key. */
async function newAdmin(): Promise<Adm> {
  const pair = await generateKeyPair();
  return { ...(await admin(pair.publicKey)), pair };
}

/** An app made through the API, then signed in with AppRole, as the CLI does with CFS_KIT. */
async function newApp(adm: Adm, name = uniq("bot")): Promise<App> {
  const pair = await generateKeyPair();
  const made = await api("POST", "/apps", adm.token, { name, publicKey: pair.publicKey });
  expect(made.status).toBe(201);
  const r = await SELF.fetch("http://t.test/api/v1/auth/approle/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ roleId: made.body.roleId, secretId: made.body.secretId }),
  });
  expect(r.status).toBe(200);
  const token = ((await r.json()) as { token: string }).token;
  return { id: made.body.id as string, name, token, pair };
}

/** A group with the admin as its only member, at key version 1. */
async function makeGroup(adm: Adm, prefix: string): Promise<Uint8Array> {
  const gk = await newGroupKey();
  const wrappedKey = await wrapGroupKey(gk, adm.pair.publicKey, prefix, 1);
  const r = await api("POST", "/keyrings", adm.token, {
    prefix,
    members: [{ identityId: adm.id, wrappedKey }],
  });
  expect(r.status).toBe(201);
  return gk;
}

/** Writes a secret as the admin. Returns the ciphertext so tests can check it never reaches the audit log. */
async function putSecret(adm: Adm, gk: Uint8Array, path: string, values: Record<string, string>) {
  const sealed = await sealSecret(gk, path, 1, values);
  const r = await api("PUT", "/secret", adm.token, {
    path,
    names: Object.keys(values),
    keyringVersion: 1,
    version: 1,
    ...sealed,
  });
  expect(r.status).toBe(201);
  return sealed.ciphertext;
}

/** Gives the app read on a path glob through a policy, as an admin would. */
async function grantRead(adm: Adm, app: App, glob: string) {
  const p = await api("POST", "/policies", adm.token, {
    name: uniq("pol"),
    rules: [{ path: glob, caps: ["read"] }],
  });
  expect(p.status).toBe(201);
  const a = await api("POST", `/policies/${p.body.id}/assign`, adm.token, { identityId: app.id });
  expect(a.status).toBeLessThan(300);
}

const addRule = (adm: Adm, app: App, body: Record<string, unknown>) =>
  api("POST", `/apps/${app.id}/rules`, adm.token, body);

/** A valid rule body. Tests override one field at a time. */
const ruleBody = (secretPath: string, over: Record<string, unknown> = {}) => ({
  alias: "github",
  secretPath,
  name: "API_KEY",
  upstream: "https://api.example.com",
  inject: "header:Authorization:Bearer {value}",
  maxReadsPerHour: 10,
  ...over,
});

/** The secret read as the app (GET /secret), with an optional reason header. */
const readAs = (app: App, path: string, reason?: string) =>
  api(
    "GET",
    `/secret?path=${encodeURIComponent(path)}`,
    app.token,
    undefined,
    reason === undefined ? {} : { "X-Cfs-Reason": reason },
  );

async function auditRows(): Promise<Record<string, unknown>[]> {
  const rows = await db.prepare("SELECT entry FROM audit").all<{ entry: string }>();
  return rows.results.map((r) => JSON.parse(r.entry) as Record<string, unknown>);
}

const audited = async (action: string, result: string, path: string) =>
  (await auditRows()).filter((r) => r.action === action && r.result === result && r.path === path);

describe("ADR 17: managing rules", () => {
  it("a member and an app cannot manage rules; only admins can", async () => {
    const adm = await newAdmin();
    const app = await newApp(adm);
    const member = await makeIdentity();
    const path = `${uniq("ar")}/dev`;

    expect((await addRule(adm, app, ruleBody(path))).status).toBe(201);
    for (const token of [member.token, app.token]) {
      expect((await api("GET", `/apps/${app.id}/rules`, token)).status).toBe(403);
      expect(
        (await api("POST", `/apps/${app.id}/rules`, token, ruleBody(path, { alias: "x" }))).status,
      ).toBe(403);
      expect(
        (await api("PUT", `/apps/${app.id}/rules/github`, token, { maxReadsPerHour: 99 })).status,
      ).toBe(403);
      expect((await api("DELETE", `/apps/${app.id}/rules/github`, token)).status).toBe(403);
    }
    // The refused calls changed nothing.
    const still = await api("GET", `/apps/${app.id}/rules`, adm.token);
    expect(still.body[0].maxReadsPerHour).toBe(10);
  });

  it("an app sees only its own rules, and no one else's", async () => {
    const adm = await newAdmin();
    const a = await newApp(adm);
    const b = await newApp(adm);
    const base = uniq("ar");
    expect((await addRule(adm, a, ruleBody(`${base}/dev`, { alias: "alpha" }))).status).toBe(201);
    expect((await addRule(adm, b, ruleBody(`${base}/dev`, { alias: "beta" }))).status).toBe(201);

    const mine = await api("GET", "/agent/rules", a.token);
    expect(mine.status).toBe(200);
    expect(mine.body.map((r: { alias: string }) => r.alias)).toEqual(["alpha"]);
    expect(JSON.stringify(mine.body)).not.toContain("beta");

    // An app cannot list another app's rules through the admin route either.
    expect((await api("GET", `/apps/${b.id}/rules`, a.token)).status).toBe(403);
    // A person with no rules sees an empty list.
    const person = await makeIdentity();
    expect((await api("GET", "/agent/rules", person.token)).body).toEqual([]);
  });

  it("an upstream that is not https is refused, and so is one with credentials or a query", async () => {
    const adm = await newAdmin();
    const app = await newApp(adm);
    const path = `${uniq("ar")}/dev`;
    for (const upstream of [
      "http://api.example.com",
      "ftp://api.example.com",
      "https://user:pw@api.example.com",
      "https://api.example.com/?key=1",
      "not a url",
    ]) {
      const r = await addRule(adm, app, ruleBody(path, { upstream }));
      expect(r.status, upstream).toBe(400);
    }
    const ok = await addRule(adm, app, ruleBody(path, { upstream: "https://api.example.com/v1/" }));
    expect(ok.status).toBe(201);
    expect(ok.body.upstream).toBe("https://api.example.com/v1");
  });

  it("an inject spec must be a header with {value} once, or a query name", async () => {
    const adm = await newAdmin();
    const app = await newApp(adm);
    const path = `${uniq("ar")}/dev`;
    for (const inject of [
      "cookie:sid",
      "header:Authorization",
      "header:Auth:{value}{value}",
      "header:Bad Name:{value}",
      "query:a b",
    ]) {
      expect((await addRule(adm, app, ruleBody(path, { inject }))).status, inject).toBe(400);
    }
    expect(
      (await addRule(adm, app, ruleBody(path, { alias: "q", inject: "query:api_key" }))).status,
    ).toBe(201);
  });

  it("approval defaults to true for */prod paths and false otherwise", async () => {
    const adm = await newAdmin();
    const app = await newApp(adm);
    const base = uniq("ar");
    const prod = await addRule(adm, app, ruleBody(`${base}/prod`, { alias: "p" }));
    const dev = await addRule(adm, app, ruleBody(`${base}/dev`, { alias: "d" }));
    expect(prod.body.requireApproval).toBe(true);
    expect(dev.body.requireApproval).toBe(false);
  });

  it("creates, updates and deletes a rule, each change is audited, and duplicates are refused", async () => {
    const adm = await newAdmin();
    const app = await newApp(adm);
    const path = `${uniq("ar")}/dev`;
    expect((await addRule(adm, app, ruleBody(path))).status).toBe(201);
    expect((await addRule(adm, app, ruleBody(path))).status).toBe(409);

    const upd = await api("PUT", `/apps/${app.id}/rules/github`, adm.token, {
      maxReadsPerHour: 25,
    });
    expect(upd.status).toBe(200);
    expect(upd.body.maxReadsPerHour).toBe(25);
    expect(
      (await api("PUT", `/apps/${app.id}/rules/github`, adm.token, { alias: "other" })).status,
    ).toBe(400);

    expect((await api("DELETE", `/apps/${app.id}/rules/github`, adm.token)).status).toBe(200);
    expect((await api("GET", "/agent/rules", app.token)).body).toEqual([]);
    expect((await api("DELETE", `/apps/${app.id}/rules/github`, adm.token)).status).toBe(404);

    expect((await audited("agent_rule.create", "ok", path)).length).toBe(1);
    expect((await audited("agent_rule.update", "ok", path)).length).toBe(1);
    expect((await audited("agent_rule.delete", "ok", path)).length).toBe(1);
  });

  it("a rule holds no value, and the list response carries none", async () => {
    const adm = await newAdmin();
    const app = await newApp(adm);
    const path = `${uniq("ar")}/dev`;
    await addRule(adm, app, ruleBody(path, { requireReason: true }));
    const r = await api("GET", `/apps/${app.id}/rules`, adm.token);
    expect(Object.keys(r.body[0]).sort()).toEqual(
      [
        "alias",
        "inject",
        "maxReadsPerHour",
        "name",
        "requireApproval",
        "requireReason",
        "secretPath",
        "upstream",
      ].sort(),
    );
  });
});

describe("ADR 17: the read path", () => {
  it("a read past the per-hour budget gets 429 and is audited, and reads under it still work", async () => {
    const adm = await newAdmin();
    const app = await newApp(adm);
    const prefix = uniq("bud");
    const gk = await makeGroup(adm, prefix);
    const path = `${prefix}/dev`;
    await putSecret(adm, gk, path, { API_KEY: "sk-test-1" });
    await grantRead(adm, app, `${prefix}/*`);
    expect((await addRule(adm, app, ruleBody(path, { maxReadsPerHour: 2 }))).status).toBe(201);

    expect((await readAs(app, path)).status).toBe(200);
    expect((await readAs(app, path)).status).toBe(200);
    const over = await readAs(app, path);
    expect(over.status).toBe(429);
    expect(over.body.error).toContain("budget");
    const denied = await audited("secret.read", "denied", path);
    expect(denied.length).toBe(1);
    expect(String(denied[0]?.note)).toContain("budget exceeded");
  });

  it("a read that needs a reason is refused without one, and the reason is audited with it", async () => {
    const adm = await newAdmin();
    const app = await newApp(adm);
    const prefix = uniq("rsn");
    const gk = await makeGroup(adm, prefix);
    const path = `${prefix}/dev`;
    const ciphertext = await putSecret(adm, gk, path, { API_KEY: "sk-test-2" });
    await grantRead(adm, app, `${prefix}/*`);
    await addRule(adm, app, ruleBody(path, { requireReason: true }));

    const none = await readAs(app, path);
    expect(none.status).toBe(403);
    expect(none.body.error).toContain("reason");
    expect((await audited("secret.read", "denied", path)).length).toBe(1);

    const ok = await readAs(app, path, "ticket 4711, rotate key");
    expect(ok.status).toBe(200);
    const granted = await audited("secret.read", "ok", path);
    expect(granted.length).toBe(1);
    expect(String(granted[0]?.note)).toContain("reason: ticket 4711, rotate key");

    // No value and no ciphertext in the audit log, only names, paths and identities.
    const text = JSON.stringify(await auditRows());
    expect(text).not.toContain(ciphertext);
    expect(text).not.toContain("sk-test-2");
  });

  it("a */prod read is refused without an approved request and allowed with one", async () => {
    const adm = await newAdmin();
    const app = await newApp(adm);
    const prefix = uniq("prd");
    const gk = await makeGroup(adm, prefix);
    const prod = `${prefix}/prod`;
    await putSecret(adm, gk, prod, { API_KEY: "sk-prod-1" });
    await grantRead(adm, app, `${prefix}/*`);
    await addRule(adm, app, ruleBody(prod));

    const blocked = await readAs(app, prod);
    expect(blocked.status).toBe(403);
    expect(blocked.body.error).toContain("approved request");
    expect((await audited("secret.read", "denied", prod)).length).toBe(1);

    // The app asks (ADR 16), an admin approves, and the same read now goes through.
    const asked = await api("POST", "/requests", app.token, {
      path: prod,
      reason: "incident 42",
      duration: 3600,
    });
    expect(asked.status).toBe(201);
    const wrappedKey = await wrapGroupKey(gk, app.pair.publicKey, prefix, 1);
    const approved = await api("POST", `/requests/${asked.body.id}/approve`, adm.token, {
      wrappedKey,
      version: 1,
    });
    expect(approved.status).toBe(200);
    const allowed = await readAs(app, prod);
    expect(allowed.status).toBe(200);
    expect(String((await audited("secret.read", "ok", prod))[0]?.note)).toContain(
      "approved request",
    );
  });

  it("an approved request covers only its own path, and stops covering it once it has expired", async () => {
    const adm = await newAdmin();
    const app = await newApp(adm);
    const prefix = uniq("exp");
    const other = uniq("exq");
    const gk = await makeGroup(adm, prefix);
    const gkOther = await makeGroup(adm, other);
    const prodA = `${prefix}/prod`;
    const prodB = `${other}/prod`;
    await putSecret(adm, gk, prodA, { API_KEY: "a" });
    await putSecret(adm, gkOther, prodB, { API_KEY: "b" });
    await grantRead(adm, app, `${prefix}/*`);
    await grantRead(adm, app, `${other}/*`);
    await addRule(adm, app, ruleBody(prodA));
    await addRule(adm, app, ruleBody(prodB, { alias: "billing" }));

    const asked = await api("POST", "/requests", app.token, {
      path: prodA,
      reason: "r",
      duration: 3600,
    });
    const wrappedKey = await wrapGroupKey(gk, app.pair.publicKey, prefix, 1);
    const approved = await api("POST", `/requests/${asked.body.id}/approve`, adm.token, {
      wrappedKey,
      version: 1,
    });
    expect(approved.status).toBe(200);

    expect((await readAs(app, prodA)).status).toBe(200);
    // Approval for one */prod path does not open another one.
    expect((await readAs(app, prodB)).status).toBe(403);

    await db
      .prepare("UPDATE access_request SET expires_at = ? WHERE id = ?")
      .bind(nowSec() - 10, asked.body.id)
      .run();
    expect((await readAs(app, prodA)).status).toBe(403);
  });

  it("a read by an identity with no rule for the path is not affected by agent rules", async () => {
    const adm = await newAdmin();
    const app = await newApp(adm);
    const other = await newApp(adm);
    const prefix = uniq("oth");
    const gk = await makeGroup(adm, prefix);
    const path = `${prefix}/prod`;
    await putSecret(adm, gk, path, { API_KEY: "z" });
    await grantRead(adm, other, `${prefix}/*`);
    await addRule(adm, app, ruleBody(path, { maxReadsPerHour: 1 }));
    // The other app has no rule, so it is not held to the one-read budget or the approval.
    expect((await readAs(other, path)).status).toBe(200);
    expect((await readAs(other, path)).status).toBe(200);
  });
});
