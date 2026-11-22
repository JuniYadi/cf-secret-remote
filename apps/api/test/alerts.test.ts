import { createExecutionContext, env, SELF, waitOnExecutionContext } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ACCESS_ACTION,
  flushAlerts,
  RECOVERY_ACTION,
  resetAlertSenders,
  setAlertSenders,
} from "../src/alerts.ts";
import { audit } from "../src/audit.ts";
import worker from "../src/index.ts";
import { dayOf, WARN_AT_WRITES } from "../src/quota.ts";
import type { Env } from "../src/types.ts";
import { now } from "../src/util.ts";
import { admin, api, makeIdentity } from "./helpers.ts";

// ADR 18: alerts and notifications. Every rule has a test that it fires on its event and not otherwise.

const db = env.DB;
const cfEnv = env as unknown as Env;
const HOOK = "https://hooks.test/services/T000/B000/SUPERSECRETTOKEN123";
const MAX_SEQ = "SELECT MAX(seq) AS s FROM audit";

let adm: { id: string; name: string; token: string };
let sent: string[]; // webhook message texts
let urls: string[]; // webhook URLs that were posted to
let emails: { to: string[]; subject: string; text: string }[];

const ev = (p: Parameters<typeof audit>[1]) => audit(db, p);
const titled = (title: string) => sent.filter((t) => t.includes(title));
const settle = () => flushAlerts();
const resetDedupe = () => db.prepare("DELETE FROM alert_state").run();

async function configure(body: Record<string, unknown>) {
  const r = await api("PUT", "/alerts", adm.token, body);
  expect(r.status).toBe(200);
  return r.body;
}

const bogusRequest = (ip = "203.0.113.9") =>
  SELF.fetch("http://t.test/api/v1/me", {
    headers: { authorization: "Bearer cfs_not_a_real_token", "CF-Connecting-IP": ip },
  });

beforeEach(async () => {
  await db.batch([
    db.prepare("DELETE FROM audit"),
    db.prepare("DELETE FROM audit_base"),
    db.prepare("DELETE FROM usage_day"),
    db.prepare("DELETE FROM setting"),
    db.prepare("DELETE FROM alert_state"),
  ]);
  sent = [];
  urls = [];
  emails = [];
  setAlertSenders({
    webhook: async (url, text) => {
      urls.push(url);
      sent.push(text);
    },
  });
  adm = await admin();
  await configure({ webhook: HOOK });
});

afterEach(async () => {
  // Nothing from this test may land in the next test's captured messages.
  await flushAlerts();
  resetAlertSenders();
  vi.restoreAllMocks();
});

describe("ADR 18: blocked", () => {
  it("fires on a denied request through the API, with identity and IP", async () => {
    expect((await bogusRequest("203.0.113.9")).status).toBe(401);
    await settle();
    const [msg] = titled("Request blocked");
    expect(msg).toContain("anonymous auth.denied from 203.0.113.9");
  });

  it("fires on a denied audit row, naming the identity and path", async () => {
    await ev({ who: "alice@test.dev", action: "secret.read", path: "pay/dev", result: "denied" });
    await settle();
    expect(titled("Request blocked")).toEqual([
      expect.stringContaining("alice@test.dev secret.read on pay/dev"),
    ]);
  });

  it("does not fire on an allowed request", async () => {
    await ev({ who: "alice@test.dev", action: "secret.read", path: "pay/dev", result: "ok" });
    await settle();
    expect(titled("Request blocked")).toEqual([]);
  });
});

describe("ADR 18: agent_prod_read", () => {
  it("fires when an app reads a */prod path", async () => {
    await makeIdentity({ kind: "app", name: "deploy-bot-1" });
    await ev({
      who: "deploy-bot-1",
      action: "secret.read",
      path: "pay/prod",
      result: "ok",
      ip: "198.51.100.4",
    });
    await settle();
    expect(titled("Agent read production secret")).toEqual([
      expect.stringContaining("agent deploy-bot-1 read pay/prod from 198.51.100.4"),
    ]);
  });

  it("does not fire for a human reading prod", async () => {
    await makeIdentity({ name: "dev@test.dev" });
    await ev({ who: "dev@test.dev", action: "secret.read", path: "pay/prod", result: "ok" });
    await settle();
    expect(titled("Agent read production secret")).toEqual([]);
  });

  it("does not fire for an app reading a non-prod path", async () => {
    await makeIdentity({ kind: "app", name: "deploy-bot-2" });
    await ev({ who: "deploy-bot-2", action: "secret.read", path: "pay/dev", result: "ok" });
    await settle();
    expect(titled("Agent read production secret")).toEqual([]);
  });

  it("does not fire for a refused read (the blocked rule covers that)", async () => {
    await makeIdentity({ kind: "app", name: "deploy-bot-3" });
    await ev({ who: "deploy-bot-3", action: "secret.read", path: "pay/prod", result: "denied" });
    await settle();
    expect(titled("Agent read production secret")).toEqual([]);
    expect(titled("Request blocked")).toHaveLength(1);
  });
});

describe("ADR 18: new_network", () => {
  it("fires on the first login from a /24, and names the network", async () => {
    await ev({ who: "bot-net", action: "login.ok", result: "ok", ip: "203.0.113.10" });
    await settle();
    expect(titled("Sign-in from a new network")).toEqual([
      expect.stringContaining("bot-net signed in from 203.0.113.0/24"),
    ]);
  });

  it("does not fire for another address in the same /24", async () => {
    await ev({ who: "bot-net", action: "login.ok", result: "ok", ip: "203.0.113.10" });
    await settle();
    await resetDedupe();
    await ev({ who: "bot-net", action: "login.ok", result: "ok", ip: "203.0.113.99" });
    await settle();
    expect(titled("Sign-in from a new network")).toHaveLength(1);
  });

  it("fires again for a different /24, and per identity", async () => {
    await ev({ who: "bot-net", action: "login.ok", result: "ok", ip: "203.0.113.10" });
    await settle();
    await resetDedupe();
    await ev({ who: "bot-net", action: "login.ok", result: "ok", ip: "198.51.100.7" });
    await ev({ who: "bot-other", action: "login.ok", result: "ok", ip: "203.0.113.10" });
    await settle();
    expect(titled("Sign-in from a new network")).toHaveLength(3);
  });
});

describe("ADR 18: read_burst", () => {
  it("does not fire at 20 reads in five minutes", async () => {
    for (let i = 0; i < 20; i++)
      await ev({ who: "reader-a", action: "secret.read", path: "pay/dev", result: "ok" });
    await settle();
    expect(titled("Read burst")).toEqual([]);
  });

  it("fires once on the 21st read", async () => {
    for (let i = 0; i < 22; i++)
      await ev({ who: "reader-a", action: "secret.read", path: "pay/dev", result: "ok" });
    await settle();
    expect(titled("Read burst")).toEqual([
      expect.stringContaining("reader-a made 21 secret reads"),
    ]);
  });

  it("counts reads per identity, not together", async () => {
    for (let i = 0; i < 20; i++) {
      await ev({ who: "reader-b", action: "secret.read", path: "pay/dev", result: "ok" });
      await ev({ who: "reader-c", action: "secret.read", path: "pay/dev", result: "ok" });
    }
    await settle();
    expect(titled("Read burst")).toEqual([]);
  });

  it("does not count writes", async () => {
    for (let i = 0; i < 25; i++)
      await ev({ who: "writer-a", action: "secret.write", path: "pay/dev", result: "ok" });
    await settle();
    expect(titled("Read burst")).toEqual([]);
  });
});

describe("ADR 18: quota_80", () => {
  it("fires when today's writes reach 80% of the free tier, not before", async () => {
    await db
      .prepare("INSERT OR REPLACE INTO usage_day (day, writes) VALUES (?, ?)")
      .bind(dayOf(now()), WARN_AT_WRITES - 2)
      .run();
    await ev({ who: "sys-q", action: "secret.write", result: "ok" }); // writes -> WARN-1
    await settle();
    expect(titled("Daily write quota at 80%")).toEqual([]);

    await ev({ who: "sys-q", action: "secret.write", result: "ok" }); // writes -> WARN
    await settle();
    expect(titled("Daily write quota at 80%")).toEqual([
      expect.stringContaining(`about ${WARN_AT_WRITES} of 100000 D1 writes`),
    ]);

    await ev({ who: "sys-q", action: "secret.write", result: "ok" });
    await settle();
    expect(titled("Daily write quota at 80%")).toHaveLength(1);
  });
});

describe("ADR 18: chain_broken", () => {
  it("does not fire while the chain verifies", async () => {
    for (let i = 0; i < 3; i++) await ev({ who: "chain-ok", action: "secret.write", result: "ok" });
    await settle();
    expect(titled("Audit chain check failed")).toEqual([]);
  });

  it("fires when a stored row no longer matches its hash", async () => {
    for (let i = 0; i < 3; i++) await ev({ who: "chain-x", action: "secret.write", result: "ok" });
    await settle();
    const seq = (await db.prepare(MAX_SEQ).first<{ s: number }>())!.s;
    await db
      .prepare(
        `UPDATE audit SET entry = REPLACE(entry, '"result":"ok"', '"result":"denied"') WHERE seq = ?`,
      )
      .bind(seq)
      .run();

    await ev({ who: "chain-x", action: "secret.write", result: "ok" });
    await settle();
    expect(titled("Audit chain check failed")).toEqual([
      expect.stringContaining(`does not verify at seq ${seq};`),
    ]);
  });
});

describe("ADR 18: recovery_requested", () => {
  it("fires on a recovery request, not on other events", async () => {
    await ev({ who: "carol@test.dev", action: "secret.read", path: "pay/dev", result: "ok" });
    await settle();
    expect(titled("Recovery requested")).toEqual([]);

    await ev({ who: "carol@test.dev", action: RECOVERY_ACTION, result: "ok", ip: "203.0.113.2" });
    await settle();
    expect(titled("Recovery requested")).toEqual([
      expect.stringContaining("carol@test.dev requested recovery from 203.0.113.2"),
    ]);
  });
});

describe("ADR 18: access_request", () => {
  it("fires on an access request for a path, not on other events", async () => {
    await ev({ who: "dan@test.dev", action: "secret.read", path: "pay/prod", result: "ok" });
    await settle();
    expect(titled("Access requested")).toEqual([]);

    await ev({ who: "dan@test.dev", action: ACCESS_ACTION, path: "pay/prod", result: "ok" });
    await settle();
    expect(titled("Access requested")).toEqual([
      expect.stringContaining("dan@test.dev requested access on pay/prod"),
    ]);
  });
});

describe("ADR 18: access_request (real route)", () => {
  it("fires when a request is made through POST /requests, so the action names match", async () => {
    await db
      .prepare(
        "INSERT OR IGNORE INTO keyring (id, prefix, created_at) VALUES ('kr-alert', 'alertgrp', 1)",
      )
      .run();
    const who = await makeIdentity();
    const r = await api("POST", "/requests", who.token, {
      path: "alertgrp/prod",
      reason: "deploy",
      duration: 3600,
    });
    expect(r.status).toBe(201);
    await settle();
    expect(titled("Access requested")).toHaveLength(1);
  });
});

describe("ADR 18: dedupe", () => {
  it("sends one message per (rule, subject) inside 15 minutes, and one per subject", async () => {
    await ev({ who: "eve@test.dev", action: "secret.read", result: "denied" });
    await ev({ who: "eve@test.dev", action: "secret.read", result: "denied" });
    await ev({ who: "frank@test.dev", action: "secret.read", result: "denied" });
    await settle();
    expect(titled("Request blocked")).toHaveLength(2);
  });

  it("sends again once the 15 minute window has passed", async () => {
    await ev({ who: "eve@test.dev", action: "secret.read", result: "denied" });
    await settle();
    await ev({ who: "eve@test.dev", action: "secret.read", result: "denied" });
    await settle();
    expect(titled("Request blocked")).toHaveLength(1);

    await db.prepare("UPDATE alert_state SET last_sent_at = last_sent_at - 901").run();
    await ev({ who: "eve@test.dev", action: "secret.read", result: "denied" });
    await settle();
    expect(titled("Request blocked")).toHaveLength(2);
  });
});

describe("ADR 18: toggles", () => {
  it("sends nothing and records no dedupe state for a rule that is off on every channel", async () => {
    const r = await configure({ rules: { blocked: { webhook: false, email: false } } });
    expect(r.rules.blocked).toEqual({ webhook: false, email: false });

    await ev({ who: "toggle@test.dev", action: "secret.read", result: "denied" });
    await settle();
    expect(sent).toEqual([]);
    const state = await db
      .prepare("SELECT COUNT(*) AS n FROM alert_state WHERE rule = 'blocked'")
      .first<{ n: number }>();
    expect(state?.n).toBe(0);
  });

  it("leaves the other rules on", async () => {
    await configure({ rules: { blocked: { webhook: false } } });
    await ev({ who: "toggle@test.dev", action: "secret.read", result: "denied" });
    await ev({ who: "carol@test.dev", action: RECOVERY_ACTION, result: "ok" });
    await settle();
    expect(titled("Request blocked")).toEqual([]);
    expect(titled("Recovery requested")).toHaveLength(1);
  });

  it("every rule is on by default", async () => {
    const r = await api("GET", "/alerts", adm.token);
    expect(Object.keys(r.body.rules).sort()).toEqual(
      [
        "access_request",
        "agent_prod_read",
        "blocked",
        "chain_broken",
        "new_network",
        "quota_80",
        "read_burst",
        "recovery_requested",
      ].sort(),
    );
    for (const v of Object.values<{ webhook: boolean; email: boolean }>(r.body.rules)) {
      expect(v).toEqual({ webhook: true, email: true });
    }
  });

  it("rejects unknown rules, unknown channels and non-boolean values", async () => {
    expect(
      (await api("PUT", "/alerts", adm.token, { rules: { nope: { webhook: true } } })).status,
    ).toBe(400);
    expect(
      (await api("PUT", "/alerts", adm.token, { rules: { blocked: { sms: true } } })).status,
    ).toBe(400);
    expect(
      (await api("PUT", "/alerts", adm.token, { rules: { blocked: { webhook: "yes" } } })).status,
    ).toBe(400);
  });
});

describe("ADR 18: settings and the masked webhook", () => {
  it("never returns the webhook URL unmasked, on read or on write", async () => {
    const put = await configure({ webhook: HOOK });
    const get = await api<any>("GET", "/alerts", adm.token);
    for (const body of [put, get.body]) {
      expect(body.webhook).toMatch(/^https:\/\/hooks\.test\/\*\*\*\*/);
      expect(body.webhook).not.toContain("SUPERSECRETTOKEN");
      expect(JSON.stringify(body)).not.toContain("T000/B000");
      expect(JSON.stringify(body)).not.toContain(HOOK);
    }
  });

  it("still posts to the full URL", async () => {
    await ev({ who: "eve@test.dev", action: "secret.read", result: "denied" });
    await settle();
    expect(urls).toEqual([HOOK]);
  });

  it("refuses non-https or malformed webhook URLs", async () => {
    for (const webhook of [
      "http://hooks.test/x",
      "javascript:alert(1)",
      "not a url",
      `https://h.test/${"a".repeat(2100)}`,
    ]) {
      expect((await api("PUT", "/alerts", adm.token, { webhook })).status).toBe(400);
    }
    const row = await db
      .prepare("SELECT value FROM setting WHERE key = 'alerts.webhook_url'")
      .first<{ value: string }>();
    expect(row?.value).toBe(HOOK);
  });

  it("clears the webhook when set to null", async () => {
    const r = await configure({ webhook: null });
    expect(r.webhook).toBeNull();
    await ev({ who: "eve@test.dev", action: "secret.read", result: "denied" });
    await settle();
    expect(sent).toEqual([]);
  });

  it("records the change in the audit trail without the URL", async () => {
    await configure({ webhook: "https://hooks.test/services/NEW/ROTATED/TOKENXYZ" });
    const rows = await db
      .prepare("SELECT entry FROM audit WHERE json_extract(entry, '$.action') = 'alerts.update'")
      .all<{ entry: string }>();
    expect(rows.results.length).toBeGreaterThan(0);
    const text = rows.results.map((r) => r.entry).join("\n");
    expect(text).toContain("webhook");
    expect(text).not.toContain("TOKENXYZ");
    expect(text).not.toContain("hooks.test");
  });

  it("a member can neither read nor change the settings", async () => {
    const member = await makeIdentity({ name: "member@test.dev" });
    const get = await api("GET", "/alerts", member.token);
    expect(get.status).toBe(403);
    expect(JSON.stringify(get.body)).not.toContain("hooks.test");

    const put = await api("PUT", "/alerts", member.token, {
      webhook: "https://evil.test/hook",
      rules: { blocked: { webhook: false } },
    });
    expect(put.status).toBe(403);

    const row = await db
      .prepare("SELECT value FROM setting WHERE key = 'alerts.webhook_url'")
      .first<{ value: string }>();
    expect(row?.value).toBe(HOOK);
    const rules = await db
      .prepare("SELECT COUNT(*) AS n FROM setting WHERE key = 'alerts.rules'")
      .first<{ n: number }>();
    expect(rules?.n).toBe(0);
  });

  it("the settings routes need a token", async () => {
    expect((await api("GET", "/alerts", null)).status).toBe(401);
  });
});

describe("ADR 18: message content", () => {
  it("never carries tokens, values, notes or the webhook URL", async () => {
    await SELF.fetch("http://t.test/api/v1/me", {
      headers: { authorization: "Bearer cfs_MARKERTOKEN9", "CF-Connecting-IP": "203.0.113.9" },
    });
    await makeIdentity({ kind: "app", name: "bot-content" });
    await ev({
      who: "bot-content",
      action: "secret.read",
      path: "pay/prod",
      result: "ok",
      note: "VALUEMARKER42",
    });
    await settle();

    expect(sent.length).toBeGreaterThan(0);
    const all = sent.join("\n");
    expect(all).toContain("bot-content");
    expect(all).toContain("pay/prod");
    expect(all).not.toContain("MARKERTOKEN9");
    expect(all).not.toContain("cfs_");
    expect(all).not.toContain("VALUEMARKER42");
    expect(all).not.toContain("SUPERSECRETTOKEN");
    expect(all).not.toContain("hooks.test");
  });
});

describe("ADR 18: delivery failures", () => {
  it("a failed send does not break the request, is retried once, and logs the label only", async () => {
    let attempts = 0;
    setAlertSenders({
      webhook: async () => {
        attempts++;
        throw new Error(`failed posting to ${HOOK}`);
      },
    });
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});

    const r = await bogusRequest();
    expect(r.status).toBe(401);
    await settle();

    expect(attempts).toBe(2);
    const logged = errors.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(logged).toContain("alert send failed after retry: webhook blocked");
    expect(logged).not.toContain("SUPERSECRETTOKEN");
    expect(logged).not.toContain("hooks.test");
  });

  it("a send that succeeds on the retry is delivered once", async () => {
    let attempts = 0;
    setAlertSenders({
      webhook: async (_url, text) => {
        attempts++;
        if (attempts === 1) throw new Error("transient");
        sent.push(text);
      },
    });
    await ev({ who: "eve@test.dev", action: "secret.read", result: "denied" });
    await settle();
    expect(attempts).toBe(2);
    expect(titled("Request blocked")).toHaveLength(1);
  });

  it("a write that fires an alert still succeeds when the send fails", async () => {
    setAlertSenders({
      webhook: async () => {
        throw new Error("down");
      },
    });
    vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(
      ev({ who: "eve@test.dev", action: "secret.read", result: "denied" }),
    ).resolves.toBeUndefined();
    await settle();
    const n = await db
      .prepare("SELECT COUNT(*) AS n FROM audit WHERE who = 'eve@test.dev'")
      .first<{ n: number }>();
    expect(n?.n).toBe(1);
    expect(titled("Request blocked")).toEqual([]);
  });

  it("evaluation is handed to the request's waitUntil", async () => {
    const ctx = createExecutionContext();
    const spy = vi.spyOn(ctx, "waitUntil");
    const res = await worker.fetch(
      new Request("http://t.test/api/v1/me", { headers: { authorization: "Bearer cfs_nope" } }),
      cfEnv,
      ctx,
    );
    expect(res.status).toBe(401);
    await waitOnExecutionContext(ctx);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(titled("Request blocked")).toHaveLength(1);
  });
});

describe("ADR 18: email (optional)", () => {
  it("is not attempted without a send_email binding", async () => {
    const r = await api<any>("GET", "/alerts", adm.token);
    expect(r.body.email.available).toBe(false);
    await ev({ who: "eve@test.dev", action: "secret.read", result: "denied" });
    await settle();
    expect(emails).toEqual([]);
    expect(titled("Request blocked")).toHaveLength(1);
  });

  it("goes to the active admin addresses only, with the same text as the webhook", async () => {
    const member = await makeIdentity({ name: "member-mail@test.dev" });
    setAlertSenders({
      webhook: async (_u, text) => {
        sent.push(text);
      },
      email: async (to, subject, text) => {
        emails.push({ to, subject, text });
      },
    });
    await ev({ who: "eve@test.dev", action: "secret.read", result: "denied" });
    await settle();
    expect(emails).toHaveLength(1);
    expect(emails[0]!.to).toContain(adm.name);
    expect(emails[0]!.to).not.toContain(member.name);
    expect(emails[0]!.subject).toBe("cfs alert: Request blocked");
    expect(emails[0]!.text).toBe(sent[0]);
  });

  it("is off for a rule whose email toggle is off, while the webhook still sends", async () => {
    setAlertSenders({
      webhook: async (_u, text) => {
        sent.push(text);
      },
      email: async (to, subject, text) => {
        emails.push({ to, subject, text });
      },
    });
    await configure({ rules: { blocked: { email: false } } });
    await ev({ who: "eve@test.dev", action: "secret.read", result: "denied" });
    await settle();
    expect(emails).toEqual([]);
    expect(sent).toHaveLength(1);
  });

  it("reports availability only when the binding and sender address are both set", async () => {
    const bound = {
      ...cfEnv,
      SEND_EMAIL: { send: async () => {} },
      ALERT_EMAIL_FROM: "alerts@test.dev",
    };
    const res = await worker.fetch(
      new Request("http://t.test/api/v1/alerts", {
        headers: { authorization: `Bearer ${adm.token}` },
      }),
      bound as unknown as Env,
      createExecutionContext(),
    );
    expect(((await res.json()) as any).email.available).toBe(true);
  });
});

describe("ADR 24: send test and recent alerts", () => {
  it("sends one test message to the webhook, reports the outcome, and logs it without the URL", async () => {
    const r = await api<{ webhook: string; email: string }>("POST", "/alerts/test", adm.token);
    expect(r.status).toBe(200);
    expect(r.body).toEqual({ webhook: "sent", email: "off" });
    expect(sent).toHaveLength(1);
    expect(sent[0]).toContain("Test alert");
    expect(urls).toEqual([HOOK]);
    const rows = await api<{ action: string; note?: string }[]>(
      "GET",
      "/audit?action=alerts.test",
      adm.token,
    );
    expect(rows.body[0]?.note).toBe("webhook sent, email off");
    expect(JSON.stringify(rows.body)).not.toContain("SUPERSECRETTOKEN123");
  });

  it("says failed when the webhook errors, and does not echo the error", async () => {
    setAlertSenders({
      webhook: async () => {
        throw new Error(`boom ${HOOK}`);
      },
    });
    const r = await api("POST", "/alerts/test", adm.token);
    expect(r.status).toBe(200);
    expect(r.body).toEqual({ webhook: "failed", email: "off" });
    expect(JSON.stringify(r.body)).not.toContain("SUPERSECRETTOKEN123");
  });

  it("says off for both channels when nothing is set up, and refuses a member", async () => {
    await configure({ webhook: null });
    expect((await api("POST", "/alerts/test", adm.token)).body).toEqual({
      webhook: "off",
      email: "off",
    });
    const m = await makeIdentity({ role: "member" });
    expect((await api("POST", "/alerts/test", m.token)).status).toBe(403);
    expect((await api("GET", "/alerts/recent", m.token)).status).toBe(403);
  });

  it("lists recent alerts newest first", async () => {
    await ev({ who: "alice@test.dev", action: "secret.read", path: "pay/dev", result: "denied" });
    await settle();
    const r = await api<{ rule: string; subject: string; at: number }[]>(
      "GET",
      "/alerts/recent",
      adm.token,
    );
    expect(r.status).toBe(200);
    expect(r.body[0]?.rule).toBe("blocked");
    expect(typeof r.body[0]?.at).toBe("number");
  });
});
