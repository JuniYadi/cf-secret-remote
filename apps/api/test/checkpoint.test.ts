import { createExecutionContext, env, SELF, waitOnExecutionContext } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { adminEmails } from "../src/alerts.ts";
import { appendRow } from "../src/audit.ts";
import { retentionDays, runDaily } from "../src/cron.ts";
import worker from "../src/index.ts";
import { dayOf } from "../src/quota.ts";
import type { Env } from "../src/types.ts";
import { now } from "../src/util.ts";
import { admin, api, makeIdentity } from "./helpers.ts";

const DAY = 86400;
const QUOTA_MSG = "exceeded the daily write quota";
const db = env.DB;
const cfEnv = env as unknown as Env;

type VerifyBody = {
  ok: boolean;
  firstBad: number | null;
  firstBadSeq: number | null;
  base: { seq: number; hash: string } | null;
  checkpoints: { stored: number; verified: number; pruned: number; mismatched: string[] };
};
type UsageBody = { day: string; writes: number; limit: number; warning: boolean };

const lastRow = () =>
  db
    .prepare("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1")
    .first<{ seq: number; hash: string }>();
const seqOfHash = async (hash: string) =>
  (await db.prepare("SELECT seq FROM audit WHERE hash = ?").bind(hash).first<{ seq: number }>())
    ?.seq ?? null;
const verify = (token: string) => api<VerifyBody>("GET", "/audit/verify", token);

/** Creates a policy, which writes one audit row. */
const writeAudit = async (token: string, name: string) =>
  (await api("POST", "/policies", token, { name, rules: [] })).status;

// Triggers stand in for D1's daily quota: a write that hits one fails with a quota message.
const quotaOn = (table: string) =>
  db
    .prepare(
      `CREATE TRIGGER quota_${table} BEFORE INSERT ON ${table} BEGIN SELECT RAISE(ABORT, '${QUOTA_MSG}'); END;`,
    )
    .run();
const quotaOff = (table: string) => db.prepare(`DROP TRIGGER IF EXISTS quota_${table}`).run();

// Storage is shared by the tests in this file, so each one starts with an empty chain.
beforeEach(async () => {
  await db.batch([
    db.prepare("DELETE FROM audit"),
    db.prepare("DELETE FROM audit_base"),
    db.prepare("DELETE FROM checkpoint"),
    db.prepare("DELETE FROM usage_day"),
    db.prepare("DELETE FROM login_attempt"),
  ]);
});

afterEach(async () => {
  vi.restoreAllMocks();
  await quotaOff("identity_policy");
  await quotaOff("audit");
});

describe("ADR 19: checkpoints", () => {
  it("stores the checkpoint with the head of the chain before any pruning", async () => {
    const adm = await admin();
    expect(await writeAudit(adm.token, "cp-one")).toBe(201);
    expect(await writeAudit(adm.token, "cp-two")).toBe(201);
    const head = await lastRow();
    const t = now();

    const r = await runDaily(cfEnv, t);

    const cp = await db
      .prepare("SELECT seq, head FROM checkpoint WHERE day = ?")
      .bind(dayOf(t))
      .first<{ seq: number; head: string }>();
    expect(cp).toEqual({ seq: head!.seq, head: head!.hash });
    expect(r.head).toBe(head!.hash);
    expect(r.pruned).toBe(0);
  });

  it("posts only the day, row count and head hash to the webhook", async () => {
    const adm = await admin();
    await writeAudit(adm.token, "hook-one");
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok"));
    const t = now();

    await runDaily({ ...cfEnv, CHECKPOINT_WEBHOOK_URL: "https://hooks.test/abc" }, t);

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://hooks.test/abc");
    const { text } = JSON.parse(init.body as string) as { text: string };
    const head = await lastRow();
    const count = await db.prepare("SELECT COUNT(*) AS n FROM audit").first<{ n: number }>();
    expect(text).toBe(`cfs audit checkpoint ${dayOf(t)}: ${count!.n} rows, head ${head!.hash}`);
  });

  it("sends nothing when no webhook is configured", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    await runDaily(cfEnv, now());
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("emails the checkpoint to active admins", async () => {
    await admin();
    const recipients = await adminEmails(db);
    const send = vi.fn().mockResolvedValue(undefined);
    const t = now();
    const result = await runDaily(
      {
        ...cfEnv,
        ALERT_EMAIL_FROM: "alerts@example.com",
        SEND_EMAIL: { send } as unknown as Env["SEND_EMAIL"],
      },
      t,
    );
    expect(recipients.length).toBeGreaterThan(0);
    expect(send.mock.calls.map((call) => call[0])).toEqual(
      recipients.map((to) => ({
        to,
        from: "alerts@example.com",
        subject: "cfs audit checkpoint",
        text: `cfs audit checkpoint ${dayOf(t)}: 0 rows, head ${result.head}`,
      })),
    );
  });

  it("continues when an email send fails", async () => {
    await admin();
    const recipients = await adminEmails(db);
    expect(recipients.length).toBeGreaterThan(0);
    const send = vi.fn().mockRejectedValue(new Error("send failed"));
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    const t = now();
    const result = await runDaily(
      {
        ...cfEnv,
        ALERT_EMAIL_FROM: "alerts@example.com",
        SEND_EMAIL: { send } as unknown as Env["SEND_EMAIL"],
      },
      t,
    );
    expect(send).toHaveBeenCalledTimes(recipients.length);
    for (const [index, to] of recipients.entries()) {
      expect(send.mock.calls[index]?.[0]).toEqual({
        to,
        from: "alerts@example.com",
        subject: "cfs audit checkpoint",
        text: `cfs audit checkpoint ${dayOf(t)}: 0 rows, head ${result.head}`,
      });
    }
    expect(error).toHaveBeenCalledWith("checkpoint email failed");
  });
});

describe("ADR 19: retention", () => {
  it("never keeps less than 90 days, whatever the setting says", () => {
    expect(retentionDays({ AUDIT_RETENTION_DAYS: "10" })).toBe(90);
    expect(retentionDays({ AUDIT_RETENTION_DAYS: "abc" })).toBe(365);
    expect(retentionDays({ AUDIT_RETENTION_DAYS: "120" })).toBe(120);
    expect(retentionDays({})).toBe(365);
  });

  it("prunes a 100 day old row under a 10 day setting, and keeps a 60 day old row", async () => {
    const t = now();
    const old = await appendRow(
      db,
      { who: "old", action: "secret.read", result: "ok" },
      t - 100 * DAY,
    );
    const recent = await appendRow(
      db,
      { who: "new", action: "secret.read", result: "ok" },
      t - 60 * DAY,
    );

    await runDaily({ ...cfEnv, AUDIT_RETENTION_DAYS: "10" }, t);

    expect(await seqOfHash(old.hash)).toBeNull();
    expect(await seqOfHash(recent.hash)).not.toBeNull();
  });

  it("keeps a 100 day old row under the default 365 day setting", async () => {
    const t = now();
    const row = await appendRow(
      db,
      { who: "kept", action: "secret.read", result: "ok" },
      t - 100 * DAY,
    );
    await runDaily(cfEnv, t);
    expect(await seqOfHash(row.hash)).not.toBeNull();
  });

  it("prunes after writing a checkpoint, and verification still passes from audit_base", async () => {
    const adm = await admin();
    const t = now();
    await appendRow(
      db,
      { who: "old", action: "secret.read", path: "a/b", result: "ok" },
      t - 400 * DAY,
    );
    const lastOld = await appendRow(
      db,
      { who: "old", action: "secret.read", path: "a/c", result: "ok" },
      t - 399 * DAY,
    );
    await writeAudit(adm.token, "after-old-one");
    await writeAudit(adm.token, "after-old-two");
    const headBefore = await lastRow();

    const r = await runDaily(cfEnv, t);

    expect(r.pruned).toBe(2);
    expect(await seqOfHash(lastOld.hash)).toBeNull();
    const base = await db
      .prepare("SELECT seq, hash FROM audit_base WHERE id = 1")
      .first<{ seq: number; hash: string }>();
    expect(base).toEqual({ seq: expect.any(Number), hash: lastOld.hash });
    const cp = await db
      .prepare("SELECT seq, head FROM checkpoint WHERE day = ?")
      .bind(dayOf(t))
      .first<{ seq: number; head: string }>();
    expect(cp).toEqual({ seq: headBefore!.seq, head: headBefore!.hash });

    const v = await verify(adm.token);
    expect(v.status).toBe(200);
    expect(v.body.ok).toBe(true);
    expect(v.body.base).toEqual(base);
    expect(v.body.checkpoints.mismatched).toEqual([]);

    // New rows keep chaining from audit_base.
    expect(await writeAudit(adm.token, "after-prune")).toBe(201);
    expect((await verify(adm.token)).body.ok).toBe(true);
  });

  it("sweeps old login windows and usage days", async () => {
    await db
      .prepare("INSERT INTO login_attempt (key, window, count) VALUES ('sweep-old', 1, 3)")
      .run();
    await db
      .prepare("INSERT INTO usage_day (day, writes, reads_logged) VALUES ('1999-01-01', 5, 0)")
      .run();
    await runDaily(cfEnv, now());
    expect(
      await db.prepare("SELECT 1 FROM login_attempt WHERE key = 'sweep-old'").first(),
    ).toBeNull();
    expect(await db.prepare("SELECT 1 FROM usage_day WHERE day = '1999-01-01'").first()).toBeNull();
  });
});

describe("ADR 6 and 19: verification", () => {
  it("detects a rewritten row", async () => {
    const adm = await admin();
    await writeAudit(adm.token, "tamper-a");
    await writeAudit(adm.token, "tamper-b");
    expect((await verify(adm.token)).body.ok).toBe(true);

    const target = await db
      .prepare("SELECT seq, entry FROM audit WHERE entry LIKE '%tamper-a%'")
      .first<{ seq: number; entry: string }>();
    await db
      .prepare(
        "UPDATE audit SET entry = replace(entry, 'policy.create', 'policy.delete') WHERE seq = ?",
      )
      .bind(target!.seq)
      .run();
    try {
      const v = await verify(adm.token);
      expect(v.body.ok).toBe(false);
      expect(v.body.firstBadSeq).toBe(target!.seq);
    } finally {
      await db
        .prepare("UPDATE audit SET entry = ? WHERE seq = ?")
        .bind(target!.entry, target!.seq)
        .run();
    }
    expect((await verify(adm.token)).body.ok).toBe(true);
  });

  it("detects removed history through the stored checkpoint", async () => {
    const adm = await admin();
    const t = now();
    await writeAudit(adm.token, "trunc-a");
    await runDaily(cfEnv, t);
    const head = await lastRow();
    // Cut the chain back to before the checkpointed row. What remains is still a valid chain.
    await db.prepare("DELETE FROM audit WHERE seq >= ?").bind(head!.seq).run();

    const v = await verify(adm.token);
    expect(v.body.firstBad).toBeNull();
    expect(v.body.checkpoints.mismatched).toContain(dayOf(t));
    expect(v.body.ok).toBe(false);
  });
});

describe("ADR 19: usage meter", () => {
  it("counts writes for today and shows them to admins only", async () => {
    const adm = await admin();
    const before = (await api<UsageBody>("GET", "/usage", adm.token)).body.writes;
    await writeAudit(adm.token, "meter-one");
    await writeAudit(adm.token, "meter-two");
    const u = await api<UsageBody>("GET", "/usage", adm.token);
    expect(u.body.writes).toBeGreaterThanOrEqual(before + 2);
    expect(u.body.limit).toBe(100000);
    expect(u.body.day).toBe(dayOf(now()));
    const member = await makeIdentity();
    expect((await api("GET", "/usage", member.token)).status).toBe(403);
  });
});

describe("ADR 19: cron trigger", () => {
  it("the scheduled handler stores today's checkpoint", async () => {
    const adm = await admin();
    await writeAudit(adm.token, "cron-one");
    const ctx = createExecutionContext();
    const scheduledTime = now() * 1000;

    await worker.scheduled({ scheduledTime } as ScheduledController, cfEnv, ctx);
    await waitOnExecutionContext(ctx);

    const cp = await db
      .prepare("SELECT day FROM checkpoint WHERE day = ?")
      .bind(dayOf(Math.floor(scheduledTime / 1000)))
      .first();
    expect(cp).not.toBeNull();
  });
});

describe("ADR 19: quota", () => {
  it("answers writes with 503 and Retry-After, while reads keep working", async () => {
    const adm = await admin();
    await quotaOn("identity_policy");

    const w = await SELF.fetch("http://t.test/api/v1/policies/p1/assign", {
      method: "POST",
      headers: { authorization: `Bearer ${adm.token}`, "content-type": "application/json" },
      body: JSON.stringify({ identityId: adm.id }),
    });
    expect(w.status).toBe(503);
    const retry = Number(w.headers.get("Retry-After"));
    expect(retry).toBeGreaterThan(0);
    expect(retry).toBeLessThanOrEqual(86400);

    expect((await api("GET", "/policies", adm.token)).status).toBe(200);
  });

  it("keeps a read working when its audit row cannot be written, then appends audit.gap", async () => {
    const adm = await admin();
    const path = await seedSecret(adm.id);
    const log = vi.spyOn(console, "log");

    await quotaOn("audit");
    const read = await api("GET", `/secret?path=${encodeURIComponent(path)}`, adm.token);
    expect(read.status).toBe(200);
    expect(read.body.ciphertext).toBe("v1.a.b");
    const pending = log.mock.calls
      .map((c) => String(c[0]))
      .filter((s) => s.includes("cfs_audit_pending"));
    expect(pending.length).toBeGreaterThan(0);
    expect(pending.join("")).not.toContain("v1.a.b");

    await quotaOff("audit");
    expect(await writeAudit(adm.token, "gap-resume")).toBe(201);
    const gap = await db
      .prepare('SELECT seq, entry FROM audit WHERE entry LIKE \'%"action":"audit.gap"%\'')
      .first<{ seq: number; entry: string }>();
    expect(gap).not.toBeNull();
    expect(JSON.parse(gap!.entry).note).toMatch(/^1 entries not recorded between .+ and .+$/);
    const resume = await db
      .prepare("SELECT seq FROM audit WHERE entry LIKE '%gap-resume%'")
      .first<{ seq: number }>();
    expect(gap!.seq).toBeLessThan(resume!.seq);
    expect((await verify(adm.token)).body.ok).toBe(true);
  });
});

/** Writes a secret row straight into D1. The ciphertext is opaque to the server, so a dummy envelope is enough. */
async function seedSecret(adminId: string): Promise<string> {
  const id = `s${Math.random().toString(36).slice(2, 10)}`;
  const path = `${id}/prod`;
  await db.batch([
    db
      .prepare("INSERT INTO keyring (id, prefix, version, created_at) VALUES (?, ?, 1, 1)")
      .bind(`kr${id}`, id),
    db
      .prepare(
        "INSERT INTO secret (id, path, keyring_id, current, created_at) VALUES (?, ?, ?, 1, 1)",
      )
      .bind(id, path, `kr${id}`),
    db
      .prepare(
        "INSERT INTO secret_version (secret_id, version, keyring_version, names, wrapped_dek, ciphertext, created_by, created_at) VALUES (?, 1, 1, '[\"KEY\"]', 'w', 'v1.a.b', ?, 1)",
      )
      .bind(id, adminId),
  ]);
  return path;
}
