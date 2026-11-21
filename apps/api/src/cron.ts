import { GENESIS } from "@cfs/core";
import { dayOf } from "./quota.ts";
import { sweepExpiredRequests } from "./requests-sweep.ts";
import { backupDaily } from "./routes/backup.ts";
import type { Env } from "./types.ts";

const DAY = 86400;
export const MIN_RETENTION_DAYS = 90;
export const DEFAULT_RETENTION_DAYS = 365;
const USAGE_KEEP_DAYS = 30;
const LOGIN_WINDOW_KEEP_SEC = DAY;

/** Retention in days. The setting can raise it, never lower it below 90 (offboarding needs that history). */
export function retentionDays(env: Pick<Env, "AUDIT_RETENTION_DAYS">): number {
  const n = Math.floor(Number(env.AUDIT_RETENTION_DAYS));
  return Math.max(MIN_RETENTION_DAYS, Number.isFinite(n) && n > 0 ? n : DEFAULT_RETENTION_DAYS);
}

/** Posts a plain message to a Slack-compatible incoming webhook. Failures are logged without the URL. */
export async function sendWebhook(url: string, text: string): Promise<void> {
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text }),
    });
    if (!r.ok) console.error(`checkpoint webhook returned ${r.status}`);
  } catch {
    console.error("checkpoint webhook failed");
  }
}

async function currentHead(db: D1Database): Promise<{ seq: number; hash: string; rows: number }> {
  const count = await db.prepare("SELECT COUNT(*) AS n FROM audit").first<{ n: number }>();
  const last = await db
    .prepare("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1")
    .first<{ seq: number; hash: string }>();
  if (last) return { ...last, rows: count?.n ?? 0 };
  const base = await db
    .prepare("SELECT seq, hash FROM audit_base WHERE id = 1")
    .first<{ seq: number; hash: string }>();
  return { seq: base?.seq ?? 0, hash: base?.hash ?? GENESIS, rows: 0 };
}

/** Deletes rows older than the cutoff as one prefix, and keeps the last deleted hash as audit_base. Returns rows deleted. */
async function pruneAudit(db: D1Database, t: number, days: number): Promise<number> {
  const cutoff = t - days * DAY;
  const last = await db
    .prepare("SELECT seq, hash FROM audit WHERE at < ? ORDER BY seq DESC LIMIT 1")
    .bind(cutoff)
    .first<{ seq: number; hash: string }>();
  if (!last) return 0;
  const n = await db
    .prepare("SELECT COUNT(*) AS n FROM audit WHERE seq <= ?")
    .bind(last.seq)
    .first<{ n: number }>();
  await db.batch([
    db
      .prepare("INSERT OR REPLACE INTO audit_base (id, seq, hash, pruned_at) VALUES (1, ?, ?, ?)")
      .bind(last.seq, last.hash, t),
    db.prepare("DELETE FROM audit WHERE seq <= ?").bind(last.seq),
  ]);
  return n?.n ?? 0;
}

/**
 * The 00:05 UTC cron (ADR 19). Order matters: the checkpoint is stored and sent before any row is pruned,
 * so the head that pruning removes from the chain is still recorded.
 * `t` is unix seconds.
 */
export async function runDaily(
  env: Env,
  t: number,
): Promise<{ day: string; head: string; pruned: number }> {
  const db = env.DB;
  const day = dayOf(t);
  const head = await currentHead(db);

  await db
    .prepare("INSERT OR REPLACE INTO checkpoint (day, seq, head, created_at) VALUES (?, ?, ?, ?)")
    .bind(day, head.seq, head.hash, t)
    .run();
  if (env.CHECKPOINT_WEBHOOK_URL)
    await sendWebhook(
      env.CHECKPOINT_WEBHOOK_URL,
      `cfs audit checkpoint ${day}: ${head.rows} rows, head ${head.hash}`,
    );

  const pruned = await pruneAudit(db, t, retentionDays(env));
  await backupDaily(env, t);

  await db.batch([
    db.prepare("DELETE FROM login_attempt WHERE window < ?").bind(t - LOGIN_WINDOW_KEEP_SEC),
    db.prepare("DELETE FROM usage_day WHERE day < ?").bind(dayOf(t - USAGE_KEEP_DAYS * DAY)),
  ]);

  await sweepExpiredRequests(db, t); // ADR 16: lapsed grants and pending requests

  return { day, head: head.hash, pruned };
}
