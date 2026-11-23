import { dayOf } from "./quota.ts";
import { currentHead, pruneAudit, pruneUsage, saveCheckpoint } from "./repository/cron.ts";
import { sweepExpiredRequests } from "./requests-sweep.ts";
import { backupDaily } from "./routes/backup.ts";
import { purgeDeletedLogins } from "./routes/logins.ts";
import { loadLimits } from "./settings.ts";
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

  await saveCheckpoint(db, day, head.seq, head.hash, t);
  if (env.CHECKPOINT_WEBHOOK_URL)
    await sendWebhook(
      env.CHECKPOINT_WEBHOOK_URL,
      `cfs audit checkpoint ${day}: ${head.rows} rows, head ${head.hash}`,
    );

  const pruned = await pruneAudit(db, t, (await loadLimits(env)).auditRetentionDays);
  await backupDaily(env, t);

  await pruneUsage(db, t - LOGIN_WINDOW_KEEP_SEC, dayOf(t - USAGE_KEEP_DAYS * DAY));

  await purgeDeletedLogins(db, t);
  await sweepExpiredRequests(db, t); // ADR 16: lapsed grants and pending requests

  return { day, head: head.hash, pruned };
}
