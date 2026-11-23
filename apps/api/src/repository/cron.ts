import { GENESIS } from "@cfs/core";
import { findAuditBase } from "./audit.ts";

const DAY = 86400;

export async function currentHead(
  db: D1Database,
): Promise<{ seq: number; hash: string; rows: number }> {
  const count = await db.prepare("SELECT COUNT(*) AS n FROM audit").first<{ n: number }>();
  const last = await db
    .prepare("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1")
    .first<{ seq: number; hash: string }>();
  if (last) return { ...last, rows: count?.n ?? 0 };
  const base = await findAuditBase(db);
  return { seq: base?.seq ?? 0, hash: base?.hash ?? GENESIS, rows: 0 };
}

/** Deletes rows older than the cutoff as one prefix, and keeps the last deleted hash as audit_base. Returns rows deleted. */
export async function pruneAudit(db: D1Database, t: number, days: number): Promise<number> {
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

export function saveCheckpoint(db: D1Database, day: string, seq: number, hash: string, t: number) {
  return db
    .prepare("INSERT OR REPLACE INTO checkpoint (day, seq, head, created_at) VALUES (?, ?, ?, ?)")
    .bind(day, seq, hash, t)
    .run();
}

export function pruneUsage(db: D1Database, loginCutoff: number, usageCutoff: string) {
  return db.batch([
    db.prepare("DELETE FROM login_attempt WHERE window < ?").bind(loginCutoff),
    db.prepare("DELETE FROM usage_day WHERE day < ?").bind(usageCutoff),
  ]);
}
