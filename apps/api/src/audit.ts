import { canonical, chainHash, GENESIS } from "@cfs/core";
import { scheduleAlerts } from "./alerts.ts";
import { dayOf, isQuotaError } from "./quota.ts";
import { now } from "./util.ts";

export interface AuditEntry {
  who: string;
  action: string; // e.g. secret.read, secret.write, login.ok, login.denied
  path?: string;
  version?: number;
  result: "ok" | "denied" | "error";
  ip?: string;
  note?: string;
  purpose?: string;
}

export type AuditRow = AuditEntry & { at: number };

/** Where a row sits in the chain: the database, the previous hash and the row's own hash. */
export interface AuditRef {
  db: D1Database;
  prev: string;
  hash: string;
}

/** ADR 18 (alerts). Called after each successful append. Never throws or blocks: evaluation is scheduled in alerts.ts. */
export function onAuditWritten(entry: AuditRow, ref: AuditRef): void {
  scheduleAlerts(entry, ref);
}

// Entries missed while D1 was over quota. Written as one `audit.gap` row when writes resume.
let gap: { from: number; missed: number } | null = null;

const iso = (t: number) => new Date(t * 1000).toISOString();

/** Hash of the last row, or of the last pruned row (ADR 19) when the table is empty. */
async function chainHead(db: D1Database): Promise<string> {
  const last = await db
    .prepare("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1")
    .first<{ hash: string }>();
  if (last) return last.hash;
  const base = await db
    .prepare("SELECT hash FROM audit_base WHERE id = 1")
    .first<{ hash: string }>();
  return base?.hash ?? GENESIS;
}

/** Appends one row at time `at` together with its usage meter update, in one D1 batch. Retries if another writer took the same prev. */
export async function appendRow(
  db: D1Database,
  entry: AuditEntry,
  at: number,
): Promise<{ row: AuditRow; hash: string; prev: string }> {
  const row: AuditRow = { ...entry, at };
  for (let attempt = 0; attempt < 5; attempt++) {
    const prev = await chainHead(db);
    const hash = await chainHash(prev, row);
    try {
      await db.batch([
        db
          .prepare("INSERT INTO audit (at, entry, prev, hash, who) VALUES (?, ?, ?, ?, ?)")
          .bind(at, canonical(row), prev, hash, entry.who),
        db
          .prepare(
            "INSERT INTO usage_day (day, writes, reads_logged) VALUES (?, 1, ?) ON CONFLICT (day) DO UPDATE SET writes = writes + 1, reads_logged = reads_logged + excluded.reads_logged",
          )
          .bind(dayOf(at), entry.action.startsWith("secret.read") ? 1 : 0),
      ]);
      return { row, hash, prev };
    } catch (e) {
      if (!String(e).includes("UNIQUE")) throw e;
    }
  }
  throw new Error("audit chain contention");
}

/**
 * Records one audit row. Fail-open on quota: the request continues, the miss is logged as `cfs_audit_pending`,
 * and the next successful append writes an `audit.gap` row covering the time range. Other errors still throw.
 */
export async function audit(db: D1Database, entry: AuditEntry): Promise<void> {
  const at = now();
  try {
    if (gap) {
      const g = gap;
      const t = now();
      const gapEntry: AuditEntry = {
        who: "system",
        action: "audit.gap",
        result: "ok",
        note: `${g.missed} entries not recorded between ${iso(g.from)} and ${iso(t)}`,
      };
      const g2 = await appendRow(db, gapEntry, t);
      notify(g2.row, { db, prev: g2.prev, hash: g2.hash });
      gap = null;
    }
    const written = await appendRow(db, entry, at);
    notify(written.row, { db, prev: written.prev, hash: written.hash });
  } catch (e) {
    if (!isQuotaError(e)) throw e;
    if (!gap) gap = { from: at, missed: 0 };
    gap.missed++;
    console.log(
      JSON.stringify({
        event: "cfs_audit_pending",
        at,
        action: entry.action,
        result: entry.result,
      }),
    );
  }
}

function notify(row: AuditRow, ref: AuditRef) {
  try {
    onAuditWritten(row, ref);
  } catch {
    // The hook must never break a request.
  }
}
