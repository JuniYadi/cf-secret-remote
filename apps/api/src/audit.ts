import { canonical, chainHash } from "@cfs/core";
import { scheduleAlerts } from "./alerts.ts";
import { dayOf, isQuotaError } from "./quota.ts";
import { chainHead, insertAuditRow } from "./repository/audit.ts";
import { now } from "./util.ts";

export interface AuditEntry {
  who: string;
  actor?: { id: string; kind: "user" | "app" };
  action: string; // e.g. secret.read, secret.write, login.ok, login.denied
  path?: string;
  version?: number;
  result: "ok" | "denied" | "error";
  ip?: string;
  note?: string;
  purpose?: string;
}

export type AuditRow = Omit<AuditEntry, "actor"> & { at: number };

/** Where a row sits in the chain: the database, the previous hash and the row's own hash. */
export interface AuditRef {
  db: D1Database;
  prev: string;
  hash: string;
  actor?: AuditEntry["actor"];
}

/** ADR 18 (alerts). Called after each successful append. Never throws or blocks: evaluation is scheduled in alerts.ts. */
export function onAuditWritten(entry: AuditRow, ref: AuditRef): void {
  scheduleAlerts(entry, ref);
}

// Entries missed while D1 was over quota. Written as one `audit.gap` row when writes resume.
let gap: { from: number; missed: number } | null = null;

const iso = (t: number) => new Date(t * 1000).toISOString();

/** Appends one row at time `at` together with its usage meter update, in one D1 batch. Retries if another writer took the same prev. */
export async function appendRow(
  db: D1Database,
  entry: AuditEntry,
  at: number,
): Promise<{ row: AuditRow; hash: string; prev: string }> {
  const { actor, ...hashedEntry } = entry;
  const row: AuditRow = { ...hashedEntry, at };
  for (let attempt = 0; attempt < 5; attempt++) {
    const prev = await chainHead(db);
    const hash = await chainHash(prev, row);
    try {
      await insertAuditRow(
        db,
        at,
        canonical(row),
        prev,
        hash,
        entry.who,
        actor?.id ?? null,
        actor?.kind ?? null,
        dayOf(at),
        entry.action.startsWith("secret.read") ? 1 : 0,
      );
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
    notify(written.row, { db, prev: written.prev, hash: written.hash, actor: entry.actor });
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
