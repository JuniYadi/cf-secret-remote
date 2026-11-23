import { GENESIS } from "@cfs/core";

/** Hash of the last row, or of the last pruned row when the table is empty. */
export async function chainHead(db: D1Database): Promise<string> {
  const last = await db
    .prepare("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1")
    .first<{ hash: string }>();
  if (last) return last.hash;
  const base = await db
    .prepare("SELECT hash FROM audit_base WHERE id = 1")
    .first<{ hash: string }>();
  return base?.hash ?? GENESIS;
}

export async function insertAuditRow(
  db: D1Database,
  at: number,
  entry: string,
  prev: string,
  hash: string,
  who: string,
  identityId: string | null,
  identityKind: string | null,
  day: string,
  readsLogged: number,
): Promise<void> {
  await db.batch([
    db
      .prepare(
        "INSERT INTO audit (at, entry, prev, hash, who, identity_id, identity_kind) VALUES (?, ?, ?, ?, ?, ?, ?)",
      )
      .bind(at, entry, prev, hash, who, identityId, identityKind),
    db
      .prepare(
        "INSERT INTO usage_day (day, writes, reads_logged) VALUES (?, 1, ?) ON CONFLICT (day) DO UPDATE SET writes = writes + 1, reads_logged = reads_logged + excluded.reads_logged",
      )
      .bind(day, readsLogged),
  ]);
}

export function findAuditBase(db: D1Database) {
  return db
    .prepare("SELECT seq, hash FROM audit_base WHERE id = 1")
    .first<{ seq: number; hash: string }>();
}
