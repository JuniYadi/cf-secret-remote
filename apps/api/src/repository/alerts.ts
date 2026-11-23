export async function usage(db: D1Database, day: string) {
  const row = await db
    .prepare("SELECT writes, reads_logged AS readsLogged FROM usage_day WHERE day = ?")
    .bind(day)
    .first<{ writes: number; readsLogged: number }>();
  return row;
}
export async function configRows(db: D1Database, webhook: string, rules: string) {
  const rows = await db
    .prepare("SELECT key, value FROM setting WHERE key IN (?, ?)")
    .bind(webhook, rules)
    .all<{ key: string; value: string }>();
  return rows.results;
}
export async function deleteSetting(db: D1Database, key: string) {
  await db.prepare("DELETE FROM setting WHERE key = ?").bind(key).run();
}
export async function putSetting(db: D1Database, key: string, value: string) {
  await db
    .prepare("INSERT OR REPLACE INTO setting (key, value) VALUES (?, ?)")
    .bind(key, value)
    .run();
}
export async function adminEmails(db: D1Database): Promise<string[]> {
  const r = await db
    .prepare(
      "SELECT name FROM identity WHERE kind = 'user' AND role = 'admin' AND status = 'active' ORDER BY name",
    )
    .all<{ name: string }>();
  return r.results.map((x) => x.name);
}

export async function claim(
  db: D1Database,
  rule: string,
  subject: string,
  t: number,
): Promise<boolean> {
  const r = await db
    .prepare(
      `INSERT INTO alert_state (rule, subject, last_sent_at) VALUES (?, ?, ?)
       ON CONFLICT (rule, subject) DO UPDATE SET last_sent_at = excluded.last_sent_at
       WHERE alert_state.last_sent_at <= ?`,
    )
    .bind(rule, subject, t, t - 15 * 60)
    .run();
  return r.meta.changes > 0;
}

export async function isApp(db: D1Database, name: string): Promise<boolean> {
  const r = await db
    .prepare("SELECT 1 AS x FROM identity WHERE kind = 'app' AND name = ?")
    .bind(name)
    .first<{ x: number }>();
  return r !== null;
}

export async function chainWindow(db: D1Database) {
  const { results } = await db
    .prepare("SELECT seq, prev, hash, entry FROM audit ORDER BY seq DESC LIMIT 5")
    .all<{ seq: number; prev: string; hash: string; entry: string }>();
  return results;
}
export async function networkCount(
  db: D1Database,
  who: string,
  identityId: string | null,
  at: number,
  hash: string,
  needle: string,
) {
  const seen = await db
    .prepare(
      `SELECT COUNT(*) AS n FROM audit
         WHERE (identity_id = ? OR (identity_id IS NULL AND who = ?)) AND at <= ? AND hash != ? AND instr(entry, ?) > 0
           AND action = 'login.ok'`,
    )
    .bind(identityId, who, at, hash, needle)
    .first<{ n: number }>();
  return seen;
}
export async function readCount(
  db: D1Database,
  who: string,
  identityId: string | null,
  from: number,
  at: number,
) {
  const reads = await db
    .prepare(
      `SELECT COUNT(*) AS n FROM audit
         WHERE (identity_id = ? OR (identity_id IS NULL AND who = ?)) AND at > ? AND at <= ?
           AND action LIKE 'secret.read%'`,
    )
    .bind(identityId, who, from, at)
    .first<{ n: number }>();
  return reads;
}
export async function usageWrites(db: D1Database, day: string) {
  const usage = await db
    .prepare("SELECT writes FROM usage_day WHERE day = ?")
    .bind(day)
    .first<{ writes: number }>();
  return usage;
}
export async function recentAlerts(
  db: D1Database,
  limit = 20,
): Promise<{ rule: string; subject: string; at: number }[]> {
  const rows = await db
    .prepare(
      "SELECT rule, subject, last_sent_at AS at FROM alert_state ORDER BY last_sent_at DESC LIMIT ?",
    )
    .bind(limit)
    .all<{ rule: string; subject: string; at: number }>();
  return rows.results;
}
