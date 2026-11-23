import { findAuditBase } from "./audit.ts";

export async function policies(db: D1Database) {
  const policies = await db
    .prepare("SELECT id, name, rules FROM policy ORDER BY name")
    .all<{ id: string; name: string; rules: string }>();
  const holders = await db
    .prepare(
      `SELECT ip.policy_id AS policyId, i.id AS identityId, i.name, i.kind, ip.expires_at AS expiresAt
       FROM identity_policy ip JOIN identity i ON i.id = ip.identity_id ORDER BY i.name`,
    )
    .all<{
      policyId: string;
      identityId: string;
      name: string;
      kind: string;
      expiresAt: number | null;
    }>();
  return { policies: policies.results, holders: holders.results };
}
export async function createPolicy(db: D1Database, id: string, name: string, rules: string) {
  await db
    .prepare("INSERT INTO policy (id, name, rules) VALUES (?, ?, ?)")
    .bind(id, name, rules)
    .run();
}
export async function assignPolicy(
  db: D1Database,
  identity: string,
  policy: string,
  expires: number | null,
) {
  await db
    .prepare(
      "INSERT OR REPLACE INTO identity_policy (identity_id, policy_id, expires_at) VALUES (?, ?, ?)",
    )
    .bind(identity, policy, expires)
    .run();
}
type AuditDbRow = { seq: number; entry: string; hash: string };

export async function auditRows(
  db: D1Database,
  f: { where: string[]; binds: (string | number)[] },
  limit: number,
) {
  const sql = `SELECT seq, entry, hash FROM audit${f.where.length ? ` WHERE ${f.where.join(" AND ")}` : ""} ORDER BY seq DESC LIMIT ?`;
  const rows = await db
    .prepare(sql)
    .bind(...f.binds, limit)
    .all<AuditDbRow>();
  return rows.results.map(
    (r) =>
      ({ seq: r.seq, hash: r.hash, ...JSON.parse(r.entry) }) as {
        seq: number;
        hash: string;
        who: string;
        at: number;
        action: string;
        path?: string;
        version?: number;
        result: string;
        ip?: string;
        note?: string;
      },
  );
}

/** Whether each name is a person or an app, by identity name. A name that is both reads as user; an unknown name is null. */
export async function kindsOf(
  db: D1Database,
  names: string[],
): Promise<Map<string, "user" | "app">> {
  const kinds = new Map<string, "user" | "app">();
  const unique = [...new Set(names)];
  // D1 allows 100 bound parameters per statement.
  for (let i = 0; i < unique.length; i += 90) {
    const chunk = unique.slice(i, i + 90);
    const found = await db
      .prepare(`SELECT name, kind FROM identity WHERE name IN (${chunk.map(() => "?").join(",")})`)
      .bind(...chunk)
      .all<{ name: string; kind: "user" | "app" }>();
    for (const r of found.results) if (kinds.get(r.name) !== "user") kinds.set(r.name, r.kind);
  }
  return kinds;
}

export async function auditStats(db: D1Database, since: number) {
  const one = async (sql: string, ...binds: (string | number)[]) =>
    (
      await db
        .prepare(sql)
        .bind(...binds)
        .first<{ n: number }>()
    )?.n ?? 0;
  const reads = "at >= ? AND action = 'secret.read' AND json_extract(entry, '$.result') = 'ok'";
  const [accesses, byApps, blocked, actors] = await Promise.all([
    one(`SELECT count(*) AS n FROM audit WHERE ${reads}`, since),
    one(
      `SELECT count(*) AS n FROM audit WHERE ${reads} AND (identity_kind = 'app' OR (identity_id IS NULL AND who IN (SELECT name FROM identity WHERE kind = 'app')))`,
      since,
    ),
    one(
      "SELECT count(*) AS n FROM audit WHERE at >= ? AND json_extract(entry, '$.result') = 'denied'",
      since,
    ),
    one(
      "SELECT count(DISTINCT COALESCE(identity_id, 'name:' || who)) AS n FROM audit WHERE at >= ? AND who != 'system'",
      since,
    ),
  ]);
  return { accesses, byApps, blocked, actors };
}
export async function chainRows(db: D1Database) {
  const base = await findAuditBase(db);
  const rows = await db
    .prepare("SELECT seq, entry, hash FROM audit ORDER BY seq")
    .all<{ seq: number; entry: string; hash: string }>();
  return { base, rows: rows.results };
}
export async function checkpoints(db: D1Database) {
  const cps = await db
    .prepare("SELECT day, seq, head FROM checkpoint ORDER BY day")
    .all<{ day: string; seq: number; head: string }>();
  return cps.results;
}
