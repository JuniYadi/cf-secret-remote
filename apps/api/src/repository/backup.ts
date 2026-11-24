/** Tables in dependency order: parents first. Restore deletes in the reverse order. */
export const BACKUP_TABLES = [
  "identity",
  "app_role",
  "keyring",
  "keyring_member",
  "keyring_member_staged",
  "policy",
  "identity_policy",
  "agent_rule",
  "access_request",
  "secret",
  "secret_version",
  "env_collection",
  "env_collection_env",
  "env_collection_key",
  "login",
  "login_version",
  "setting",
  "alert_state",
  "audit",
  "audit_base",
  "checkpoint",
  "usage_day",
] as const;
export type BackupTable = (typeof BACKUP_TABLES)[number];

/**
 * Tables never exported: sessions and CLI login codes (ADR 23), rate-limit counters, the maintenance flag, and
 * in-flight recovery requests (ADR 20: short-lived, hold cancel-token hashes; restoring a stale one would revive it).
 */
export const EXCLUDED_TABLES = [
  "session",
  "cli_login",
  "login_attempt",
  "maintenance",
  "recovery_request",
] as const;

/**
 * Settings never written to a backup (ADR 23: the alert webhook is masked out). A webhook URL is a credential,
 * so after a restore the admin sets it again.
 */
export const MASKED_SETTINGS = ["alerts.webhook_url"] as const;

/** The columns exported and accepted on restore. A file with any other column is refused. */
export const COLUMNS: Record<BackupTable, readonly string[]> = {
  identity: [
    "id",
    "kind",
    "name",
    "role",
    "public_key",
    "locked_key",
    "status",
    "created_at",
    "owner_id",
    "recovery_locked_key",
    "last_unlocked_at",
  ],
  app_role: [
    "identity_id",
    "role_id",
    "secret_hash",
    "token_ttl",
    "max_uses",
    "uses",
    "cidr",
    "expires_at",
    "first_login_at",
    "last_login_at",
    "last_ip",
  ],
  keyring: ["id", "prefix", "version", "created_at", "status", "personal_owner"],
  keyring_member: ["keyring_id", "identity_id", "version", "wrapped_key", "expires_at"],
  keyring_member_staged: ["keyring_id", "identity_id", "version", "wrapped_key"],
  policy: ["id", "name", "rules"],
  identity_policy: ["identity_id", "policy_id", "expires_at"],
  agent_rule: [
    "identity_id",
    "alias",
    "secret_path",
    "name",
    "upstream",
    "inject",
    "max_reads_per_hour",
    "require_reason",
    "require_approval",
  ],
  secret: ["id", "path", "keyring_id", "current", "created_at", "deleted_at", "meta"],
  secret_version: [
    "secret_id",
    "version",
    "keyring_version",
    "names",
    "wrapped_dek",
    "ciphertext",
    "created_by",
    "created_at",
    "fps",
  ],
  // ADR 36: definitions only. Descriptions are cleartext metadata, like key names.
  env_collection: ["id", "name", "revision", "created_at", "updated_at"],
  env_collection_env: ["collection_id", "label", "path"],
  env_collection_key: ["collection_id", "name", "description"],
  login: ["id", "keyring_id", "current", "created_at", "deleted_at"],
  login_version: [
    "login_id",
    "version",
    "keyring_id",
    "keyring_version",
    "wrapped_dek",
    "ciphertext",
    "fps",
    "created_by",
    "created_at",
  ],
  audit: ["seq", "at", "entry", "prev", "hash", "who", "identity_id", "identity_kind"],
  access_request: [
    "id",
    "requester_id",
    "path_glob",
    "group_prefix",
    "reason",
    "duration",
    "rekey_after",
    "status",
    "approver_id",
    "created_at",
    "decided_at",
    "expires_at",
  ],
  setting: ["key", "value"],
  alert_state: ["rule", "subject", "last_sent_at"],
  audit_base: ["id", "seq", "hash", "pruned_at"],
  checkpoint: ["day", "seq", "head", "created_at"],
  usage_day: ["day", "writes", "reads_logged"],
};

import type { BackupFile, Row, Tables } from "../routes/backup.ts";

const CHUNK = 100;
export async function readTables(db: D1Database): Promise<Tables> {
  const masked = MASKED_SETTINGS.map(() => "?").join(", ");
  const results = await db.batch(
    BACKUP_TABLES.map((t) =>
      t === "setting"
        ? db
            .prepare(
              `SELECT ${COLUMNS[t].join(", ")} FROM setting WHERE key NOT IN (${masked}) ORDER BY rowid`,
            )
            .bind(...MASKED_SETTINGS)
        : db.prepare(`SELECT ${COLUMNS[t].join(", ")} FROM ${t} ORDER BY rowid`),
    ),
  );
  const tables = {} as Tables;
  BACKUP_TABLES.forEach((t, i) => {
    tables[t] = results[i]?.results as Row[];
  });
  return tables;
}

export async function currentCounts(db: D1Database): Promise<Record<BackupTable, number>> {
  const results = await db.batch(
    BACKUP_TABLES.map((t) => db.prepare(`SELECT COUNT(*) AS n FROM ${t}`)),
  );
  return Object.fromEntries(
    BACKUP_TABLES.map((t, i) => [
      t,
      Number((results[i]?.results[0] as { n: number } | undefined)?.n ?? 0),
    ]),
  ) as Record<BackupTable, number>;
}

export async function replaceTables(db: D1Database, f: BackupFile): Promise<void> {
  const deletes = [
    "DELETE FROM session",
    "DELETE FROM cli_login",
    "DELETE FROM login_attempt",
    ...[...BACKUP_TABLES].reverse().map((t) => `DELETE FROM ${t}`),
  ].map((sql) => db.prepare(sql));
  await runChunks(db, deletes);

  const writes: D1PreparedStatement[] = [];
  const owners: D1PreparedStatement[] = [];
  for (const t of BACKUP_TABLES) {
    const cols = COLUMNS[t];
    const sql = `INSERT INTO ${t} (${cols.join(", ")}) VALUES (${cols.map(() => "?").join(", ")})`;
    for (const row of f.tables[t]) {
      // Owners can be inserted before their owner; links are set once every identity exists.
      const vals = cols.map((col) =>
        t === "identity" && col === "owner_id" ? null : (row[col] ?? null),
      );
      writes.push(db.prepare(sql).bind(...vals));
      if (t === "identity" && row.owner_id != null)
        owners.push(
          db.prepare("UPDATE identity SET owner_id = ? WHERE id = ?").bind(row.owner_id, row.id),
        );
    }
  }
  await runChunks(db, [...writes, ...owners]);
}

async function runChunks(db: D1Database, stmts: D1PreparedStatement[]): Promise<void> {
  for (let i = 0; i < stmts.length; i += CHUNK) await db.batch(stmts.slice(i, i + CHUNK));
}

export async function maintenance(db: D1Database) {
  return db.prepare("SELECT since FROM maintenance WHERE id = 1").first();
}
export async function backupHistory(db: D1Database) {
  const rows = await db
    .prepare(
      "SELECT at FROM audit WHERE json_extract(entry, '$.action') = 'backup.export' ORDER BY seq DESC LIMIT 20",
    )
    .all<{ at: number }>();
  return rows.results;
}
export async function latestAudit(db: D1Database) {
  return db.prepare("SELECT seq FROM audit ORDER BY seq DESC LIMIT 1").first<{ seq: number }>();
}
export async function startMaintenance(db: D1Database, at: number, who: string) {
  await db
    .prepare("INSERT OR REPLACE INTO maintenance (id, since, by) VALUES (1, ?, ?)")
    .bind(at, who)
    .run();
}
export async function endMaintenance(db: D1Database) {
  await db.prepare("DELETE FROM maintenance WHERE id = 1").run();
}
