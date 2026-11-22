import {
  canonical,
  chainHash,
  GENESIS,
  isSealedBackup,
  MIN_BACKUP_PASSPHRASE,
  openBackup,
  sealBackup,
} from "@cfs/core";
import { type Context, Hono, type MiddlewareHandler } from "hono";
import { audit } from "../audit.ts";
import { requireAdmin } from "../auth.ts";
import { dayOf } from "../quota.ts";
import type { AppEnv, Env } from "../types.ts";
import { now, sha256Hex } from "../util.ts";

// ADR 23: backup and restore. The file is gzip JSON: { schema, createdAt, tables, sha256 }.
// sha256 is the hex SHA-256 of canonical({ schema, createdAt, tables }).
// A passphrase, when given, seals the gzip bytes (packages/core/src/backup-seal.ts).
// Values stay encrypted. Names, paths, emails and dates are in clear.

/** The number of the latest migration. A file must match it to restore. */
export const SCHEMA_VERSION = 15;

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
  keyring: ["id", "prefix", "version", "created_at", "status"],
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
  audit: ["seq", "at", "entry", "prev", "hash", "who"],
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

/** Statements per D1 batch during restore. Each batch is one transaction. */
const CHUNK = 100;
/** Daily R2 copies kept (ADR 23). */
export const R2_KEEP = 30;
const R2_PREFIX = "backups/";

type Value = string | number | null;
export type Row = Record<string, Value>;
export type Tables = Record<BackupTable, Row[]>;

export interface BackupFile {
  schema: number;
  createdAt: number;
  tables: Tables;
  sha256: string;
}

export class BackupError extends Error {
  constructor(
    readonly status: 400 | 409 | 422,
    message: string,
  ) {
    super(message);
  }
}

export const backup = new Hono<AppEnv>();
backup.use("/backup", requireAdmin);
backup.use("/backup/history", requireAdmin);
backup.use("/restore", requireAdmin);
backup.use("/restore/*", requireAdmin);

const RESTORE_PATHS = ["/api/v1/restore", "/api/v1/restore/check"];

/**
 * ADR 23 maintenance mode. While a restore runs, every write returns 503. Reads and the restore routes stay open.
 * Registered for every /api request in src/index.ts, so logins and sign-ups are blocked too.
 */
export const blockDuringMaintenance: MiddlewareHandler<AppEnv> = async (c, next) => {
  const m = c.req.method;
  if (m === "GET" || m === "HEAD" || m === "OPTIONS" || RESTORE_PATHS.includes(c.req.path))
    return next();
  const row = await c.env.DB.prepare("SELECT since FROM maintenance WHERE id = 1").first();
  if (row) {
    c.header("Retry-After", "60");
    return c.json({ error: "maintenance: a restore is running, try again shortly" }, 503);
  }
  return next();
};

/** Reads every backed-up table in one batch (one D1 transaction, so one consistent snapshot). */
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

/** SHA-256 over the canonical body. Used on export and to check a file on import. */
export const digest = (schema: number, createdAt: number, tables: Tables) =>
  sha256Hex(canonical({ schema, createdAt, tables }));

export async function buildFile(db: D1Database, t: number): Promise<BackupFile> {
  const tables = await readTables(db);
  return {
    schema: SCHEMA_VERSION,
    createdAt: t,
    tables,
    sha256: await digest(SCHEMA_VERSION, t, tables),
  };
}

const bytesOf = (s: string) => new TextEncoder().encode(s);
const textOf = (b: Uint8Array) => new TextDecoder().decode(b);

async function gzip(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(
    await new Response(
      new Blob([bytes as BlobPart]).stream().pipeThrough(new CompressionStream("gzip")),
    ).arrayBuffer(),
  );
}

async function gunzip(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(
    await new Response(
      new Blob([bytes as BlobPart]).stream().pipeThrough(new DecompressionStream("gzip")),
    ).arrayBuffer(),
  );
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/** Checks the file's shape, every table and every column name, before any value is used. */
function checkShape(v: unknown): BackupFile {
  const bad = () => new BackupError(400, "not a cfs backup file");
  if (!isObj(v) || !isObj(v.tables)) throw bad();
  const { schema, createdAt, sha256, tables } = v;
  if (!Number.isInteger(schema) || !Number.isInteger(createdAt) || typeof sha256 !== "string")
    throw bad();
  for (const k of Object.keys(tables))
    if (!(BACKUP_TABLES as readonly string[]).includes(k))
      throw new BackupError(400, `unknown table in file: ${k}`);
  for (const t of BACKUP_TABLES) {
    const rows = tables[t];
    if (!Array.isArray(rows)) throw new BackupError(400, `file has no ${t} table`);
    for (const r of rows) {
      if (!isObj(r)) throw bad();
      for (const [col, val] of Object.entries(r)) {
        if (!COLUMNS[t].includes(col)) throw new BackupError(400, `unknown column ${t}.${col}`);
        const scalar =
          val === null ||
          typeof val === "string" ||
          (typeof val === "number" && Number.isFinite(val));
        if (!scalar) throw new BackupError(400, `bad value in ${t}.${col}`);
      }
    }
  }
  return v as unknown as BackupFile;
}

/** Opens (if sealed), decompresses and shape-checks a file. Nothing is written. */
export async function readFile(bytes: Uint8Array, passphrase?: string): Promise<BackupFile> {
  let data = bytes;
  if (isSealedBackup(data)) {
    if (!passphrase)
      throw new BackupError(400, "this file is sealed: send the passphrase in X-Backup-Passphrase");
    try {
      data = await openBackup(data, passphrase);
    } catch {
      throw new BackupError(400, "wrong passphrase or damaged file");
    }
  }
  let json: unknown;
  try {
    json = JSON.parse(textOf(await gunzip(data)));
  } catch {
    throw new BackupError(400, "not a cfs backup file");
  }
  return checkShape(json);
}

/** Hash, then schema. Both come before the audit check, as ADR 23 orders them. */
export async function verifyFile(f: BackupFile): Promise<void> {
  if ((await digest(f.schema, f.createdAt, f.tables)) !== f.sha256)
    throw new BackupError(422, "hash mismatch: the file was changed or damaged");
  if (f.schema !== SCHEMA_VERSION)
    throw new BackupError(
      409,
      `file is schema ${f.schema}; this instance runs schema ${SCHEMA_VERSION}`,
    );
}

export interface AuditCheck {
  ok: boolean;
  rows: number;
  firstBadSeq: number | null;
  lastAuditAt: number | null;
  checkpoints: { stored: number; verified: number; pruned: number; mismatched: string[] };
}

/**
 * Re-checks the audit chain inside the file, from its audit_base (or genesis), and each checkpoint.
 * Same rules as GET /audit/verify (ADR 6, ADR 19), applied to the file instead of the live table.
 */
export async function checkAuditFile(tables: Tables): Promise<AuditCheck> {
  const base = tables.audit_base.find((r) => r.id === 1) as
    | { seq: number; hash: string }
    | undefined;
  const start = base?.hash ?? GENESIS;
  const rows = [...tables.audit].sort((a, b) => (a.seq as number) - (b.seq as number));
  let prev = start;
  let firstBadSeq: number | null = null;
  for (const r of rows) {
    let entry: unknown;
    try {
      entry = JSON.parse(String(r.entry));
    } catch {
      firstBadSeq = r.seq as number;
      break;
    }
    if (r.prev !== prev || (await chainHash(prev, entry)) !== r.hash) {
      firstBadSeq = r.seq as number;
      break;
    }
    prev = String(r.hash);
  }

  const bySeq = new Map(rows.map((r) => [r.seq as number, String(r.hash)]));
  const cps = {
    stored: tables.checkpoint.length,
    verified: 0,
    pruned: 0,
    mismatched: [] as string[],
  };
  for (const cp of tables.checkpoint) {
    const seq = cp.seq as number;
    const head = String(cp.head);
    const day = String(cp.day);
    if (seq === 0) {
      if (head === GENESIS && !base) cps.verified++;
      else if (head === GENESIS) cps.pruned++;
      else cps.mismatched.push(day);
    } else if (base && seq === base.seq) {
      if (head === base.hash) cps.verified++;
      else cps.mismatched.push(day);
    } else if (base && seq < base.seq) {
      cps.pruned++;
    } else if (bySeq.get(seq) === head) cps.verified++;
    else cps.mismatched.push(day);
  }

  const at = rows.reduce<number | null>((m, r) => {
    const t = r.at as number;
    return m === null || t > m ? t : m;
  }, null);
  return {
    ok: firstBadSeq === null && cps.mismatched.length === 0,
    rows: rows.length,
    firstBadSeq,
    lastAuditAt: at,
    checkpoints: cps,
  };
}

const counts = (tables: Tables) =>
  Object.fromEntries(BACKUP_TABLES.map((t) => [t, tables[t].length])) as Record<
    BackupTable,
    number
  >;

async function currentCounts(db: D1Database): Promise<Record<BackupTable, number>> {
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

const requestHost = (c: { req: { url: string } }) => new URL(c.req.url).host;

/** Reads, verifies and chain-checks a file. Used by both /restore/check and /restore. Writes nothing. */
async function inspect(
  bytes: Uint8Array,
  passphrase?: string,
): Promise<{ file: BackupFile; chain: AuditCheck }> {
  const file = await readFile(bytes, passphrase);
  await verifyFile(file);
  const chain = await checkAuditFile(file.tables);
  if (!chain.ok)
    throw new BackupError(
      422,
      chain.firstBadSeq !== null
        ? `audit chain broken in the file at seq ${chain.firstBadSeq}`
        : "a checkpoint in the file does not match its audit chain",
    );
  return { file, chain };
}

/** Body: JSON { file: base64 backup, confirmHost? }. Decodes the file bytes. */
function parseRestoreBody(raw: unknown): { bytes: Uint8Array; confirmHost?: string } {
  if (!isObj(raw) || typeof raw.file !== "string")
    throw new BackupError(400, "send JSON with the backup as base64 in `file`");
  let bytes: Uint8Array;
  try {
    bytes = Uint8Array.from(atob(raw.file), (ch) => ch.charCodeAt(0));
  } catch {
    throw new BackupError(400, "`file` is not valid base64");
  }
  return {
    bytes,
    confirmHost: typeof raw.confirmHost === "string" ? raw.confirmHost : undefined,
  };
}

/** The passphrase travels only in this header (never in the URL, a log or the audit). */
const passphraseOf = (c: { req: { header: (n: string) => string | undefined } }) =>
  c.req.header("X-Backup-Passphrase") || undefined;

export interface BackupCopy {
  at: number;
  type: "auto" | "manual";
  /** Bytes. Known for R2 copies only. */
  size: number | null;
}

/** The R2 copies the daily job keeps, newest first. Empty when nothing is stored. */
export async function listAutoBackups(bucket: R2Bucket): Promise<BackupCopy[]> {
  const out: BackupCopy[] = [];
  let cursor: string | undefined;
  do {
    const page = await bucket.list({ prefix: R2_PREFIX, cursor });
    for (const o of page.objects)
      out.push({ at: Math.floor(o.uploaded.getTime() / 1000), type: "auto", size: o.size });
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  return out.sort((a, b) => b.at - a.at);
}

// ADR 24 (Settings, Backup): what the Backup tab lists. Manual downloads come from the audit log (which records
// the time only, not the size); automatic copies come from R2 when it is connected.
backup.get("/backup/history", async (c) => {
  const manual = await c.env.DB.prepare(
    "SELECT at FROM audit WHERE json_extract(entry, '$.action') = 'backup.export' ORDER BY seq DESC LIMIT 20",
  ).all<{ at: number }>();
  const auto = c.env.BACKUP ? await listAutoBackups(c.env.BACKUP) : [];
  const copies: BackupCopy[] = [
    ...auto,
    ...manual.results.map((r) => ({ at: r.at, type: "manual" as const, size: null })),
  ].sort((a, b) => b.at - a.at);
  return c.json({ r2: Boolean(c.env.BACKUP), copies: copies.slice(0, 30) });
});

// Export. The passphrase goes in a header, never the URL.
backup.get("/backup", async (c) => {
  if (c.req.query("passphrase") !== undefined)
    return c.json(
      { error: "send the passphrase in the X-Backup-Passphrase header, not the URL" },
      400,
    );
  const pass = passphraseOf(c);
  if (pass !== undefined && pass.length < MIN_BACKUP_PASSPHRASE)
    return c.json(
      { error: `passphrase must be at least ${MIN_BACKUP_PASSPHRASE} characters` },
      400,
    );

  const t = now();
  const f = await buildFile(c.env.DB, t);
  const total = BACKUP_TABLES.reduce((n, k) => n + f.tables[k].length, 0);
  await audit(c.env.DB, {
    who: c.get("who").name,
    action: "backup.export",
    result: "ok",
    note: `schema ${SCHEMA_VERSION}, ${pass ? "sealed" : "plain"}, ${total} rows`,
    ip: c.req.header("CF-Connecting-IP"),
  });

  const headers = {
    "content-type": "application/octet-stream",
    "content-disposition": `attachment; filename="cfs-backup-${dayOf(t)}.cfsbackup"`,
    "cache-control": "no-store",
  };
  const json = bytesOf(JSON.stringify(f));
  if (pass)
    return new Response((await sealBackup(await gzip(json), pass)) as BodyInit, { headers });
  // Plain files stream: the JSON is compressed on the way out.
  return new Response(
    new Blob([json as BlobPart]).stream().pipeThrough(new CompressionStream("gzip")),
    {
      headers,
    },
  );
});

// Check: reads and verifies the file, changes nothing.
backup.post("/restore/check", async (c) => {
  try {
    const { bytes } = parseRestoreBody(await c.req.json().catch(() => null));
    const { file: f, chain } = await inspect(bytes, passphraseOf(c));
    return c.json({
      ok: true,
      host: requestHost(c),
      schema: f.schema,
      createdAt: f.createdAt,
      gapSeconds: Math.max(0, now() - f.createdAt),
      lastAuditAt: chain.lastAuditAt,
      audit: { rows: chain.rows, ok: chain.ok, checkpoints: chain.checkpoints },
      counts: { file: counts(f.tables), current: await currentCounts(c.env.DB) },
      sha256: f.sha256,
    });
  } catch (e) {
    return failure(c, e);
  }
});

// Restore. Typed host name, maintenance mode, ordered replace, sessions cleared, audited.
backup.post("/restore", async (c) => {
  try {
    const { bytes, confirmHost } = parseRestoreBody(await c.req.json().catch(() => null));
    if (confirmHost !== requestHost(c))
      throw new BackupError(400, `type this server's host name to confirm: ${requestHost(c)}`);
    const { file: f } = await inspect(bytes, passphraseOf(c));
    const db = c.env.DB;
    const who = c.get("who");
    const before = await db
      .prepare("SELECT seq FROM audit ORDER BY seq DESC LIMIT 1")
      .first<{ seq: number }>();

    await db
      .prepare("INSERT OR REPLACE INTO maintenance (id, since, by) VALUES (1, ?, ?)")
      .bind(now(), who.id)
      .run();
    try {
      await replaceTables(db, f);
    } catch {
      // Maintenance stays on: a half-written instance must not take writes. Running restore again finishes it.
      console.error("restore failed part way; instance left in maintenance");
      return c.json(
        { error: "restore failed part way. The instance stays in maintenance. Run restore again." },
        500,
      );
    }
    await db.prepare("DELETE FROM maintenance WHERE id = 1").run();
    await audit(db, {
      who: who.name,
      action: "restore",
      result: "ok",
      note: `schema ${f.schema}, file ${f.sha256.slice(0, 16)}, replaced audit up to seq ${before?.seq ?? 0}`,
      ip: c.req.header("CF-Connecting-IP"),
    });
    return c.json({ ok: true, restoredAt: now(), counts: counts(f.tables) });
  } catch (e) {
    return failure(c, e);
  }
});

/** Known refusals become their status and message. Anything else is a real error for the global handler. */
function failure(c: Context<AppEnv>, e: unknown): Response {
  if (e instanceof BackupError) return c.json({ error: e.message }, e.status);
  throw e;
}

/**
 * Deletes every backed-up table, then inserts the file's rows, parents first. Sessions, login codes and attempt
 * counters are cleared, so everyone signs in again. Each CHUNK of statements is one D1 batch (a transaction).
 */
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

/**
 * ADR 23 scheduled copy, called from the daily cron (ADR 19). Only runs when the optional R2 binding `BACKUP`
 * exists. Writes a plain (unsealed) file and keeps the newest R2_KEEP. Errors are logged without any content.
 */
export async function backupDaily(env: Env, t: number): Promise<void> {
  const bucket = env.BACKUP;
  if (!bucket) return;
  try {
    const f = await buildFile(env.DB, t);
    await bucket.put(
      `${R2_PREFIX}cfs-backup-${dayOf(t)}.cfsbackup`,
      await gzip(bytesOf(JSON.stringify(f))),
    );
    await keepNewest(bucket, R2_KEEP);
  } catch {
    console.error("scheduled backup to R2 failed");
  }
}

/** Deletes everything under the backup prefix except the newest `keep`. Keys sort by date, so that is lexical order. */
export async function keepNewest(bucket: R2Bucket, keep: number): Promise<number> {
  const keys: string[] = [];
  let cursor: string | undefined;
  do {
    const page = await bucket.list({ prefix: R2_PREFIX, cursor });
    for (const o of page.objects) keys.push(o.key);
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  keys.sort();
  const extra = keys.slice(0, Math.max(0, keys.length - keep));
  for (let i = 0; i < extra.length; i += 1000) await bucket.delete(extra.slice(i, i + 1000));
  return extra.length;
}
