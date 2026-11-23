import type { Who } from "../types.ts";

export function historyRows(db: D1Database, path: string, since: number) {
  return db
    .prepare(
      `SELECT at, json_extract(entry, '$.who') AS who, json_extract(entry, '$.version') AS version
       FROM audit
       WHERE json_extract(entry, '$.action') = 'secret.read'
         AND json_extract(entry, '$.path') = ?
         AND json_extract(entry, '$.result') = 'ok'
         AND at >= ?
       ORDER BY at DESC, seq DESC`,
    )
    .bind(path, since)
    .all<{ at: number; who: string; version: number }>();
}

export function historyIdentity(db: D1Database, name: string) {
  return db
    .prepare(
      "SELECT id, kind, name, role, status FROM identity WHERE name = ? ORDER BY kind LIMIT 1",
    )
    .bind(name)
    .first<Who & { status: string }>();
}

export function historyMembership(db: D1Database, prefix: string, id: string) {
  return db
    .prepare(
      `SELECT 1 AS ok FROM keyring k JOIN keyring_member km ON km.keyring_id = k.id
       WHERE k.prefix = ? AND km.identity_id = ? AND km.version = k.version`,
    )
    .bind(prefix, id)
    .first();
}

export function findSecretMeta(db: D1Database, path: string) {
  return db
    .prepare("SELECT id, meta FROM secret WHERE path = ? AND deleted_at IS NULL")
    .bind(path)
    .first<{ id: string; meta: string | null }>();
}

export async function updateSecretMeta(db: D1Database, meta: string, id: string) {
  await db.prepare("UPDATE secret SET meta = ? WHERE id = ?").bind(meta, id).run();
}

export function findDeletedSecret(db: D1Database, path: string) {
  return db
    .prepare("SELECT id, deleted_at AS deletedAt FROM secret WHERE path = ?")
    .bind(path)
    .first<{ id: string; deletedAt: number | null }>();
}

export async function restoreDeletedSecret(db: D1Database, id: string) {
  await db.prepare("UPDATE secret SET deleted_at = NULL WHERE id = ?").bind(id).run();
}

export function listExpiredSecrets(db: D1Database, cutoff: number) {
  return db
    .prepare("SELECT id, path FROM secret WHERE deleted_at IS NOT NULL AND deleted_at < ?")
    .bind(cutoff)
    .all<{ id: string; path: string }>();
}

export async function deleteSecretVersions(db: D1Database, id: string) {
  await db.batch([
    db.prepare("DELETE FROM secret_version WHERE secret_id = ?").bind(id),
    db.prepare("DELETE FROM secret WHERE id = ?").bind(id),
  ]);
}
