import { now } from "../util.ts";

export async function member(db: D1Database, keyringId: string, identityId: string) {
  return db
    .prepare(
      `SELECT k.version, k.status FROM keyring k JOIN keyring_member m ON m.keyring_id = k.id AND m.version = k.version WHERE k.id = ? AND m.identity_id = ? AND (m.expires_at IS NULL OR m.expires_at > ?)`,
    )
    .bind(keyringId, identityId, now())
    .first<{ version: number; status: string }>();
}
export async function item(db: D1Database, id: string, identityId: string, deleted = false) {
  return db
    .prepare(
      `SELECT l.id, l.keyring_id AS keyringId, l.current, l.created_at AS createdAt, l.deleted_at AS deletedAt FROM login l JOIN keyring k ON k.id = l.keyring_id JOIN keyring_member m ON m.keyring_id = k.id AND m.version = k.version WHERE l.id = ? AND m.identity_id = ? AND (m.expires_at IS NULL OR m.expires_at > ?) AND l.deleted_at IS ${deleted ? "NOT NULL" : "NULL"}`,
    )
    .bind(id, identityId, now())
    .first<{
      id: string;
      keyringId: string;
      current: number;
      createdAt: number;
      deletedAt: number | null;
    }>();
}

export function listLogins(db: D1Database, identityId: string, at: number) {
  return db
    .prepare(
      `SELECT l.id, l.created_at AS createdAt, v.version, v.keyring_id AS keyringId, v.keyring_version AS keyringVersion, v.wrapped_dek AS wrappedDek, v.ciphertext, v.fps, v.created_at AS updatedAt, length(v.ciphertext) AS size FROM login l JOIN login_version v ON v.login_id = l.id AND v.version = l.current JOIN keyring k ON k.id = l.keyring_id JOIN keyring_member m ON m.keyring_id = k.id AND m.version = k.version WHERE m.identity_id = ? AND (m.expires_at IS NULL OR m.expires_at > ?) AND l.deleted_at IS NULL ORDER BY l.id`,
    )
    .bind(identityId, at)
    .all<{ fps: string }>();
}

export function listLoginVersions(db: D1Database, identityId: string, id: string, at: number) {
  return db
    .prepare(
      `SELECT v.version, v.keyring_id AS keyringId, v.keyring_version AS keyringVersion, v.fps, v.created_at AS createdAt FROM login_version v JOIN keyring_member m ON m.keyring_id = v.keyring_id AND m.identity_id = ? AND m.version = v.keyring_version WHERE v.login_id = ? AND (m.expires_at IS NULL OR m.expires_at > ?) ORDER BY v.version DESC`,
    )
    .bind(identityId, id, at)
    .all<{ fps: string }>();
}

const selectVersion = `SELECT v.version, v.keyring_id AS keyringId, v.keyring_version AS keyringVersion, v.wrapped_dek AS wrappedDek, v.ciphertext, v.fps, v.created_at AS updatedAt, length(v.ciphertext) AS size FROM login_version v`;

export function findLoginVersion(
  db: D1Database,
  identityId: string,
  id: string,
  version: number,
  at: number,
) {
  return db
    .prepare(
      `${selectVersion} JOIN keyring_member m ON m.keyring_id = v.keyring_id AND m.version = v.keyring_version AND m.identity_id = ? WHERE v.login_id = ? AND v.version = ? AND (m.expires_at IS NULL OR m.expires_at > ?)`,
    )
    .bind(identityId, id, version, at)
    .first<{ fps: string }>();
}

export function findCurrentLoginVersion(db: D1Database, id: string, version: number) {
  return db
    .prepare(`${selectVersion} WHERE v.login_id = ? AND v.version = ?`)
    .bind(id, version)
    .first<{ fps: string }>();
}

export function findRestoreSource(
  db: D1Database,
  id: string,
  target: number,
  identityId: string,
  at: number,
) {
  return db
    .prepare(
      `SELECT 1 FROM login_version v JOIN keyring_member m ON m.keyring_id = v.keyring_id AND m.version = v.keyring_version WHERE v.login_id = ? AND v.version = ? AND m.identity_id = ? AND (m.expires_at IS NULL OR m.expires_at > ?)`,
    )
    .bind(id, target, identityId, at)
    .first();
}
export function loginExists(db: D1Database, id: string) {
  return db.prepare("SELECT 1 FROM login WHERE id = ?").bind(id).first();
}
export function writeLogin(
  db: D1Database,
  p: {
    id: string;
    version: number;
    keyringId: string;
    keyringVersion: number;
    wrappedDek: string;
    ciphertext: string;
    fps: string;
    identityId: string;
    oldCurrent?: number;
  },
) {
  return db.batch([
    p.oldCurrent !== undefined
      ? db
          .prepare(
            "UPDATE login SET current = ?, keyring_id = ? WHERE id = ? AND current = ? AND deleted_at IS NULL AND EXISTS (SELECT 1 FROM keyring WHERE id = ? AND version = ? AND status = 'active')",
          )
          .bind(p.version, p.keyringId, p.id, p.oldCurrent, p.keyringId, p.keyringVersion)
      : db
          .prepare(
            "INSERT INTO login (id, keyring_id, current, created_at) SELECT ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM keyring WHERE id = ? AND version = ? AND status = 'active')",
          )
          .bind(p.id, p.keyringId, p.version, now(), p.keyringId, p.keyringVersion),
    db
      .prepare(
        "INSERT INTO login_version (login_id, version, keyring_id, keyring_version, wrapped_dek, ciphertext, fps, created_by, created_at) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM login WHERE id = ? AND current = ? AND keyring_id = ? AND deleted_at IS NULL)",
      )
      .bind(
        p.id,
        p.version,
        p.keyringId,
        p.keyringVersion,
        p.wrappedDek,
        p.ciphertext,
        p.fps,
        p.identityId,
        now(),
        p.id,
        p.version,
        p.keyringId,
      ),
  ]);
}

export async function deleteLogin(db: D1Database, at: number, id: string) {
  await db
    .prepare("UPDATE login SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL")
    .bind(at, id)
    .run();
}

export async function undeleteLogin(db: D1Database, id: string) {
  await db.prepare("UPDATE login SET deleted_at = NULL WHERE id = ?").bind(id).run();
}

export async function purgeLoginRows(db: D1Database, cutoff: number) {
  await db.batch([
    db
      .prepare(
        "DELETE FROM login_version WHERE login_id IN (SELECT id FROM login WHERE deleted_at IS NOT NULL AND deleted_at < ?)",
      )
      .bind(cutoff),
    db.prepare("DELETE FROM login WHERE deleted_at IS NOT NULL AND deleted_at < ?").bind(cutoff),
  ]);
}
