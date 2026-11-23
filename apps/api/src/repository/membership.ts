import { now } from "../util.ts";

export interface Group {
  id: string;
  version: number;
  status: "active" | "rotating";
}

/**
 * Two-admin guard (ADR 20): active user admins that hold a vault, not counting `exceptId`.
 * Callers refuse a demotion or disable of an admin when this is below 2.
 */
export async function countAdminsWithVault(db: D1Database, exceptId?: string): Promise<number> {
  const row = await db
    .prepare(
      "SELECT COUNT(*) AS n FROM identity WHERE kind = 'user' AND role = 'admin' AND status = 'active' AND public_key IS NOT NULL AND id != ?",
    )
    .bind(exceptId ?? "")
    .first<{ n: number }>();
  return row?.n ?? 0;
}

export const loadGroup = (db: D1Database, prefix: string) =>
  db
    .prepare("SELECT id, version, status FROM keyring WHERE prefix = ? AND personal_owner IS NULL")
    .bind(prefix)
    .first<Group>();

export async function findMembership(
  db: D1Database,
  groupId: string,
  identityId: string,
  version: number,
  at: number,
) {
  const mine = await db
    .prepare(
      `SELECT 1 AS ok FROM keyring_member WHERE keyring_id = ? AND identity_id = ? AND version = ?
       AND (expires_at IS NULL OR expires_at > ?)`,
    )
    .bind(groupId, identityId, version, at)
    .first();
  return mine;
}

export async function listMembers(db: D1Database, groupId: string, version: number, at: number) {
  const rows = await db
    .prepare(
      `SELECT i.id AS identityId, i.name, i.role, i.status FROM keyring_member m
     JOIN identity i ON i.id = m.identity_id
     WHERE m.keyring_id = ? AND m.version = ? AND (m.expires_at IS NULL OR m.expires_at > ?)
     ORDER BY i.name`,
    )
    .bind(groupId, version, at)
    .all();
  return rows;
}

export async function findTarget(db: D1Database, identityId: string) {
  const target = await db
    .prepare("SELECT name, public_key AS publicKey, status FROM identity WHERE id = ?")
    .bind(identityId)
    .first<{ name: string; publicKey: string | null; status: string }>();
  return target;
}

export async function addMember(
  db: D1Database,
  groupId: string,
  identityId: string,
  version: number,
  wrappedKey: string,
) {
  await db
    .prepare(
      "INSERT INTO keyring_member (keyring_id, identity_id, version, wrapped_key) VALUES (?, ?, ?, ?)",
    )
    .bind(groupId, identityId, version, wrappedKey)
    .run();
}

export async function currentMembers(db: D1Database, groupId: string, version: number, at: number) {
  const current = await db
    .prepare(
      `SELECT identity_id AS id FROM keyring_member WHERE keyring_id = ? AND version = ?
       AND (expires_at IS NULL OR expires_at > ?)`,
    )
    .bind(groupId, version, at)
    .all<{ id: string }>();
  return current;
}

export async function knownIdentity(db: D1Database, removeId: string) {
  const known = await db
    .prepare("SELECT 1 AS ok FROM identity WHERE id = ?")
    .bind(removeId)
    .first();
  return known;
}

export async function removedIdentity(db: D1Database, removeId: string) {
  const removed = await db
    .prepare("SELECT name FROM identity WHERE id = ?")
    .bind(removeId)
    .first<{ name: string }>();
  return removed;
}

export async function startRotation(
  db: D1Database,
  groupId: string,
  members: { identityId: string; wrappedKey: string }[],
  next: number,
  removeId: string,
) {
  const started = await db.batch([
    db
      .prepare("UPDATE keyring SET status = 'rotating' WHERE id = ? AND status = 'active'")
      .bind(groupId),
    ...members.map((m) =>
      db
        .prepare(
          "INSERT INTO keyring_member_staged (keyring_id, identity_id, version, wrapped_key) SELECT ?, ?, ?, ? WHERE changes() = 1",
        )
        .bind(groupId, m.identityId, next, m.wrappedKey),
    ),
    db
      .prepare(
        "DELETE FROM keyring_member WHERE keyring_id = ? AND identity_id = ? AND changes() = 1",
      )
      .bind(groupId, removeId),
  ]);
  return started;
}

export async function liveSecrets(db: D1Database, groupId: string) {
  const live = await db
    .prepare("SELECT COUNT(*) AS n FROM secret WHERE keyring_id = ? AND deleted_at IS NULL")
    .bind(groupId)
    .first<{ n: number }>();
  return live;
}

export async function rotationLogins(db: D1Database, groupId: string) {
  const rows = await db
    .prepare(
      `SELECT l.id, v.version, v.wrapped_dek AS wrappedDek, v.ciphertext, v.fps
     FROM login l JOIN login_version v ON v.login_id = l.id AND v.version = l.current
     WHERE l.keyring_id = ? ORDER BY l.id`,
    )
    .bind(groupId)
    .all<{ fps: string }>();
  return rows;
}

export async function loginCurrent(db: D1Database, id: string, groupId: string) {
  const row = await db
    .prepare("SELECT current FROM login WHERE id = ? AND keyring_id = ?")
    .bind(id, groupId)
    .first<{ current: number }>();
  return row;
}

export async function secretCurrent(db: D1Database, path: string, groupId: string) {
  const row = await db
    .prepare(
      "SELECT id, current, deleted_at AS deletedAt FROM secret WHERE path = ? AND keyring_id = ?",
    )
    .bind(path, groupId)
    .first<{ id: string; current: number; deletedAt: number | null }>();
  return row;
}

export async function stageRotation(
  db: D1Database,
  secrets: {
    path: string;
    names: string[];
    wrappedDek: string;
    ciphertext: string;
    version: number;
  }[],
  rows: { secretId: string; version: number }[],
  loginItems: {
    id: string;
    version: number;
    wrappedDek: string;
    ciphertext: string;
    fps: unknown;
  }[],
  groupId: string,
  next: number,
  whoId: string,
) {
  await db.batch([
    ...secrets.flatMap((s, i) => {
      const r = rows[i] as { secretId: string; version: number };
      return [
        // A retried chunk replaces its own staged rows.
        db
          .prepare(
            "DELETE FROM secret_version WHERE secret_id = ? AND version = ? AND keyring_version = ?",
          )
          .bind(r.secretId, r.version, next),
        db
          .prepare(
            "INSERT INTO secret_version (secret_id, version, keyring_version, names, wrapped_dek, ciphertext, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
          )
          .bind(
            r.secretId,
            r.version,
            next,
            JSON.stringify(s.names),
            s.wrappedDek,
            s.ciphertext,
            whoId,
            now(),
          ),
      ];
    }),
    ...loginItems.flatMap((l) => [
      db
        .prepare(
          "DELETE FROM login_version WHERE login_id = ? AND version = ? AND keyring_version = ?",
        )
        .bind(l.id, l.version, next),
      db
        .prepare(
          "INSERT INTO login_version (login_id, version, keyring_id, keyring_version, wrapped_dek, ciphertext, fps, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(
          l.id,
          l.version,
          groupId,
          next,
          l.wrappedDek,
          l.ciphertext,
          JSON.stringify(l.fps),
          whoId,
          now(),
        ),
    ]),
  ]);
}

export async function missingSecrets(db: D1Database, groupId: string, next: number) {
  const missing = await db
    .prepare(
      `SELECT s.path FROM secret s WHERE s.keyring_id = ? AND s.deleted_at IS NULL
       AND NOT EXISTS (SELECT 1 FROM secret_version v WHERE v.secret_id = s.id AND v.keyring_version = ?)
       ORDER BY s.path`,
    )
    .bind(groupId, next)
    .all<{ path: string }>();
  return missing;
}

export async function missingLogins(db: D1Database, groupId: string, next: number) {
  const missingLogins = await db
    .prepare(
      `SELECT l.id FROM login l WHERE l.keyring_id = ? AND NOT EXISTS
     (SELECT 1 FROM login_version v WHERE v.login_id = l.id AND v.version = l.current + 1 AND v.keyring_version = ? AND v.keyring_id = ?)`,
    )
    .bind(groupId, next, groupId)
    .all<{ id: string }>();
  return missingLogins;
}

export async function commitRotation(db: D1Database, groupId: string, next: number) {
  await db.batch([
    db
      .prepare(
        `UPDATE keyring SET version = ?, status = 'active' WHERE id = ? AND status = 'rotating'
           AND NOT EXISTS (SELECT 1 FROM secret s WHERE s.keyring_id = ? AND s.deleted_at IS NULL
             AND NOT EXISTS (SELECT 1 FROM secret_version v WHERE v.secret_id = s.id AND v.keyring_version = ?))
           AND NOT EXISTS (SELECT 1 FROM login l WHERE l.keyring_id = ? AND NOT EXISTS
             (SELECT 1 FROM login_version v WHERE v.login_id = l.id AND v.version = l.current + 1 AND v.keyring_version = ? AND v.keyring_id = ?))`,
      )
      .bind(next, groupId, groupId, next, groupId, next, groupId),
    // The statements below only apply if the keyring flip above happened.
    db
      .prepare(
        `UPDATE secret SET current = current + 1 WHERE keyring_id = ? AND deleted_at IS NULL
           AND EXISTS (SELECT 1 FROM secret_version v WHERE v.secret_id = secret.id AND v.keyring_version = ?)
           AND EXISTS (SELECT 1 FROM keyring WHERE id = ? AND version = ?)`,
      )
      .bind(groupId, next, groupId, next),
    db
      .prepare(`UPDATE login SET current = current + 1 WHERE keyring_id = ?
        AND EXISTS (SELECT 1 FROM login_version v WHERE v.login_id = login.id AND v.version = login.current + 1 AND v.keyring_version = ? AND v.keyring_id = ?)
        AND EXISTS (SELECT 1 FROM keyring WHERE id = ? AND version = ?)`)
      .bind(groupId, next, groupId, groupId, next),
    db
      .prepare(
        `INSERT INTO keyring_member (keyring_id, identity_id, version, wrapped_key)
           SELECT keyring_id, identity_id, version, wrapped_key FROM keyring_member_staged
           WHERE keyring_id = ? AND version = ? AND EXISTS (SELECT 1 FROM keyring WHERE id = ? AND version = ?)`,
      )
      .bind(groupId, next, groupId, next),
    db
      .prepare(
        "DELETE FROM keyring_member_staged WHERE keyring_id = ? AND EXISTS (SELECT 1 FROM keyring WHERE id = ? AND version = ?)",
      )
      .bind(groupId, groupId, next),
  ]);
}

export async function abortRotation(db: D1Database, groupId: string, next: number) {
  await db.batch([
    db
      .prepare(
        "DELETE FROM secret_version WHERE keyring_version = ? AND secret_id IN (SELECT id FROM secret WHERE keyring_id = ?)",
      )
      .bind(next, groupId),
    db
      .prepare(
        "DELETE FROM login_version WHERE keyring_version = ? AND keyring_id = ? AND login_id IN (SELECT id FROM login WHERE keyring_id = ?)",
      )
      .bind(next, groupId, groupId),
    db.prepare("DELETE FROM keyring_member_staged WHERE keyring_id = ?").bind(groupId),
    db
      .prepare("UPDATE keyring SET status = 'active' WHERE id = ? AND status = 'rotating'")
      .bind(groupId),
  ]);
}

export async function findIdentity(db: D1Database, id: string) {
  const t = await db
    .prepare(
      "SELECT id, kind, name, role, status, public_key AS publicKey FROM identity WHERE id = ?",
    )
    .bind(id)
    .first<{
      id: string;
      kind: string;
      name: string;
      role: string;
      status: string;
      publicKey: string | null;
    }>();
  return t;
}

export async function updateIdentity(db: D1Database, role: string, status: string, id: string) {
  const statements = [
    db.prepare("UPDATE identity SET role = ?, status = ? WHERE id = ?").bind(role, status, id),
  ];
  if (status === "disabled")
    statements.push(db.prepare("DELETE FROM session WHERE identity_id = ?").bind(id));
  await db.batch(statements);
}
