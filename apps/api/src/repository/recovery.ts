export function findPendingRecovery(db: D1Database, identityId: string) {
  return db
    .prepare("SELECT id FROM recovery_request WHERE identity_id = ? AND status = 'pending'")
    .bind(identityId)
    .first();
}
export async function createRecovery(
  db: D1Database,
  id: string,
  identityId: string,
  publicKey: string,
  lockedKey: string,
  cancelHash: string,
  at: number,
) {
  await db.batch([
    // A locked request is finished; clear it so the record stays small.
    db
      .prepare("DELETE FROM recovery_request WHERE identity_id = ? AND status = 'locked'")
      .bind(identityId),
    db
      .prepare(
        "INSERT INTO recovery_request (id, identity_id, public_key, locked_key, cancel_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .bind(id, identityId, publicKey, lockedKey, cancelHash, at),
  ]);
}

export function listRecoveries(db: D1Database) {
  return db
    .prepare(
      `SELECT r.id, i.name, r.created_at AS createdAt, r.attempts FROM recovery_request r
     JOIN identity i ON i.id = r.identity_id WHERE r.status = 'pending' ORDER BY r.created_at`,
    )
    .all<{ id: string; name: string; createdAt: number; attempts: number }>();
}

interface RequestRow {
  id: string;
  identity_id: string;
  name: string;
  public_key: string;
  status: string;
  attempts: number;
}

export const loadRequest = (db: D1Database, id: string) =>
  db
    .prepare(
      `SELECT r.id, r.identity_id, i.name, r.public_key, r.status, r.attempts
     FROM recovery_request r JOIN identity i ON i.id = r.identity_id WHERE r.id = ?`,
    )
    .bind(id)
    .first<RequestRow>();

export function recoveryGroups(db: D1Database, identityId: string) {
  return db
    .prepare(
      `SELECT k.prefix FROM keyring_member m JOIN keyring k ON k.id = m.keyring_id
     WHERE m.identity_id = ? AND m.version = k.version ORDER BY k.prefix`,
    )
    .bind(identityId)
    .all<{ prefix: string }>();
}

export async function recordWrongCode(db: D1Database, maxAttempts: number, id: string) {
  await db
    .prepare(
      "UPDATE recovery_request SET attempts = attempts + 1, status = CASE WHEN attempts + 1 >= ? THEN 'locked' ELSE status END WHERE id = ? AND status = 'pending'",
    )
    .bind(maxAttempts, id)
    .run();
}
export function findRecoveryGroup(db: D1Database, prefix: string) {
  return db
    .prepare("SELECT id, version, status FROM keyring WHERE prefix = ?")
    .bind(prefix)
    .first<{ id: string; version: number; status: string }>();
}
export function findRecoveryMember(
  db: D1Database,
  keyringId: string,
  identityId: string,
  version: number,
) {
  return db
    .prepare(
      "SELECT 1 AS ok FROM keyring_member WHERE keyring_id = ? AND identity_id = ? AND version = ?",
    )
    .bind(keyringId, identityId, version)
    .first();
}
export async function grantRecovery(
  db: D1Database,
  adminId: string,
  t: number,
  id: string,
  identityId: string,
  plan: { keyringId: string; prefix: string; version: number; wrappedKey: string }[],
) {
  const guard =
    "EXISTS (SELECT 1 FROM recovery_request WHERE id = ? AND status = 'granted' AND resolved_by = ?)";
  await db.batch([
    db
      .prepare(
        "UPDATE recovery_request SET status = 'granted', resolved_by = ?, resolved_at = ? WHERE id = ? AND status = 'pending'",
      )
      .bind(adminId, t, id),
    db
      .prepare(
        `UPDATE identity SET
           public_key = (SELECT public_key FROM recovery_request WHERE id = ?),
           locked_key = (SELECT locked_key FROM recovery_request WHERE id = ?),
           recovery_locked_key = NULL
         WHERE id = ? AND ${guard}`,
      )
      .bind(id, id, identityId, id, adminId),
    ...plan.flatMap((p) => [
      db
        .prepare(`DELETE FROM keyring_member WHERE keyring_id = ? AND identity_id = ? AND ${guard}`)
        .bind(p.keyringId, identityId, id, adminId),
      db
        .prepare(
          `INSERT INTO keyring_member (keyring_id, identity_id, version, wrapped_key)
           SELECT ?, ?, ?, ? WHERE ${guard}`,
        )
        .bind(p.keyringId, identityId, p.version, p.wrappedKey, id, adminId),
    ]),
  ]);
}

export function findCancellation(db: D1Database, id: string) {
  return db
    .prepare("SELECT identity_id, cancel_hash, status FROM recovery_request WHERE id = ?")
    .bind(id)
    .first<{ identity_id: string; cancel_hash: string; status: string }>();
}
export async function cancelRecovery(db: D1Database, id: string) {
  await db
    .prepare("DELETE FROM recovery_request WHERE id = ? AND status = 'pending'")
    .bind(id)
    .run();
}
