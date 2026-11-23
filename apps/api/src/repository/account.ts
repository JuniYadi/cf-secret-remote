/** D1 operations for a person's vault and signed-in sessions. */
export function listSessions(db: D1Database, identityId: string, time: number) {
  return db
    .prepare(
      "SELECT substr(token_hash, 1, 16) AS id, kind, device, created_at AS createdAt, last_used_at AS lastUsedAt, expires_at AS expiresAt FROM session WHERE identity_id = ? AND expires_at > ? ORDER BY created_at DESC",
    )
    .bind(identityId, time)
    .all();
}

export function deleteSession(db: D1Database, identityId: string, id: string) {
  return db
    .prepare("DELETE FROM session WHERE identity_id = ? AND substr(token_hash, 1, 16) = ?")
    .bind(identityId, id)
    .run();
}

export function deleteSessions(db: D1Database, identityId: string) {
  return db.prepare("DELETE FROM session WHERE identity_id = ?").bind(identityId).run();
}

export function getVault(db: D1Database, identityId: string) {
  return db
    .prepare("SELECT public_key, locked_key FROM identity WHERE id = ?")
    .bind(identityId)
    .first<{ public_key: string | null; locked_key: string | null }>();
}

export function stampUnlock(db: D1Database, identityId: string, time: number, cutoff: number) {
  return db
    .prepare(
      "UPDATE identity SET last_unlocked_at = ? WHERE id = ? AND (last_unlocked_at IS NULL OR last_unlocked_at <= ?)",
    )
    .bind(time, identityId, cutoff)
    .run();
}

export function setupVault(
  db: D1Database,
  identityId: string,
  publicKey: string,
  lockedKey: string,
) {
  return db
    .prepare(
      "UPDATE identity SET public_key = ?, locked_key = ? WHERE id = ? AND public_key IS NULL",
    )
    .bind(publicKey, lockedKey, identityId)
    .run();
}

export function updateVaultLock(db: D1Database, identityId: string, lockedKey: string) {
  return db
    .prepare("UPDATE identity SET locked_key = ? WHERE id = ? AND public_key IS NOT NULL")
    .bind(lockedKey, identityId)
    .run();
}

export function getRecoveryLock(db: D1Database, identityId: string) {
  return db
    .prepare("SELECT recovery_locked_key AS lockedKey FROM identity WHERE id = ?")
    .bind(identityId)
    .first<{ lockedKey: string | null }>();
}

export function updateRecoveryLock(db: D1Database, identityId: string, lockedKey: string) {
  return db
    .prepare("UPDATE identity SET recovery_locked_key = ? WHERE id = ? AND public_key IS NOT NULL")
    .bind(lockedKey, identityId)
    .run();
}
