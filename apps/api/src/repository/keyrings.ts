export function listKeyrings(db: D1Database, role: string, id: string) {
  return db
    .prepare(
      `SELECT k.id, k.prefix, k.version FROM keyring k
     WHERE k.personal_owner IS NULL AND (?1 = 'admin' OR EXISTS (SELECT 1 FROM keyring_member m WHERE m.keyring_id = k.id AND m.identity_id = ?2))
     ORDER BY k.prefix`,
    )
    .bind(role, id)
    .all();
}
export function createKeyring(
  db: D1Database,
  id: string,
  prefix: string,
  at: number,
  members: { identityId: string; wrappedKey: string }[],
) {
  return db.batch([
    db
      .prepare("INSERT INTO keyring (id, prefix, created_at) VALUES (?, ?, ?)")
      .bind(id, prefix, at),
    ...members.map((m) =>
      db
        .prepare(
          "INSERT INTO keyring_member (keyring_id, identity_id, version, wrapped_key) VALUES (?, ?, 1, ?)",
        )
        .bind(id, m.identityId, m.wrappedKey),
    ),
  ]);
}
export function findKeyringKey(db: D1Database, prefix: string, id: string, version: number | null) {
  return db
    .prepare(
      `SELECT m.wrapped_key, m.version, m.expires_at AS expiresAt FROM keyring_member m JOIN keyring k ON k.id = m.keyring_id
     WHERE k.prefix = ? AND k.personal_owner IS NULL AND m.identity_id = ? AND (?3 IS NULL OR m.version = ?3)
     ORDER BY m.version DESC LIMIT 1`,
    )
    .bind(prefix, id, version)
    .first<{ wrapped_key: string; version: number; expiresAt: number | null }>();
}
export function listIdentities(db: D1Database) {
  return db
    .prepare(
      "SELECT id, kind, name, role, public_key AS publicKey, status, (recovery_locked_key IS NOT NULL) AS recoverySet, last_unlocked_at FROM identity ORDER BY name",
    )
    .all();
}
export function inviteIdentity(
  db: D1Database,
  id: string,
  email: string,
  role: string,
  at: number,
) {
  return db
    .prepare("INSERT INTO identity (id, kind, name, role, created_at) VALUES (?, 'user', ?, ?, ?)")
    .bind(id, email, role, at)
    .run();
}
export function findPersonalKeyring(db: D1Database, id: string) {
  return db
    .prepare(
      `SELECT k.id, k.prefix, k.version, m.wrapped_key AS wrappedKey FROM keyring k
     JOIN keyring_member m ON m.keyring_id = k.id AND m.identity_id = k.personal_owner AND m.version = k.version
     WHERE k.personal_owner = ?`,
    )
    .bind(id)
    .first();
}
export function findPublicKey(db: D1Database, id: string) {
  return db
    .prepare("SELECT public_key FROM identity WHERE id = ?")
    .bind(id)
    .first<{ public_key: string | null }>();
}
export function createPersonalKeyring(
  db: D1Database,
  id: string,
  prefix: string,
  at: number,
  owner: string,
  wrappedKey: string,
) {
  return db.batch([
    db
      .prepare("INSERT INTO keyring (id, prefix, created_at, personal_owner) VALUES (?, ?, ?, ?)")
      .bind(id, prefix, at, owner),
    db
      .prepare(
        "INSERT INTO keyring_member (keyring_id, identity_id, version, wrapped_key) VALUES (?, ?, 1, ?)",
      )
      .bind(id, owner, wrappedKey),
  ]);
}
export function findPersonalKeyringOwner(db: D1Database, id: string) {
  return db
    .prepare("SELECT id, prefix, version FROM keyring WHERE personal_owner = ?")
    .bind(id)
    .first();
}
export function grantCounts(db: D1Database, identityId: string, prefix: string, t: number) {
  return db
    .prepare(
      `SELECT
         COALESCE(SUM(CASE WHEN m.expires_at IS NOT NULL AND m.expires_at <= ? THEN 1 ELSE 0 END), 0) AS lapsed,
         COALESCE(SUM(CASE WHEN m.expires_at IS NULL OR m.expires_at > ? THEN 1 ELSE 0 END), 0) AS live
       FROM keyring_member m JOIN keyring k ON k.id = m.keyring_id
       WHERE k.prefix = ? AND m.identity_id = ?`,
    )
    .bind(t, t, prefix, identityId)
    .first<{ lapsed: number; live: number }>();
}
