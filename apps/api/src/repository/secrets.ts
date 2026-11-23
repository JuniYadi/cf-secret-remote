export function policyRules(db: D1Database, id: string, at: number) {
  return db
    .prepare(
      `SELECT p.rules FROM identity_policy ip JOIN policy p ON p.id = ip.policy_id
       WHERE ip.identity_id = ? AND (ip.expires_at IS NULL OR ip.expires_at > ?)`,
    )
    .bind(id, at)
    .all<{ rules: string }>();
}
export function findOwner(db: D1Database, name: string) {
  return db
    .prepare("SELECT 1 AS ok FROM identity WHERE name = ? AND status = 'active'")
    .bind(name)
    .first();
}
export function listSecrets(db: D1Database) {
  return db
    .prepare(
      `SELECT s.path, s.current AS version, v.names, v.created_at AS updatedAt, s.meta
     FROM secret s JOIN secret_version v ON v.secret_id = s.id AND v.version = s.current
     JOIN keyring k ON k.id = s.keyring_id AND k.personal_owner IS NULL
     WHERE s.deleted_at IS NULL ORDER BY s.path`,
    )
    .all<{
      path: string;
      version: number;
      names: string;
      updatedAt: number;
      meta: string | null;
    }>();
}
export function readSecret(db: D1Database, version: number | null, path: string) {
  return db
    .prepare(
      `SELECT v.version, v.keyring_version AS keyringVersion, v.names, v.wrapped_dek AS wrappedDek, v.ciphertext, v.created_at AS createdAt
     FROM secret s JOIN secret_version v ON v.secret_id = s.id AND v.version = COALESCE(?, s.current)
     JOIN keyring k ON k.id = s.keyring_id AND k.personal_owner IS NULL
     WHERE s.path = ? AND s.deleted_at IS NULL AND v.version <= s.current`,
    )
    .bind(version, path)
    .first<{ version: number; names: string }>();
}
export function findKeyring(db: D1Database, prefix: string) {
  return db
    .prepare("SELECT id, version, status FROM keyring WHERE prefix = ? AND personal_owner IS NULL")
    .bind(prefix)
    .first<{ id: string; version: number; status: string }>();
}
export function findSecret(db: D1Database, path: string) {
  return db
    .prepare("SELECT id, current, deleted_at AS deletedAt, meta FROM secret WHERE path = ?")
    .bind(path)
    .first<{ id: string; current: number; deletedAt: number | null; meta: string | null }>();
}
export async function writeSecret(
  db: D1Database,
  existing: boolean,
  id: string,
  path: string,
  keyringId: string,
  version: number,
  metaJson: string | null,
  keyringVersion: number,
  names: string,
  wrappedDek: string,
  ciphertext: string,
  author: string,
  fps: string | null,
  at: () => number,
) {
  const stmts = [
    existing
      ? db
          .prepare("UPDATE secret SET current = ?, meta = COALESCE(?, meta) WHERE id = ?")
          .bind(version, metaJson, id)
      : db
          .prepare(
            "INSERT INTO secret (id, path, keyring_id, current, created_at, meta) VALUES (?, ?, ?, ?, ?, ?)",
          )
          .bind(id, path, keyringId, version, at(), metaJson),
    db
      .prepare(
        "INSERT INTO secret_version (secret_id, version, keyring_version, names, wrapped_dek, ciphertext, created_by, created_at, fps) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .bind(id, version, keyringVersion, names, wrappedDek, ciphertext, author, at(), fps),
  ];
  await db.batch(stmts);
}
export function secretGroup(db: D1Database, path: string) {
  return db
    .prepare(
      "SELECT k.status FROM secret s JOIN keyring k ON k.id = s.keyring_id WHERE s.path = ? AND s.deleted_at IS NULL",
    )
    .bind(path)
    .first<{ status: string }>();
}
export function deleteSecret(db: D1Database, at: number, path: string) {
  return db
    .prepare("UPDATE secret SET deleted_at = ? WHERE path = ? AND deleted_at IS NULL")
    .bind(at, path)
    .run();
}
export function secretVersions(db: D1Database, path: string) {
  return db
    .prepare(
      `SELECT v.version, v.names, v.fps, v.created_at AS createdAt, i.name AS createdBy
     FROM secret s JOIN secret_version v ON v.secret_id = s.id JOIN identity i ON i.id = v.created_by
     WHERE s.path = ? AND v.version <= s.current ORDER BY v.version DESC`,
    )
    .bind(path)
    .all<{ names: string; fps: string | null }>();
}
