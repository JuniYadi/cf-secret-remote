/** Groups the person still belongs to: current-version members (not lapsed) and staged members of a rotation. */
export async function groupsOf(db: D1Database, id: string, at: number): Promise<string[]> {
  const current = await db
    .prepare(
      `SELECT k.prefix AS prefix FROM keyring_member m JOIN keyring k ON k.id = m.keyring_id
       WHERE m.identity_id = ? AND m.version = k.version AND (m.expires_at IS NULL OR m.expires_at > ?)`,
    )
    .bind(id, at)
    .all<{ prefix: string }>();
  const staged = await db
    .prepare(
      `SELECT DISTINCT k.prefix AS prefix FROM keyring_member_staged s JOIN keyring k ON k.id = s.keyring_id
       WHERE s.identity_id = ?`,
    )
    .bind(id)
    .all<{ prefix: string }>();
  return [...new Set([...current.results, ...staged.results].map((r) => r.prefix))].sort();
}

/** Active apps the person owns. Disabled apps do not block (ADR 15). */
export async function activeAppsOf(db: D1Database, id: string) {
  const rows = await db
    .prepare(
      "SELECT id, name, status FROM identity WHERE kind = 'app' AND owner_id = ? AND status = 'active' ORDER BY name",
    )
    .bind(id)
    .all<{ id: string; name: string; status: string }>();
  return rows.results;
}

export async function planData(
  db: D1Database,
  id: string,
  name: string,
  since: number,
  at: number,
) {
  const sessions = await db
    .prepare(
      "SELECT substr(token_hash, 1, 16) AS id, kind, device, created_at AS createdAt, expires_at AS expiresAt FROM session WHERE identity_id = ? AND expires_at > ? ORDER BY created_at DESC",
    )
    .bind(id, at)
    .all();
  const apps = await db
    .prepare(
      "SELECT id, name, status FROM identity WHERE kind = 'app' AND owner_id = ? ORDER BY name",
    )
    .bind(id)
    .all<{ id: string; name: string; status: string }>();

  const reads = await db
    .prepare(
      `SELECT json_extract(entry, '$.path') AS path, json_extract(entry, '$.version') AS version, at
       FROM audit
       WHERE who = ? AND json_extract(entry, '$.action') = 'secret.read'
         AND json_extract(entry, '$.result') = 'ok' AND at >= ?
       ORDER BY at DESC, seq DESC`,
    )
    .bind(name, since)
    .all<{ path: string; version: number; at: number }>();

  return { sessions, apps, reads };
}

export function secretNames(db: D1Database, path: string) {
  return db
    .prepare(
      "SELECT v.version AS version, v.names AS names FROM secret s JOIN secret_version v ON v.secret_id = s.id WHERE s.path = ?",
    )
    .bind(path)
    .all<{ version: number; names: string }>();
}

export function findOwnedApp(db: D1Database, id: string | undefined) {
  return db
    .prepare("SELECT id, name, owner_id AS ownerId FROM identity WHERE id = ? AND kind = 'app'")
    .bind(id)
    .first<{ id: string; name: string; ownerId: string | null }>();
}

export function findNextOwner(db: D1Database, id: string) {
  return db
    .prepare("SELECT id, name, kind, status FROM identity WHERE id = ?")
    .bind(id)
    .first<{ id: string; name: string; kind: string; status: string }>();
}

export function reassignApp(db: D1Database, nextId: string, appId: string, ownerId: string) {
  return db
    .prepare("UPDATE identity SET owner_id = ? WHERE id = ? AND owner_id = ?")
    .bind(nextId, appId, ownerId)
    .run();
}

export function finishOffboard(db: D1Database, id: string) {
  return db.batch([
    db
      .prepare(
        `UPDATE identity SET status = 'disabled' WHERE id = ? AND status <> 'disabled'
         AND NOT EXISTS (SELECT 1 FROM keyring_member WHERE identity_id = ?)
         AND NOT EXISTS (SELECT 1 FROM keyring_member_staged WHERE identity_id = ?)`,
      )
      .bind(id, id, id),
    db
      .prepare(
        "DELETE FROM session WHERE identity_id = ? AND EXISTS (SELECT 1 FROM identity WHERE id = ? AND status = 'disabled')",
      )
      .bind(id, id),
    db
      .prepare(
        "DELETE FROM identity_policy WHERE identity_id = ? AND EXISTS (SELECT 1 FROM identity WHERE id = ? AND status = 'disabled')",
      )
      .bind(id, id),
  ]);
}
