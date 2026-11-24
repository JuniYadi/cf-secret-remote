// ADR 36: environment collections. Writes that change a definition are one D1 batch. Each statement that writes
// children checks the parent revision the caller saw, and the parent update comes last. D1 runs a batch as one
// transaction, so a stale caller changes nothing.
export function findCollection(db: D1Database, name: string) {
  return db
    .prepare(
      "SELECT id, name, revision, created_at AS createdAt, updated_at AS updatedAt FROM env_collection WHERE name = ?",
    )
    .bind(name)
    .first<{ id: string; name: string; revision: number; createdAt: number; updatedAt: number }>();
}

export function collectionEnvs(db: D1Database, id: string) {
  return db
    .prepare("SELECT label, path FROM env_collection_env WHERE collection_id = ? ORDER BY label")
    .bind(id)
    .all<{ label: string; path: string }>();
}

export function collectionKeys(db: D1Database, id: string) {
  return db
    .prepare(
      "SELECT name, description FROM env_collection_key WHERE collection_id = ? ORDER BY name",
    )
    .bind(id)
    .all<{ name: string; description: string | null }>();
}

export function listCollections(db: D1Database) {
  return db
    .prepare(
      `SELECT c.name, c.revision, c.updated_at AS updatedAt,
       (SELECT COUNT(*) FROM env_collection_env e WHERE e.collection_id = c.id) AS envCount,
       (SELECT COUNT(*) FROM env_collection_key k WHERE k.collection_id = c.id) AS keyCount
     FROM env_collection c ORDER BY c.name`,
    )
    .all<{
      name: string;
      revision: number;
      updatedAt: number;
      envCount: number;
      keyCount: number;
    }>();
}

export function countCollections(db: D1Database) {
  return db.prepare("SELECT COUNT(*) AS n FROM env_collection").first<{ n: number }>();
}

/** Current cleartext names of live secrets at these paths. Missing or deleted paths are absent from the result. */
export function currentSecrets(db: D1Database, paths: string[]) {
  const marks = paths.map(() => "?").join(", ");
  return db
    .prepare(
      `SELECT s.path, s.current AS version, v.names, v.created_at AS updatedAt
     FROM secret s
     JOIN keyring k ON k.id = s.keyring_id AND k.personal_owner IS NULL
     JOIN secret_version v ON v.secret_id = s.id AND v.version = s.current
     WHERE s.deleted_at IS NULL AND s.path IN (${marks})`,
    )
    .bind(...paths)
    .all<{ path: string; version: number; names: string; updatedAt: number }>();
}

// Evaluated inside the write batch, so source versions cannot change between validation and commit.
function sourceGuard(sources: Record<string, number>) {
  const entries = Object.entries(sources);
  return {
    sql:
      entries
        .map(
          () =>
            "EXISTS (SELECT 1 FROM secret WHERE path = ? AND current = ? AND deleted_at IS NULL)",
        )
        .join(" AND ") || "1",
    args: entries.flatMap(([path, version]) => [path, version]),
  };
}

export async function createCollection(
  db: D1Database,
  id: string,
  name: string,
  at: number,
  envs: { label: string; path: string }[],
  keys: { name: string; description: string | null }[],
  sources: Record<string, number> = {},
): Promise<boolean> {
  const guard = sourceGuard(sources);
  const results = await db.batch([
    db
      .prepare(
        `INSERT INTO env_collection (id, name, revision, created_at, updated_at) SELECT ?, ?, 1, ?, ? WHERE ${guard.sql}`,
      )
      .bind(id, name, at, at, ...guard.args),
    ...envs.map((e) =>
      db
        .prepare(
          "INSERT INTO env_collection_env (collection_id, label, path) SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM env_collection WHERE id = ?)",
        )
        .bind(id, e.label, e.path, id),
    ),
    ...keys.map((k) =>
      db
        .prepare(
          "INSERT INTO env_collection_key (collection_id, name, description) SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM env_collection WHERE id = ?)",
        )
        .bind(id, k.name, k.description, id),
    ),
  ]);
  return (results[0]?.meta.changes ?? 0) === 1;
}

/**
 * Replaces the whole definition if the revision is still `expected`. Returns false when it is not, and then
 * nothing was written: the child statements check the same revision as the final update.
 */
export async function replaceDefinition(
  db: D1Database,
  id: string,
  expected: number,
  at: number,
  envs: { label: string; path: string }[],
  keys: { name: string; description: string | null }[],
): Promise<boolean> {
  const live = "EXISTS (SELECT 1 FROM env_collection WHERE id = ? AND revision = ?)";
  const results = await db.batch([
    db
      .prepare(`DELETE FROM env_collection_env WHERE collection_id = ? AND ${live}`)
      .bind(id, id, expected),
    db
      .prepare(`DELETE FROM env_collection_key WHERE collection_id = ? AND ${live}`)
      .bind(id, id, expected),
    ...envs.map((e) =>
      db
        .prepare(
          `INSERT INTO env_collection_env (collection_id, label, path) SELECT ?, ?, ? WHERE ${live}`,
        )
        .bind(id, e.label, e.path, id, expected),
    ),
    ...keys.map((k) =>
      db
        .prepare(
          `INSERT INTO env_collection_key (collection_id, name, description) SELECT ?, ?, ? WHERE ${live}`,
        )
        .bind(id, k.name, k.description, id, expected),
    ),
    db
      .prepare(
        "UPDATE env_collection SET revision = revision + 1, updated_at = ? WHERE id = ? AND revision = ?",
      )
      .bind(at, id, expected),
  ]);
  return (results[results.length - 1]?.meta.changes ?? 0) === 1;
}

/** Adds declared names (no value is written anywhere) if the revision is still `expected`. */
export async function addKeys(
  db: D1Database,
  id: string,
  expected: number,
  at: number,
  keys: { name: string; description: string | null }[],
  sources: Record<string, number>,
): Promise<boolean> {
  const guard = sourceGuard(sources);
  const live = `EXISTS (SELECT 1 FROM env_collection WHERE id = ? AND revision = ?) AND ${guard.sql}`;
  const results = await db.batch([
    ...keys.map((k) =>
      db
        .prepare(
          `INSERT INTO env_collection_key (collection_id, name, description) SELECT ?, ?, ? WHERE ${live}`,
        )
        .bind(id, k.name, k.description, id, expected, ...guard.args),
    ),
    db
      .prepare(
        `UPDATE env_collection SET revision = revision + 1, updated_at = ? WHERE id = ? AND revision = ? AND ${guard.sql}`,
      )
      .bind(at, id, expected, ...guard.args),
  ]);
  return (results[results.length - 1]?.meta.changes ?? 0) === 1;
}

/** Deletes a definition (children first) if the revision is still `expected`. Stored values are never touched. */
export async function deleteCollection(
  db: D1Database,
  id: string,
  expected: number,
): Promise<boolean> {
  const live = "EXISTS (SELECT 1 FROM env_collection WHERE id = ? AND revision = ?)";
  const results = await db.batch([
    db
      .prepare(`DELETE FROM env_collection_env WHERE collection_id = ? AND ${live}`)
      .bind(id, id, expected),
    db
      .prepare(`DELETE FROM env_collection_key WHERE collection_id = ? AND ${live}`)
      .bind(id, id, expected),
    db.prepare("DELETE FROM env_collection WHERE id = ? AND revision = ?").bind(id, expected),
  ]);
  return (results[results.length - 1]?.meta.changes ?? 0) === 1;
}
