export interface AppRow {
  id: string;
  name: string;
  status: string;
  createdAt: number;
  owner: string | null;
  roleId: string;
  tokenTtl: number;
  maxUses: number | null;
  uses: number;
  cidr: string | null;
  expiresAt: number | null;
  firstLoginAt: number | null;
  lastLoginAt: number | null;
  lastIp: string | null;
}

const APP_SELECT = `SELECT i.id, i.name, i.status, i.created_at AS createdAt, o.name AS owner,
  a.role_id AS roleId, a.token_ttl AS tokenTtl, a.max_uses AS maxUses, a.uses, a.cidr,
  a.expires_at AS expiresAt, a.first_login_at AS firstLoginAt, a.last_login_at AS lastLoginAt,
  a.last_ip AS lastIp
  FROM identity i JOIN app_role a ON a.identity_id = i.id LEFT JOIN identity o ON o.id = i.owner_id
  WHERE i.kind = 'app'`;

export const findApp = (db: D1Database, id: string) =>
  db.prepare(`${APP_SELECT} AND i.id = ?`).bind(id).first<AppRow>();
export async function listApps(db: D1Database) {
  return (await db.prepare(`${APP_SELECT} ORDER BY i.name`).all<AppRow>()).results;
}
export async function createApp(
  db: D1Database,
  p: {
    id: string;
    name: string;
    publicKey: string;
    owner: string;
    at: number;
    roleId: string;
    secretHash: string;
    tokenTtl: number;
    maxUses: number | null;
    expiresAt: number | null;
    cidr: string | null;
  },
) {
  await db.batch([
    db
      .prepare(
        "INSERT INTO identity (id, kind, name, role, public_key, owner_id, created_at) VALUES (?, 'app', ?, 'member', ?, ?, ?)",
      )
      .bind(p.id, p.name, p.publicKey, p.owner, p.at),
    db
      .prepare(
        "INSERT INTO app_role (identity_id, role_id, secret_hash, token_ttl, max_uses, expires_at, cidr) VALUES (?, ?, ?, ?, ?, ?, ?)",
      )
      .bind(p.id, p.roleId, p.secretHash, p.tokenTtl, p.maxUses, p.expiresAt, p.cidr),
  ]);
}
export async function appSessions(db: D1Database, id: string, at: number) {
  return (
    await db
      .prepare(
        "SELECT substr(token_hash, 1, 16) AS id, created_at AS createdAt, expires_at AS expiresAt FROM session WHERE identity_id = ? AND expires_at > ? ORDER BY created_at DESC",
      )
      .bind(id, at)
      .all<{ id: string; createdAt: number; expiresAt: number }>()
  ).results;
}
export async function appActivity(db: D1Database, name: string, roleId: string, limit: number) {
  return (
    await db
      .prepare(
        "SELECT entry FROM audit WHERE json_extract(entry, '$.who') IN (?, ?) ORDER BY seq DESC LIMIT ?",
      )
      .bind(name, `app:${roleId}`, limit)
      .all<{ entry: string }>()
  ).results;
}
export async function rotateApp(db: D1Database, hash: string, id: string) {
  await db
    .prepare("UPDATE app_role SET secret_hash = ? WHERE identity_id = ?")
    .bind(hash, id)
    .run();
}
export async function disableApp(db: D1Database, id: string) {
  await db.batch([
    db.prepare("UPDATE identity SET status = 'disabled' WHERE id = ?").bind(id),
    db.prepare("DELETE FROM session WHERE identity_id = ?").bind(id),
  ]);
}
export function findAppRole(db: D1Database, roleId: string) {
  return db
    .prepare(`SELECT a.identity_id, a.secret_hash, a.token_ttl, a.max_uses, a.cidr, a.expires_at, i.name, i.status
     FROM app_role a JOIN identity i ON i.id = a.identity_id WHERE a.role_id = ?`)
    .bind(roleId)
    .first<{
      identity_id: string;
      secret_hash: string;
      token_ttl: number;
      max_uses: number | null;
      cidr: string | null;
      expires_at: number | null;
      name: string;
      status: string;
    }>();
}
export async function claimAppUse(db: D1Database, id: string) {
  return (
    await db
      .prepare(
        "UPDATE app_role SET uses = uses + 1 WHERE identity_id = ? AND (max_uses IS NULL OR uses < max_uses)",
      )
      .bind(id)
      .run()
  ).meta.changes;
}
export async function createAppSession(
  db: D1Database,
  at: number,
  ip: string | null,
  id: string,
  hash: string,
  expiresAt: number,
) {
  await db.batch([
    db
      .prepare(
        "UPDATE app_role SET first_login_at = COALESCE(first_login_at, ?), last_login_at = ?, last_ip = ? WHERE identity_id = ?",
      )
      .bind(at, at, ip, id),
    db
      .prepare(
        "INSERT INTO session (token_hash, identity_id, kind, created_at, expires_at) VALUES (?, ?, 'app', ?, ?)",
      )
      .bind(hash, id, at, expiresAt),
  ]);
}
