import type { Who } from "../types.ts";

export function findSession(db: D1Database, hash: string, at: number) {
  return db
    .prepare(`SELECT i.id, i.kind, i.name, i.role, s.last_used_at AS lastUsedAt
         FROM session s JOIN identity i ON i.id = s.identity_id
         WHERE s.token_hash = ? AND s.expires_at > ? AND i.status = 'active'`)
    .bind(hash, at)
    .first<Who & { lastUsedAt: number | null }>();
}
export async function stampSession(db: D1Database, at: number, hash: string) {
  await db.prepare("UPDATE session SET last_used_at = ? WHERE token_hash = ?").bind(at, hash).run();
}
export function findUser(db: D1Database, email: string) {
  return db
    .prepare("SELECT id, kind, name, role, status FROM identity WHERE kind = 'user' AND name = ?")
    .bind(email)
    .first<Who & { status: string }>();
}
export async function insertBootstrapUser(db: D1Database, id: string, email: string, at: number) {
  await db
    .prepare(
      "INSERT INTO identity (id, kind, name, role, created_at) VALUES (?, 'user', ?, 'admin', ?)",
    )
    .bind(id, email, at)
    .run();
}
export async function startCliLogin(
  db: D1Database,
  hash: string,
  code: string,
  device: string,
  expiresAt: number,
  deviceType: string,
) {
  await db
    .prepare(
      "INSERT INTO cli_login (device_hash, user_code, device, expires_at, device_type) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(hash, code, device, expiresAt, deviceType)
    .run();
}
export function findCliLogin(db: D1Database, hash: string) {
  return db
    .prepare(
      "SELECT l.status, l.identity_id, l.device, l.expires_at, i.name FROM cli_login l LEFT JOIN identity i ON i.id = l.identity_id WHERE l.device_hash = ?",
    )
    .bind(hash)
    .first<{
      status: string;
      identity_id: string | null;
      device: string;
      expires_at: number;
      name: string | null;
    }>();
}
export async function claimCliLogin(db: D1Database, hash: string) {
  return (
    await db
      .prepare("UPDATE cli_login SET status = 'used' WHERE device_hash = ? AND status = 'approved'")
      .bind(hash)
      .run()
  ).meta.changes;
}
export async function createCliSession(
  db: D1Database,
  hash: string,
  id: string,
  device: string,
  at: number,
  expiresAt: number,
) {
  await db
    .prepare(
      "INSERT INTO session (token_hash, identity_id, kind, device, created_at, expires_at) VALUES (?, ?, 'cli', ?, ?, ?)",
    )
    .bind(hash, id, device, at, expiresAt)
    .run();
}
export function findPendingCliLogin(db: D1Database, code: string, at: number) {
  return db
    .prepare(
      "SELECT device, device_type AS deviceType, expires_at AS expiresAt FROM cli_login WHERE user_code = ? AND status = 'pending' AND expires_at > ?",
    )
    .bind(code, at)
    .first<{ device: string; deviceType: string; expiresAt: number }>();
}
export async function approveCliLogin(db: D1Database, id: string, code: string, at: number) {
  return (
    await db
      .prepare(
        "UPDATE cli_login SET status = 'approved', identity_id = ? WHERE user_code = ? AND status = 'pending' AND expires_at > ?",
      )
      .bind(id, code, at)
      .run()
  ).meta.changes;
}
