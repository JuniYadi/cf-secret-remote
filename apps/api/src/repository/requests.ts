const LIST_LIMIT = 200;
type Status = "pending" | "approved" | "denied" | "cancelled" | "expired";

const RequestCols = `SELECT r.id, r.requester_id AS requesterId, q.name AS requester,
  r.path_glob AS path, r.group_prefix AS groupPrefix, r.reason, r.duration,
  r.rekey_after AS rekeyAfter, r.status, a.name AS approver, r.created_at AS createdAt,
  r.decided_at AS decidedAt, r.expires_at AS expiresAt
  FROM access_request r JOIN identity q ON q.id = r.requester_id
  LEFT JOIN identity a ON a.id = r.approver_id`;

export interface RequestRow {
  id: string;
  requesterId: string;
  requester: string;
  path: string;
  groupPrefix: string;
  reason: string;
  duration: number;
  rekeyAfter: number;
  status: Status;
  approver: string | null;
  createdAt: number;
  decidedAt: number | null;
  expiresAt: number | null;
}

export const loadRequest = (db: D1Database, id: string) =>
  db.prepare(`${RequestCols} WHERE r.id = ?`).bind(id).first<RequestRow>();

export async function listRequests(
  db: D1Database,
  role: string,
  id: string,
  status: string | undefined,
) {
  const where: string[] = [];
  const binds: unknown[] = [];
  if (role !== "admin") {
    where.push("r.requester_id = ?");
    binds.push(id);
  }
  if (status) {
    where.push("r.status = ?");
    binds.push(status);
  }
  const sql = `${RequestCols}${where.length ? ` WHERE ${where.join(" AND ")}` : ""}
    ORDER BY r.created_at DESC LIMIT ${LIST_LIMIT}`;
  const rows = await db
    .prepare(sql)
    .bind(...binds)
    .all<RequestRow>();
  return rows;
}

export function findRequestGroup(db: D1Database, prefix: string) {
  return db
    .prepare("SELECT id FROM keyring WHERE prefix = ? AND personal_owner IS NULL")
    .bind(prefix)
    .first<{ id: string }>();
}

export function cancelRequest(db: D1Database, at: number, id: string) {
  return db
    .prepare(
      "UPDATE access_request SET status = 'cancelled', decided_at = ? WHERE id = ? AND status = 'pending'",
    )
    .bind(at, id)
    .run();
}

export function denyRequest(db: D1Database, approver: string, at: number, id: string) {
  return db
    .prepare(
      "UPDATE access_request SET status = 'denied', approver_id = ?, decided_at = ? WHERE id = ? AND status = 'pending'",
    )
    .bind(approver, at, id)
    .run();
}

export function findRequester(db: D1Database, id: string) {
  return db
    .prepare("SELECT status FROM identity WHERE id = ?")
    .bind(id)
    .first<{ status: string }>();
}

export async function createRequest(
  db: D1Database,
  id: string,
  requesterId: string,
  path: string,
  prefix: string,
  reason: string,
  duration: number,
  rekeyAfter: number,
  at: number,
) {
  await db
    .prepare(
      `INSERT INTO access_request (id, requester_id, path_glob, group_prefix, reason, duration,
         rekey_after, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)`,
    )
    .bind(id, requesterId, path, prefix, reason, duration, rekeyAfter, at)
    .run();
}

export async function approveRequest(
  db: D1Database,
  request: RequestRow,
  approver: string,
  at: number,
  expiresAt: number,
  policyId: string,
  group: { id: string; version: number },
  wrappedKey: string,
) {
  const guard = `EXISTS (SELECT 1 FROM access_request WHERE id = ? AND status = 'approved' AND approver_id = ? AND decided_at = ?)`;
  const guardBinds = [request.id, approver, at];
  const rules = JSON.stringify([{ path: request.path, caps: ["read", "list"] }]);
  return db.batch([
    db
      .prepare(
        `UPDATE access_request SET status = 'approved', approver_id = ?, decided_at = ?, expires_at = ?
         WHERE id = ? AND status = 'pending'
         AND EXISTS (SELECT 1 FROM keyring WHERE id = ? AND version = ? AND status = 'active')`,
      )
      .bind(approver, at, expiresAt, request.id, group.id, group.version),
    db
      .prepare(`INSERT INTO policy (id, name, rules) SELECT ?, ?, ? WHERE ${guard}`)
      .bind(policyId, `request:${request.id}`, rules, ...guardBinds),
    db
      .prepare(
        `INSERT INTO identity_policy (identity_id, policy_id, expires_at) SELECT ?, ?, ? WHERE ${guard}`,
      )
      .bind(request.requesterId, policyId, expiresAt, ...guardBinds),
    // A permanent membership is left alone. A lapsed or missing one is replaced by the time-boxed key.
    db
      .prepare(
        `INSERT OR IGNORE INTO keyring_member (keyring_id, identity_id, version, wrapped_key, expires_at)
         SELECT ?, ?, ?, ?, ? WHERE ${guard}`,
      )
      .bind(group.id, request.requesterId, group.version, wrappedKey, expiresAt, ...guardBinds),
    db
      .prepare(
        `UPDATE keyring_member SET wrapped_key = ?, expires_at = ?
         WHERE keyring_id = ? AND identity_id = ? AND version = ? AND expires_at IS NOT NULL AND ${guard}`,
      )
      .bind(wrappedKey, expiresAt, group.id, request.requesterId, group.version, ...guardBinds),
  ]);
}

export function listStaleRequests(db: D1Database, before: number) {
  return db
    .prepare(
      `SELECT r.id, r.path_glob AS path, i.name AS requester FROM access_request r
       JOIN identity i ON i.id = r.requester_id
       WHERE r.status = 'pending' AND r.created_at <= ?`,
    )
    .bind(before)
    .all<{ id: string; path: string; requester: string }>();
}

export function expireRequest(db: D1Database, at: number, id: string) {
  return db
    .prepare(
      "UPDATE access_request SET status = 'expired', decided_at = ? WHERE id = ? AND status = 'pending'",
    )
    .bind(at, id)
    .run();
}

export function listExpiredGrants(db: D1Database, at: number) {
  return db
    .prepare(
      `SELECT ip.identity_id AS identityId, ip.policy_id AS policyId, p.name AS policyName,
              i.name AS identity FROM identity_policy ip
       JOIN policy p ON p.id = ip.policy_id JOIN identity i ON i.id = ip.identity_id
       WHERE ip.expires_at IS NOT NULL AND ip.expires_at <= ?`,
    )
    .bind(at)
    .all<{ identityId: string; policyId: string; policyName: string; identity: string }>();
}

export function deleteExpiredGrant(
  db: D1Database,
  identityId: string,
  policyId: string,
  at: number,
) {
  return db
    .prepare(
      "DELETE FROM identity_policy WHERE identity_id = ? AND policy_id = ? AND expires_at <= ?",
    )
    .bind(identityId, policyId, at)
    .run();
}

export function deleteRequestPolicy(db: D1Database, policyId: string) {
  return db
    .prepare(
      `DELETE FROM policy WHERE id = ? AND name LIKE 'request:%'
         AND NOT EXISTS (SELECT 1 FROM identity_policy WHERE policy_id = ?)`,
    )
    .bind(policyId, policyId)
    .run();
}

export function listExpiredMemberships(db: D1Database, at: number) {
  return db
    .prepare(
      `SELECT k.prefix AS prefix, i.name AS identity, m.identity_id AS identityId,
              m.keyring_id AS keyringId, m.version AS version
       FROM keyring_member m JOIN keyring k ON k.id = m.keyring_id
       JOIN identity i ON i.id = m.identity_id
       WHERE m.expires_at IS NOT NULL AND m.expires_at <= ?`,
    )
    .bind(at)
    .all<{
      prefix: string;
      identity: string;
      identityId: string;
      keyringId: string;
      version: number;
    }>();
}

export function deleteExpiredMembership(
  db: D1Database,
  keyringId: string,
  identityId: string,
  version: number,
  at: number,
) {
  return db
    .prepare(
      "DELETE FROM keyring_member WHERE keyring_id = ? AND identity_id = ? AND version = ? AND expires_at <= ?",
    )
    .bind(keyringId, identityId, version, at)
    .run();
}
