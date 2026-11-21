import { audit } from "./audit.ts";

// ADR 16. The daily sweep, called from runDaily (cron.ts). It ends lapsed grants and pending requests.
// Audit rows name identities, groups and paths only.

/** A pending request auto-expires this many seconds after it was created (24 h). */
export const REQUEST_TTL = 86400;

export interface SweepResult {
  requests: number;
  grants: number;
  memberships: number;
}

/** Ends pending requests older than REQUEST_TTL, removes lapsed policy grants and lapsed group keys. `t` is unix seconds. */
export async function sweepExpiredRequests(db: D1Database, t: number): Promise<SweepResult> {
  const result: SweepResult = { requests: 0, grants: 0, memberships: 0 };

  const stale = await db
    .prepare(
      `SELECT r.id, r.path_glob AS path, i.name AS requester FROM access_request r
       JOIN identity i ON i.id = r.requester_id
       WHERE r.status = 'pending' AND r.created_at <= ?`,
    )
    .bind(t - REQUEST_TTL)
    .all<{ id: string; path: string; requester: string }>();
  for (const r of stale.results) {
    const done = await db
      .prepare(
        "UPDATE access_request SET status = 'expired', decided_at = ? WHERE id = ? AND status = 'pending'",
      )
      .bind(t, r.id)
      .run();
    if (done.meta.changes !== 1) continue;
    result.requests++;
    await audit(db, {
      who: "system",
      action: "request.expire",
      path: r.path,
      note: `request ${r.id} by ${r.requester}`,
      result: "ok",
    });
  }

  const grants = await db
    .prepare(
      `SELECT ip.identity_id AS identityId, ip.policy_id AS policyId, p.name AS policyName,
              i.name AS identity FROM identity_policy ip
       JOIN policy p ON p.id = ip.policy_id JOIN identity i ON i.id = ip.identity_id
       WHERE ip.expires_at IS NOT NULL AND ip.expires_at <= ?`,
    )
    .bind(t)
    .all<{ identityId: string; policyId: string; policyName: string; identity: string }>();
  for (const g of grants.results) {
    await db
      .prepare(
        "DELETE FROM identity_policy WHERE identity_id = ? AND policy_id = ? AND expires_at <= ?",
      )
      .bind(g.identityId, g.policyId, t)
      .run();
    // Only a policy this module made for a request goes with its grant.
    await db
      .prepare(
        `DELETE FROM policy WHERE id = ? AND name LIKE 'request:%'
         AND NOT EXISTS (SELECT 1 FROM identity_policy WHERE policy_id = ?)`,
      )
      .bind(g.policyId, g.policyId)
      .run();
    result.grants++;
    await audit(db, {
      who: "system",
      action: "policy.expire",
      note: `${g.policyName} for ${g.identity}`,
      result: "ok",
    });
  }

  const keys = await db
    .prepare(
      `SELECT k.prefix AS prefix, i.name AS identity, m.identity_id AS identityId,
              m.keyring_id AS keyringId, m.version AS version
       FROM keyring_member m JOIN keyring k ON k.id = m.keyring_id
       JOIN identity i ON i.id = m.identity_id
       WHERE m.expires_at IS NOT NULL AND m.expires_at <= ?`,
    )
    .bind(t)
    .all<{
      prefix: string;
      identity: string;
      identityId: string;
      keyringId: string;
      version: number;
    }>();
  for (const k of keys.results) {
    await db
      .prepare(
        "DELETE FROM keyring_member WHERE keyring_id = ? AND identity_id = ? AND version = ? AND expires_at <= ?",
      )
      .bind(k.keyringId, k.identityId, k.version, t)
      .run();
    result.memberships++;
    await audit(db, {
      who: "system",
      action: "group.member.expire",
      path: k.prefix,
      version: k.version,
      note: k.identity,
      result: "ok",
    });
  }

  return result;
}
