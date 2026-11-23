import { audit } from "./audit.ts";
import {
  deleteExpiredGrant,
  deleteExpiredMembership,
  deleteRequestPolicy,
  expireRequest,
  listExpiredGrants,
  listExpiredMemberships,
  listStaleRequests,
} from "./repository/requests.ts";

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

  const stale = await listStaleRequests(db, t - REQUEST_TTL);
  for (const r of stale.results) {
    const done = await expireRequest(db, t, r.id);
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

  const grants = await listExpiredGrants(db, t);
  for (const g of grants.results) {
    await deleteExpiredGrant(db, g.identityId, g.policyId, t);
    // Only a policy this module made for a request goes with its grant.
    await deleteRequestPolicy(db, g.policyId);
    result.grants++;
    await audit(db, {
      who: "system",
      action: "policy.expire",
      note: `${g.policyName} for ${g.identity}`,
      result: "ok",
    });
  }

  const keys = await listExpiredMemberships(db, t);
  for (const k of keys.results) {
    await deleteExpiredMembership(db, k.keyringId, k.identityId, k.version, t);
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
