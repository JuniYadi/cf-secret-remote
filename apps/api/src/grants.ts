import { grantCounts } from "./repository/keyrings.ts";

// ADR 16. Time-boxed group grants. A grant lapses when its keyring_member row has expires_at in the past.

/**
 * True when the identity held a time-boxed key for the group and none is still live.
 * Admins and members with permanent keys are never lapsed. Used to refuse ciphertext after expiry.
 */
export async function lapsedGrant(
  db: D1Database,
  identityId: string,
  prefix: string,
  t: number,
): Promise<boolean> {
  const row = await grantCounts(db, identityId, prefix, t);
  return !!row && row.lapsed > 0 && row.live === 0;
}
