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
  const row = await db
    .prepare(
      `SELECT
         COALESCE(SUM(CASE WHEN m.expires_at IS NOT NULL AND m.expires_at <= ? THEN 1 ELSE 0 END), 0) AS lapsed,
         COALESCE(SUM(CASE WHEN m.expires_at IS NULL OR m.expires_at > ? THEN 1 ELSE 0 END), 0) AS live
       FROM keyring_member m JOIN keyring k ON k.id = m.keyring_id
       WHERE k.prefix = ? AND m.identity_id = ?`,
    )
    .bind(t, t, prefix, identityId)
    .first<{ lapsed: number; live: number }>();
  return !!row && row.lapsed > 0 && row.live === 0;
}
