// Offboarding's group removal (ADR 21). It is the Groups part's staged re-key (lib/groups.ts, ADR 14) with the
// same checks: the removed person must be a member, every staying person needs a public key, and the caller
// opens the old group key first. Only @cfs/core does the cryptography; this file only sequences the calls.

import type { api as realApi, SecretListRow } from "./api.ts";
import {
  groupSecrets,
  openMyGroupKey,
  planRemoval,
  type RelockProgress,
  runRotation,
} from "./groups.ts";

/** Why a removal was refused before anything changed on the server. */
export class RemovalError extends Error {
  readonly reason: "self" | "notMember" | "noKey";
  /** For "noKey": the staying person who has no vault key yet. */
  readonly person: string | undefined;

  constructor(reason: RemovalError["reason"], person?: string) {
    super(reason);
    this.name = "RemovalError";
    this.reason = reason;
    this.person = person;
  }
}

/**
 * Removes `removeIdentityId` from the group `prefix` and re-keys it (ADR 14). The server ends the removed
 * person's access at start. Each live secret of the group is re-sealed under the new key, in chunks, then the
 * rotation is committed. A failure after start aborts it (see runRotation).
 *
 * `myId` is the caller, who must stay in the group. `client` is injectable for tests.
 */
export async function removeMemberFromGroup(
  prefix: string,
  removeIdentityId: string,
  myId: string,
  client: typeof realApi,
): Promise<{ count: number; progress: RelockProgress }> {
  const [members, identities, all] = await Promise.all([
    client.keyringMembers(prefix),
    client.identities(),
    client.secrets(),
  ]);
  const plan = planRemoval(members, identities, removeIdentityId, myId);
  if (!plan.ok) throw new RemovalError(plan.reason, plan.name);

  const { key, version } = await openMyGroupKey(prefix, client);
  const secrets: SecretListRow[] = groupSecrets(all, prefix);
  const progress = await runRotation(
    {
      prefix,
      currentVersion: version,
      removeIdentityId,
      remaining: plan.remaining,
      oldKey: key,
      secrets,
    },
    client,
  );
  return { count: secrets.length, progress };
}
