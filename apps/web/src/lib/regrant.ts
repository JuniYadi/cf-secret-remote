// "Give access again" (ADR 20): the admin's browser re-wraps each group key the person used to be in, to the
// person's new public key. Only a group the admin holds can be re-wrapped; the server checks the same.

import { unwrapGroupKey, wrapGroupKey } from "@cfs/core";
import { ApiError, type RecoveryDetail } from "./api.ts";

/** The caller's wrapped copy of a group key at one version (ADR 14). */
interface GroupKeyResponse {
  wrappedKey: string;
  version: number;
}

export interface RegrantKey {
  prefix: string;
  version: number;
  wrappedKey: string;
}

export interface RegrantDeps {
  groupKey: (prefix: string) => Promise<GroupKeyResponse>;
}

/**
 * Re-wraps the group keys for the person's new public key. Groups the admin is not in are left out and
 * listed, so another admin can grant them. Nothing is sent to the server here; the caller posts the result.
 */
export async function regrantKeys(
  deps: RegrantDeps,
  req: Pick<RecoveryDetail, "groups" | "publicKey">,
  admin: { privateKey: string; publicKey: string },
): Promise<{ keys: RegrantKey[]; notRewrapped: string[] }> {
  const keys: RegrantKey[] = [];
  const notRewrapped: string[] = [];
  for (const prefix of req.groups) {
    let mine: GroupKeyResponse;
    try {
      mine = await deps.groupKey(prefix);
    } catch (err) {
      if (err instanceof ApiError && err.kind === "not-found") {
        notRewrapped.push(prefix);
        continue;
      }
      throw err;
    }
    const groupKey = await unwrapGroupKey(
      mine.wrappedKey,
      admin.privateKey,
      admin.publicKey,
      prefix,
      mine.version,
    );
    keys.push({
      prefix,
      version: mine.version,
      wrappedKey: await wrapGroupKey(groupKey, req.publicKey, prefix, mine.version),
    });
  }
  return { keys, notRewrapped };
}
