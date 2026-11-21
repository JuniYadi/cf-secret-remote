// Access requests (ADR 16). The approval flow is here so it can be tested without a screen.
//
// The approver's browser unwraps the group key with its own private key, wraps it to the requester's public
// key, and sends only that wrapped value. The group key itself never goes into a request, storage or a log.

import { unwrapGroupKey, wrapGroupKey } from "@cfs/core";

/** Longest grant the Worker accepts, in seconds (24 h). */
export const MAX_REQUEST_SECONDS = 86400;
/** Grant lengths offered in the form, in seconds. */
export const REQUEST_DURATIONS: readonly number[] = [1800, 3600, 7200, 14400, 28800, 86400];
export const MAX_REASON = 500;

/** True for a whole number of seconds from 1 to 24 h, the same bounds the Worker checks. */
export function validDuration(seconds: number): boolean {
  return Number.isInteger(seconds) && seconds >= 1 && seconds <= MAX_REQUEST_SECONDS;
}

export interface RequestDraft {
  path: string;
  reason: string;
  duration: number;
}

export type RequestErrors = Partial<Record<keyof RequestDraft, "path" | "reason" | "duration">>;

/** Field errors for the request form. An empty object means it can be sent. */
export function checkRequest(draft: RequestDraft): RequestErrors {
  const errors: RequestErrors = {};
  const path = draft.path.trim();
  if (path === "" || path.startsWith("/") || path.endsWith("/") || path.includes("//")) {
    errors.path = "path";
  } else {
    const group = path.split("/")[0] ?? "";
    // The group (first segment) must be literal. Globs are allowed after it, as in the Worker.
    if (group.includes("*")) errors.path = "path";
  }
  const reason = draft.reason.trim();
  if (reason === "" || draft.reason.length > MAX_REASON) errors.reason = "reason";
  if (!validDuration(draft.duration)) errors.duration = "duration";
  return errors;
}

/** The group a secret belongs to: its first path segment. Mirrors prefixOf in the Worker. */
export const groupOf = (path: string): string => path.split("/")[0] ?? "";

export interface Approval {
  wrappedKey: string;
  version: number;
}

export interface ApprovalDeps {
  /** GET /keyrings/:prefix/key for the approver. Returns the approver's own wrapped copy. */
  fetchGroupKey: (prefix: string) => Promise<{ wrappedKey: string; version: number }>;
  /** The requester's public key, from GET /identities. */
  requesterPublicKey: (requesterId: string) => Promise<string>;
  /** POST /requests/:id/approve with the wrapped key only. */
  send: (approval: Approval) => Promise<void>;
}

export interface ApproverKeys {
  publicKey: string;
  privateKey: string;
}

/**
 * Approves a request. Unwraps the group key for the approver, wraps it for the requester, and sends the
 * wrapped result. The group key bytes are zeroed when this returns, whether or not the send worked.
 */
export async function approveWithGroupKey(
  request: { requesterId: string; groupPrefix: string },
  keys: ApproverKeys,
  deps: ApprovalDeps,
): Promise<void> {
  const prefix = request.groupPrefix;
  const mine = await deps.fetchGroupKey(prefix);
  const requesterKey = await deps.requesterPublicKey(request.requesterId);
  const groupKey = await unwrapGroupKey(
    mine.wrappedKey,
    keys.privateKey,
    keys.publicKey,
    prefix,
    mine.version,
  );
  try {
    const wrappedKey = await wrapGroupKey(groupKey, requesterKey, prefix, mine.version);
    await deps.send({ wrappedKey, version: mine.version });
  } finally {
    groupKey.fill(0);
  }
}
