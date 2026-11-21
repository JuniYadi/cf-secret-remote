import type { Env } from "./types.ts";

// ADR 20 / ADR 18. Emails ("Was this you?") are out of scope for this change. The routes call this hook
// with ids only, so an email sender can be added later without touching the routes.
export interface RecoveryEvent {
  kind: "requested" | "granted" | "cancelled" | "locked";
  identityId: string;
  requestId: string;
}

// Intentionally empty.
export function notifyRecovery(_env: Env, _event: RecoveryEvent): void {}
