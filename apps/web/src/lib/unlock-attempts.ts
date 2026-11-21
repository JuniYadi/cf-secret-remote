// Wrong vault password attempts, counted in the browser (ADR 20). The server cannot see them.
// After MAX_TRIES wrong passwords the Unlock screen waits COOLDOWN_MS before the next try.

export const MAX_TRIES = 5;
export const COOLDOWN_MS = 60_000;

export interface AttemptState {
  failures: number;
  /** Epoch milliseconds when the next try is allowed. Null when there is no wait. */
  lockedUntil: number | null;
}

export const NO_ATTEMPTS: AttemptState = { failures: 0, lockedUntil: null };

export function recordFailure(state: AttemptState, now: number): AttemptState {
  const failures = state.failures + 1;
  if (failures >= MAX_TRIES) return { failures: 0, lockedUntil: now + COOLDOWN_MS };
  return { failures, lockedUntil: null };
}

export const triesLeft = (state: AttemptState): number => MAX_TRIES - state.failures;

/** Whole seconds left in the wait, rounded up. Zero when the person may try again. */
export function cooldownSeconds(state: AttemptState, now: number): number {
  const remaining = (state.lockedUntil ?? 0) - now;
  return remaining > 0 ? Math.ceil(remaining / 1000) : 0;
}
