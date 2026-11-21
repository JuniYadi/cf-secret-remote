// The free-tier daily write quota (ADR 19). When a write gets a quota 503, writes pause until the reset
// (Retry-After, 00:00 UTC). Reads keep working. The state lives here so the banner and the Quota screen agree.

/** Used when the server sends no Retry-After. */
export const DEFAULT_QUOTA_WAIT_S = 60;

export interface QuotaState {
  /** Epoch milliseconds when writes may resume. Null when the quota is not reached. */
  resumeAt: number | null;
}

let state: QuotaState = { resumeAt: null };
const listeners = new Set<() => void>();

function emit(): void {
  for (const listener of [...listeners]) listener();
}

/** Records a quota 503 for a write. Called by the API client. */
export function markQuotaReached(retryAfterSeconds: number | null, now = Date.now()): void {
  const wait = retryAfterSeconds ?? DEFAULT_QUOTA_WAIT_S;
  state = { resumeAt: now + wait * 1000 };
  emit();
}

/** True while the quota is reached. Expires on its own once the wait has passed. */
export function quotaActive(now = Date.now()): boolean {
  return state.resumeAt !== null && now < state.resumeAt;
}

export function getQuota(): QuotaState {
  return state;
}

export function subscribeQuota(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Test helper: back to the start state. */
export function resetQuotaForTests(): void {
  state = { resumeAt: null };
}

/** Whole seconds until the writes resume, rounded up. Zero when not reached. */
export function quotaSecondsLeft(now = Date.now()): number {
  if (state.resumeAt === null) return 0;
  return Math.max(0, Math.ceil((state.resumeAt - now) / 1000));
}
