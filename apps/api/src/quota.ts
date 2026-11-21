// ADR 19: free-tier quota. D1 write errors at the daily limit become 503 with Retry-After until 00:00 UTC.

export const FREE_WRITES_PER_DAY = 100_000;
export const WARN_AT_WRITES = Math.floor(FREE_WRITES_PER_DAY * 0.8);

/** True when a D1 error is the daily quota or limit being exceeded. */
export function isQuotaError(e: unknown): boolean {
  const msg = e instanceof Error ? e.message : String(e);
  return /quota|exceeded.*limit|daily.*limit/i.test(msg);
}

/** Seconds from `t` (unix seconds) until the next 00:00 UTC. */
export function retryAfterSeconds(t: number): number {
  const d = new Date(t * 1000);
  const next = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1) / 1000;
  return Math.max(1, next - t);
}

/** UTC calendar day for unix seconds `t`, as YYYY-MM-DD. */
export const dayOf = (t: number) => new Date(t * 1000).toISOString().slice(0, 10);
