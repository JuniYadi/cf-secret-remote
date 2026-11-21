// The unlocked private key lives in this module's variable and nowhere else (ADR 24).
// It is never written to localStorage, sessionStorage, IndexedDB, cookies or the URL, and never logged.
// Lock, sign-out and the idle timer drop the reference.
//
// Idle auto-lock: the warning shows after 14 minutes without activity, and the vault locks at 15.
// Any activity (see watchActivity) restarts both timers.

export const IDLE_LOCK_MS = 15 * 60_000;
export const WARNING_LEAD_MS = 60_000;

export interface UnlockedKeys {
  publicKey: string;
  privateKey: string;
}

export interface KeyStatus {
  unlocked: boolean;
  /** True from 14 minutes of idle time until the activity resets it or the vault locks. */
  warning: boolean;
  /** Epoch milliseconds when the vault locks itself. Null when locked. */
  lockAt: number | null;
}

let keys: UnlockedKeys | null = null;
let warning = false;
let lockAt: number | null = null;
let warnTimer: ReturnType<typeof setTimeout> | undefined;
let lockTimer: ReturnType<typeof setTimeout> | undefined;
const listeners = new Set<() => void>();

function emit(): void {
  for (const listener of [...listeners]) listener();
}

function clearTimers(): void {
  if (warnTimer !== undefined) clearTimeout(warnTimer);
  if (lockTimer !== undefined) clearTimeout(lockTimer);
  warnTimer = undefined;
  lockTimer = undefined;
}

function armTimers(): void {
  clearTimers();
  warning = false;
  lockAt = Date.now() + IDLE_LOCK_MS;
  warnTimer = setTimeout(() => {
    warning = true;
    emit();
  }, IDLE_LOCK_MS - WARNING_LEAD_MS);
  lockTimer = setTimeout(() => lock(), IDLE_LOCK_MS);
}

/** Stores the unlocked keys in memory and starts the idle timer. */
export function unlock(next: UnlockedKeys): void {
  keys = { publicKey: next.publicKey, privateKey: next.privateKey };
  armTimers();
  emit();
}

/** Drops the private key, cancels the timers, and tells subscribers. Safe to call when already locked. */
export function lock(): void {
  clearTimers();
  keys = null;
  warning = false;
  lockAt = null;
  emit();
}

/** Records activity. Restarts the idle timer, and hides the warning if it was showing. */
export function touch(): void {
  if (keys === null) return;
  const wasWarning = warning;
  armTimers();
  if (wasWarning) emit();
}

/** The unlocked private key, or null when locked. Only @cfs/core functions should receive it. */
export function getPrivateKey(): string | null {
  return keys?.privateKey ?? null;
}

export function getPublicKey(): string | null {
  return keys?.publicKey ?? null;
}

export function getStatus(): KeyStatus {
  return { unlocked: keys !== null, warning, lockAt };
}

export function subscribeKeys(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Counts pointer, key, and input events on target as activity. Returns the function that stops it. */
export function watchActivity(target: EventTarget): () => void {
  const events = ["pointerdown", "keydown", "input", "scroll"] as const;
  const onActivity = () => touch();
  for (const name of events) target.addEventListener(name, onActivity, { passive: true });
  return () => {
    for (const name of events) target.removeEventListener(name, onActivity);
  };
}
