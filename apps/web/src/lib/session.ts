// Who is signed in, from GET /whoami. This holds identity and vault status only. It never holds keys.
// The unlocked private key is in keystore.ts.

import { ApiError, api, type Me } from "./api.ts";
import { lock } from "./keystore.ts";

/** Cloudflare Access ends the session at this path on the same hostname (DESIGN.md, sign out). */
export const ACCESS_LOGOUT_PATH = "/cdn-cgi/access/logout";

/** Drops the unlocked key from memory, then ends the Access session. */
export function signOut(): void {
  lock();
  window.location.assign(ACCESS_LOGOUT_PATH);
}

export type SessionPhase = "loading" | "signed-out" | "error" | "ready";

export interface SessionState {
  phase: SessionPhase;
  me: Me | null;
}

let state: SessionState = { phase: "loading", me: null };
const listeners = new Set<() => void>();

function set(next: SessionState): void {
  state = next;
  for (const listener of [...listeners]) listener();
}

export const getSession = (): SessionState => state;

/** Test helper: back to the start state, as on a fresh page load. */
export function resetSessionForTests(): void {
  state = { phase: "loading", me: null };
}

export function subscribeSession(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Loads /whoami. A 401 means the Access session is gone or the person is not invited. */
export async function loadSession(): Promise<void> {
  set({ phase: "loading", me: null });
  try {
    const me = await api.whoami();
    set({ phase: "ready", me });
  } catch (err) {
    if (err instanceof ApiError && err.kind === "unauthorized")
      set({ phase: "signed-out", me: null });
    else set({ phase: "error", me: null });
  }
}

/** Called after POST /vault succeeds, so the guard lets the person on to the recovery step. */
export function markVaultReady(publicKey: string, lockedKey: string): void {
  if (state.me) {
    set({ phase: "ready", me: { ...state.me, vaultReady: true, publicKey, lockedKey } });
  }
}
