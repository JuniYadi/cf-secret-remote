import { useEffect, useReducer } from "preact/hooks";
import { currentLang, type Lang, subscribeLang } from "./i18n.ts";
import { getStatus, type KeyStatus, subscribeKeys } from "./keystore.ts";
import { getSession, type SessionState, subscribeSession } from "./session.ts";

/** Re-renders the component when a store changes. The store is read again on every render. */
function useStore(subscribe: (listener: () => void) => () => void): void {
  const [, bump] = useReducer((n: number) => n + 1, 0);
  useEffect(() => subscribe(() => bump(0)), [subscribe]);
}

export function useLang(): Lang {
  useStore(subscribeLang);
  return currentLang();
}

export function useSession(): SessionState {
  useStore(subscribeSession);
  return getSession();
}

export function useKeyStatus(): KeyStatus {
  useStore(subscribeKeys);
  return getStatus();
}
