// Loads one secret version for a screen: fetch the sealed version, then open it with the group key.
// Every failure becomes a status the screen can show, so no screen has to read errors itself.

import { useCallback, useEffect, useState } from "preact/hooks";
import { ApiError, type SecretRecord } from "./api.ts";
import { fetchSecret, type OpenedSecret, openFetched } from "./secret-store.ts";

export type SecretState =
  | { status: "loading" }
  | { status: "ready"; secret: OpenedSecret; record: SecretRecord }
  /** The person can read the secret but has no group key, so values stay locked (ADR 2). */
  | { status: "nokey"; record: SecretRecord }
  /** The group key has lapsed (a time-boxed grant, ADR 16). */
  | { status: "expired" }
  | { status: "denied" }
  | { status: "missing" }
  | { status: "error" };

/** Maps a failed load to a state. Exported for tests. */
export function stateForError(err: unknown): SecretState {
  if (err instanceof ApiError) {
    if (err.kind === "forbidden") return { status: "denied" };
    if (err.kind === "not-found") return { status: "missing" };
  }
  return { status: "error" };
}

/**
 * Loads a secret version (the current one when `version` is omitted). `reload` runs it again, for example
 * after a 409 on save. With `enabled` false nothing is fetched and the state stays "loading".
 */
export function useSecret(
  path: string,
  version?: number,
  enabled = true,
): { state: SecretState; reload: () => void } {
  const [state, setState] = useState<SecretState>({ status: "loading" });
  const [token, setToken] = useState(0);
  const reload = useCallback(() => setToken((n) => n + 1), []);

  useEffect(() => {
    if (!enabled) return;
    let live = true;
    setState({ status: "loading" });
    (async () => {
      let record: SecretRecord;
      try {
        record = await fetchSecret(path, version);
      } catch (err) {
        if (live) setState(stateForError(err));
        return;
      }
      try {
        const secret = await openFetched(record);
        if (live) setState({ status: "ready", secret, record });
      } catch (err) {
        if (!live) return;
        if (err instanceof ApiError && err.kind === "not-found") {
          setState({ status: "nokey", record });
        } else if (err instanceof ApiError && err.kind === "forbidden") {
          setState({ status: "expired" });
        } else {
          setState({ status: "error" });
        }
      }
    })();
    return () => {
      live = false;
    };
  }, [path, version, token, enabled]);

  return { state, reload };
}
