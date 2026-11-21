import { useEffect, useState } from "preact/hooks";

export interface Loaded<T> {
  data: T | null;
  error: unknown;
  loading: boolean;
  reload: () => void;
}

/**
 * Runs `load` when the component mounts and whenever `key` changes, and again on reload(). A result that
 * arrives after the key changed is dropped, so a slow answer never overwrites a newer one.
 */
export function useLoad<T>(load: () => Promise<T>, key: string): Loaded<T> {
  const [state, setState] = useState<{ data: T | null; error: unknown; loading: boolean }>({
    data: null,
    error: null,
    loading: true,
  });
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let current = true;
    setState((s) => ({ ...s, loading: true, error: null }));
    load().then(
      (data) => {
        if (current) setState({ data, error: null, loading: false });
      },
      (error: unknown) => {
        if (current) setState({ data: null, error, loading: false });
      },
    );
    return () => {
      current = false;
    };
    // The loader is re-created on each render; only the key and reloads should start a new load.
  }, [key, tick]);

  return { ...state, reload: () => setTick((n) => n + 1) };
}
