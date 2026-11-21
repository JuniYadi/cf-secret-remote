import type { ComponentChildren } from "preact";
import { useEffect, useState } from "preact/hooks";
import { ApiError } from "../lib/api.ts";
import { RotationError, VaultLockedError } from "../lib/groups.ts";
import { useLang } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";

/** Pill tones match the boards: plain, teal (acc), green (ok), amber (warn), red (bad). */
export type Tone = "" | "acc" | "ok" | "warn" | "bad";

export function Pill({ tone = "", children }: { tone?: Tone; children: ComponentChildren }) {
  return <span class={`pill ${tone}`.trim()}>{children}</span>;
}

/** A banner: amber for things to notice, teal for explanations, red for failures. Text carries the meaning. */
export function Notice({
  tone = "warn",
  title,
  children,
}: {
  tone?: "warn" | "info" | "danger";
  title?: string;
  children: ComponentChildren;
}) {
  return (
    <div class={`notice ${tone}`} role={tone === "danger" ? "alert" : undefined}>
      <span>
        {title && <b>{title} </b>}
        {children}
      </span>
    </div>
  );
}

/** Advanced details, closed by default (DESIGN.md: names and identifiers live in "Technical details"). */
export function TechDetails({ children }: { children: ComponentChildren }) {
  useLang();
  return (
    <details class="tech admin-tech">
      <summary>{t("Technical details", "Detail teknis")}</summary>
      <div class="code">{children}</div>
    </details>
  );
}

/** The message for a failed call. Never the response body. */
export function failureText(err: unknown): string {
  if (err instanceof VaultLockedError)
    return t(
      "Unlock your vault first. This needs your key, and it stays in your browser.",
      "Buka vault-mu dulu. Ini butuh kunci-mu, dan kunci itu tetap di browsermu.",
    );
  if (err instanceof RotationError)
    return t(
      "Locking didn't finish. The person you removed can no longer open this group, but the values are still under the old key.",
      "Pengunciannya belum selesai. Orang yang kamu keluarkan tidak bisa lagi membuka grup ini, tetapi nilainya masih memakai kunci lama.",
    );
  if (err instanceof ApiError) {
    switch (err.kind) {
      case "network":
        return t(
          "We couldn't reach the server. Check your connection and try again.",
          "Kami tidak bisa menghubungi server. Periksa koneksi lalu coba lagi.",
        );
      case "forbidden":
        return t(
          "Your access doesn't allow this. Ask an admin.",
          "Aksesmu tidak mengizinkan ini. Minta admin.",
        );
      case "conflict":
        return t(
          "This changed while you were working. Reload and try again.",
          "Ini berubah saat kamu bekerja. Muat ulang lalu coba lagi.",
        );
      case "not-found":
        return t("We couldn't find that.", "Kami tidak menemukannya.");
      case "rate-limited":
        return t("Too many tries. Wait a minute.", "Terlalu sering mencoba. Tunggu sebentar.");
      case "unavailable":
        return t(
          "The server is busy right now. Try again later.",
          "Server sedang sibuk. Coba lagi nanti.",
        );
      default:
        return t("Something went wrong. Try again.", "Terjadi kesalahan. Coba lagi.");
    }
  }
  return t("Something went wrong. Try again.", "Terjadi kesalahan. Coba lagi.");
}

export interface LoadState<T> {
  data: T | null;
  error: unknown;
  loading: boolean;
  reload: () => void;
}

/**
 * Runs `load` on mount and whenever `key` changes. A stale answer is ignored after the key changes or the
 * component unmounts, so a slow request never overwrites a newer one.
 */
export function useLoad<T>(load: () => Promise<T>, key: string): LoadState<T> {
  const [state, setState] = useState<{ data: T | null; error: unknown; loading: boolean }>({
    data: null,
    error: null,
    loading: true,
  });
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let live = true;
    setState((s) => ({ ...s, loading: true, error: null }));
    load().then(
      (data) => {
        if (live) setState({ data, error: null, loading: false });
      },
      (error: unknown) => {
        if (live) setState({ data: null, error, loading: false });
      },
    );
    return () => {
      live = false;
    };
    // `load` is recreated on every render; the key and the reload counter decide when to run again.
  }, [key, tick]);
  return { ...state, reload: () => setTick((n) => n + 1) };
}

/** Loading or failure for a list page. Returns null when data is ready. */
export function LoadStatus({
  state,
}: {
  state: { loading: boolean; error: unknown; reload: () => void };
}) {
  useLang();
  if (state.loading)
    return (
      <p class="note" role="status">
        {t("Loading...", "Memuat...")}
      </p>
    );
  if (state.error)
    return (
      <Notice tone="danger">
        {failureText(state.error)}{" "}
        <button type="button" class="link-btn" onClick={state.reload}>
          {t("Try again", "Coba lagi")}
        </button>
      </Notice>
    );
  return null;
}

/** Human date, from epoch seconds. Falls back to a dash for empty values. */
export function formatWhen(sec: number | null | undefined): string {
  if (sec === null || sec === undefined || sec === 0) return "—";
  return new Date(sec * 1000).toLocaleString(undefined, {
    day: "numeric",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}
