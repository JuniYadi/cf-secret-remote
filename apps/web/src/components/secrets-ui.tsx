// Parts shared by the secrets screens: the Show/Hide timer, the Copy button, the secret tabs and the pills.
// The values never leave this file's callers except through the copy helper (clipboard.ts).

import type { ComponentChildren } from "preact";
import { useEffect, useState } from "preact/hooks";
import { Link } from "wouter-preact";
import { CLIPBOARD_CLEAR_MS, copyWithAutoClear } from "../lib/clipboard.ts";
import { t } from "../lib/i18n.ts";
import { isRevealed, revealDeadline } from "../lib/reveal.ts";
import { SECRET_TABS, secretHref } from "../routes.ts";
import "../styles/secrets.css";

/** The dots shown instead of a value. Fixed length, so the dots do not hint at the value's length. */
export const MASK = "••••••••••••";

/** Show/Hide for one value. A shown value hides itself after 30 seconds (ADR 24). */
export function useReveal(): { shown: boolean; show: () => void; hide: () => void } {
  const [deadline, setDeadline] = useState<number | null>(null);
  useEffect(() => {
    if (deadline === null) return;
    const id = setTimeout(() => setDeadline(null), Math.max(0, deadline - Date.now()));
    return () => clearTimeout(id);
  }, [deadline]);
  return {
    shown: isRevealed(deadline, Date.now()),
    show: () => setDeadline(revealDeadline(Date.now())),
    hide: () => setDeadline(null),
  };
}

/** Copies a value and says so. The clipboard clears after 30 seconds if it still holds the value. */
export function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    const ok = await copyWithAutoClear(text);
    setCopied(ok);
  };
  return (
    <>
      <button type="button" class="btn ghost sm" onClick={onCopy}>
        {label}
      </button>
      {copied && (
        <span class="copy-note" role="status">
          {t(
            `Copied. The clipboard clears in ${CLIPBOARD_CLEAR_MS / 1000} seconds.`,
            `Tersalin. Papan klip dibersihkan dalam ${CLIPBOARD_CLEAR_MS / 1000} detik.`,
          )}
        </span>
      )}
    </>
  );
}

/** The three tabs of a secret. The active one is the page the person is on. */
export function SecretTabs({
  name,
  active,
}: {
  name: string;
  active: "values" | "versions" | "history";
}) {
  const tabs = [
    { id: "values" as const, href: secretHref(name), label: t("Values", "Nilai") },
    {
      id: "versions" as const,
      href: `${secretHref(name)}${SECRET_TABS.versions}`,
      label: t("Versions", "Versi"),
    },
    {
      id: "history" as const,
      href: `${secretHref(name)}${SECRET_TABS.history}`,
      label: t("Access history", "Riwayat akses"),
    },
  ];
  return (
    <nav class="tabs" aria-label={t("Secret sections", "Bagian secret")}>
      {tabs.map((tab) => (
        <Link
          key={tab.id}
          href={tab.href}
          class={tab.id === active ? "on" : ""}
          aria-current={tab.id === active ? "page" : undefined}
        >
          {tab.label}
        </Link>
      ))}
    </nav>
  );
}

export type PillTone = "" | "ok" | "acc" | "warn" | "bad" | "add" | "chg" | "rem";

export function Pill({ tone = "", children }: { tone?: PillTone; children: ComponentChildren }) {
  return <span class={tone ? `pill ${tone}` : "pill"}>{children}</span>;
}

/** Human text for a value type, as on the boards. */
export function typeLabel(type: "text" | "boolean" | "number"): string {
  if (type === "boolean") return t("True / false", "Benar / salah");
  if (type === "number") return t("Number", "Angka");
  return t("Text", "Teks");
}

/** The one-line note under a page, as on the boards (a soft teal box). */
export function InfoBox({ children }: { children: ComponentChildren }) {
  return (
    <div class="info-box" role="note">
      <svg
        width="16"
        height="16"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
        aria-hidden="true"
        focusable="false"
      >
        <path d="M5 11h14v10H5z M8 11V7a4 4 0 0 1 8 0v4" />
      </svg>
      <span>{children}</span>
    </div>
  );
}

/** The amber warning box (leaked values, locked group). Its text is announced, not coloured. */
export function WarnBox({ children }: { children: ComponentChildren }) {
  return <div class="warn-box">{children}</div>;
}
