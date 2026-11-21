// Small parts shared by the ADR 24 part 5 screens: settings tabs, API error notes, the quota banner.
import type { ComponentChildren } from "preact";
import { useEffect, useState } from "preact/hooks";
import { Link } from "wouter-preact";
import { ApiError } from "../lib/api.ts";
import { useLang } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { quotaActive, quotaSecondsLeft, subscribeQuota } from "../lib/quota.ts";
import { PATHS } from "../routes.ts";
import { Icon } from "./shared.tsx";

/** The General / Admins / Backup tabs on the Settings pages (design boards Settings, Settings-Admins). */
export function SettingsTabs({ current }: { current: "general" | "admins" | "backup" }) {
  useLang();
  const tabs = [
    { id: "general", href: PATHS.settings, label: t("General", "Umum") },
    { id: "admins", href: PATHS.settingsAdmins, label: t("Admins", "Admin") },
    { id: "backup", href: PATHS.settingsBackup, label: t("Backup", "Cadangan") },
  ] as const;
  return (
    <nav class="tabs" aria-label={t("Settings tabs", "Tab pengaturan")}>
      {tabs.map((tab) => (
        <Link
          key={tab.id}
          href={tab.href}
          class={tab.id === current ? "tab on" : "tab"}
          aria-current={tab.id === current ? "page" : undefined}
        >
          {tab.label}
        </Link>
      ))}
    </nav>
  );
}

/** One line of text for a failed load or action. Maps the kind; the server's message is never shown. */
export function ErrorNote({ error }: { error: unknown }) {
  useLang();
  if (!error) return null;
  const kind = error instanceof ApiError ? error.kind : "other";
  const text = (() => {
    switch (kind) {
      case "forbidden":
        return t("Only admins can do this.", "Hanya admin yang bisa melakukan ini.");
      case "unauthorized":
        return t("Your session ended. Sign in again.", "Sesimu berakhir. Masuk lagi.");
      case "network":
        return t(
          "We couldn't reach the server. Check your connection and try again.",
          "Kami tidak bisa menghubungi server. Periksa koneksi lalu coba lagi.",
        );
      case "not-found":
        return t("We couldn't find that anymore.", "Kami tidak menemukannya lagi.");
      case "conflict":
        return t(
          "This changed while you were looking. Reload and try again.",
          "Ini berubah saat kamu melihatnya. Muat ulang lalu coba lagi.",
        );
      case "maintenance":
        return t(
          "A restore is running. Try again in a minute.",
          "Pemulihan sedang berjalan. Coba lagi sebentar lagi.",
        );
      case "quota":
        return t(
          "Saving is paused until 00:00 UTC. Opening secrets still works.",
          "Penyimpanan dijeda sampai pukul 00:00 UTC. Membuka secret tetap berjalan.",
        );
      case "rate-limited":
        return t("Too many tries. Wait a moment.", "Terlalu banyak percobaan. Tunggu sebentar.");
      default:
        return t("Something went wrong. Try again.", "Ada yang salah. Coba lagi.");
    }
  })();
  return (
    <p class="field-error" role="alert">
      {text}
    </p>
  );
}

/** A label and a value, as a definition list row. */
export function KeyRow({ label, children }: { label: string; children: ComponentChildren }) {
  return (
    <div class="kv-row">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

/** A thin meter for a count against a limit. The number is written out, so colour is not the only cue. */
export function Meter({ label, value, max }: { label: string; value: number; max: number }) {
  const pct = max > 0 ? Math.min(100, Math.round((value / max) * 100)) : 0;
  return (
    <div class="usage-row">
      <div class="usage-head">
        <span>{label}</span>
        <span class="mono">
          {value.toLocaleString("en-US")} / {max.toLocaleString("en-US")}
        </span>
      </div>
      <div class="usage-bar" role="img" aria-label={`${pct}%`}>
        <i style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

/** Re-renders when the quota state changes, and once a second while it is active (for the countdown). */
export function useQuota(): { active: boolean; secondsLeft: number } {
  const [, bump] = useState(0);
  const active = quotaActive();
  useEffect(() => subscribeQuota(() => bump((n) => n + 1)), []);
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => bump((n) => n + 1), 1000);
    return () => clearInterval(id);
  }, [active]);
  return { active, secondsLeft: quotaSecondsLeft() };
}

/** Shown at the top of every shell page while the free-tier quota is reached (ADR 19). Reads keep working. */
export function QuotaBanner() {
  useLang();
  const { active } = useQuota();
  if (!active) return null;
  return (
    <div class="quota-banner" role="status">
      <Icon name="warning" size={18} />
      <div>
        <b>{t("Free plan limit reached for today", "Batas paket gratis hari ini tercapai")}</b>{" "}
        <span>
          {t(
            "Saving is paused until 00:00 UTC. Opening secrets still works.",
            "Penyimpanan dijeda sampai pukul 00:00 UTC. Membuka secret tetap berjalan.",
          )}
        </span>
      </div>
      <Link href={PATHS.quota}>{t("See usage", "Lihat pemakaian")}</Link>
    </div>
  );
}
