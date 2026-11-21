import type { ComponentChildren } from "preact";
import { useEffect, useRef, useState } from "preact/hooks";
import { Link, useLocation } from "wouter-preact";
import { useKeyStatus, useLang, useSession } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { lock, touch } from "../lib/keystore.ts";
import { signOut } from "../lib/session.ts";
import { NAV_ITEMS, PATHS } from "../routes.ts";
import { BrandRow, Icon, LangToggle } from "./shared.tsx";

/** The signed-in layout: sidebar with Lock vault and Sign out, then the page. */
export function Shell({ children }: { children: ComponentChildren }) {
  useLang();
  const [location] = useLocation();
  const { me } = useSession();
  const keys = useKeyStatus();
  if (!me) return null;

  const initial = me.name.trim().charAt(0).toUpperCase() || "?";
  const roleLabel = me.role === "admin" ? t("Admin", "Admin") : t("Member", "Anggota");

  return (
    <div class="app">
      <aside class="side">
        <BrandRow />
        <nav class="nav" aria-label={t("Main", "Utama")}>
          {NAV_ITEMS.map((item) => {
            const active = location === item.path || location.startsWith(`${item.path}/`);
            return (
              <Link
                key={item.path}
                href={item.path}
                class={active ? "on" : ""}
                aria-current={active ? "page" : undefined}
              >
                <Icon name={item.icon} />
                {item.label()}
              </Link>
            );
          })}
        </nav>
        <div class="side-foot">
          <LangToggle />
          <Link
            href={PATHS.devices}
            class="me"
            aria-label={t("Your signed-in devices", "Perangkat yang masuk")}
          >
            <span class="ava" aria-hidden="true">
              {initial}
            </span>
            <div class="me-text">
              <div class="me-name">{me.name}</div>
              <div class="me-role">{roleLabel}</div>
            </div>
          </Link>
          <div class="side-actions">
            <button type="button" class="btn ghost sm" onClick={() => lock()}>
              {t("Lock vault", "Kunci vault")}
            </button>
            <button type="button" class="btn ghost sm" onClick={() => signOut()}>
              {t("Sign out", "Keluar")}
            </button>
          </div>
        </div>
      </aside>
      <main class="main">{children}</main>
      {keys.warning && keys.lockAt !== null && <AutoLockWarning lockAt={keys.lockAt} />}
    </div>
  );
}

/** Shown from 14 minutes idle. "Stay unlocked" restarts the timer. Locks at 15 minutes (ADR 24). */
export function AutoLockWarning({ lockAt }: { lockAt: number }) {
  useLang();
  const [now, setNow] = useState(() => Date.now());
  const stayRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    // Focus the safe choice when the dialog opens, so a keyboard user can answer at once.
    stayRef.current?.focus();
    return () => clearInterval(id);
  }, []);

  const left = Math.max(0, Math.ceil((lockAt - now) / 1000));
  const clock = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;

  return (
    <div class="overlay">
      <div
        class="modal"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="autolock-title"
        aria-describedby="autolock-sub"
      >
        <div class="modal-head">
          <div class="modal-icon">
            <Icon name="clock" size={24} />
          </div>
          <div>
            <h2 id="autolock-title" class="modal-title">
              {t("Still there?", "Masih di sana?")}
            </h2>
            <div class="countdown" role="timer">
              {clock}
            </div>
          </div>
        </div>
        <p id="autolock-sub" class="modal-text">
          {t(
            "Your vault locks itself after 15 minutes of inactivity, to keep your secrets safe if you step away.",
            "Vault-mu terkunci sendiri setelah 15 menit tidak aktif, supaya secret-mu aman kalau kamu pergi.",
          )}
        </p>
        <progress
          class="lock-progress"
          max={60}
          value={left}
          aria-label={t("Time left", "Sisa waktu")}
        />
        <div class="row-actions">
          <button type="button" class="btn ghost" onClick={() => lock()}>
            {t("Lock now", "Kunci sekarang")}
          </button>
          <button ref={stayRef} type="button" class="btn" onClick={() => touch()}>
            {t("Stay unlocked", "Tetap terbuka")}
          </button>
        </div>
        <p class="modal-note">
          {t(
            "When it locks you'll just enter your vault password again. Nothing is lost.",
            "Saat terkunci kamu cukup memasukkan vault password lagi. Tidak ada yang hilang.",
          )}
        </p>
      </div>
    </div>
  );
}
