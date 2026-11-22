import { useEffect, useState } from "preact/hooks";
import { Link, useLocation } from "wouter-preact";
import { PageTitle, Standalone } from "../components/shared.tsx";
import { api } from "../lib/api.ts";
import { useLang, useSession } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { unlock } from "../lib/keystore.ts";
import { signOut } from "../lib/session.ts";
import {
  type AttemptState,
  cooldownSeconds,
  NO_ATTEMPTS,
  recordFailure,
  triesLeft,
} from "../lib/unlock-attempts.ts";
import { unlockVault } from "../lib/vault.ts";
import { PATHS, pageCrumbs } from "../routes.ts";

// Kept at module level so a wrong password is still counted after the route changes (ADR 20).
// Counted in the browser only. A reload starts the count again.
let attempts: AttemptState = NO_ATTEMPTS;

/** Asks for the vault password and opens the private key in memory. */
export function UnlockPage() {
  useLang();
  const [, navigate] = useLocation();
  const { me } = useSession();
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const [state, setState] = useState<AttemptState>(attempts);
  const [now, setNow] = useState(() => Date.now());

  const waiting = cooldownSeconds(state, now);

  // Ticks once a second while a wait is running, so the count and the button stay in step.
  useEffect(() => {
    if (state.lockedUntil === null) return;
    const id = setInterval(() => {
      const current = Date.now();
      setNow(current);
      if (current >= (state.lockedUntil ?? 0)) {
        attempts = { ...attempts, lockedUntil: null };
        setState(attempts);
      }
    }, 1000);
    return () => clearInterval(id);
  }, [state.lockedUntil]);

  if (!me || me.lockedKey === null || me.publicKey === null) return null;

  async function onSubmit(event: Event) {
    event.preventDefault();
    if (busy || waiting > 0 || password === "") return;
    setBusy(true);
    try {
      const privateKey = await unlockVault(me?.lockedKey ?? "", password);
      attempts = NO_ATTEMPTS;
      setState(attempts);
      setFailed(false);
      setPassword("");
      unlock({ publicKey: me?.publicKey ?? "", privateKey });
      // Recording is best-effort: neither latency nor an API failure should block the vault.
      void api.recordUnlock().catch(() => {});
      navigate(PATHS.secrets);
    } catch {
      const at = Date.now();
      attempts = recordFailure(attempts, at);
      setState(attempts);
      setNow(at);
      setFailed(true);
      setBusy(false);
    }
  }

  const initial = me.name.trim().charAt(0).toUpperCase() || "?";
  const left = triesLeft(state);

  return (
    <Standalone>
      <div class="card unlock-card">
        <div class="person">
          <div class="ava big" aria-hidden="true">
            {initial}
          </div>
          <div>
            <div class="person-name">{me.name}</div>
          </div>
        </div>

        <form class="form-stack" onSubmit={onSubmit} aria-labelledby="unlock-title">
          <div>
            <PageTitle crumbs={pageCrumbs("unlock")} />
            <p class="sub">
              {t(
                "Enter your vault password to open your secrets on this device.",
                "Masukkan vault password untuk membuka secret di perangkat ini.",
              )}
            </p>
          </div>

          <div class="field">
            <label for="unlock-password">{t("Vault password", "Vault password")}</label>
            <input
              id="unlock-password"
              type="password"
              autocomplete="current-password"
              value={password}
              onInput={(e) => setPassword(e.currentTarget.value)}
              aria-invalid={failed ? "true" : undefined}
              aria-describedby={failed ? "unlock-error" : undefined}
              disabled={busy}
              required
            />
            {failed && (
              <div id="unlock-error" class="field-error" role="alert">
                <span aria-hidden="true">⚠</span>
                <span>
                  <b>{t("That password didn't work.", "Password itu tidak cocok.")}</b>{" "}
                  {t(
                    "Check for typos, caps lock, and extra spaces, then try again.",
                    "Periksa salah ketik, caps lock, dan spasi berlebih, lalu coba lagi.",
                  )}
                </span>
              </div>
            )}
          </div>

          <button
            type="submit"
            class="btn pri block"
            disabled={busy || waiting > 0 || password === ""}
          >
            {busy
              ? t("Unlocking...", "Membuka...")
              : failed
                ? t("Try again", "Coba lagi")
                : t("Unlock", "Buka")}
          </button>

          <div class="help">
            <span>
              {waiting > 0
                ? t(
                    `Wait ${waiting} seconds before the next try.`,
                    `Tunggu ${waiting} detik sebelum mencoba lagi.`,
                  )
                : failed
                  ? t(
                      `${left} ${left === 1 ? "try" : "tries"} left before a 1-minute wait.`,
                      `Sisa ${left} percobaan sebelum menunggu 1 menit.`,
                    )
                  : t(
                      "Locks again automatically after 15 minutes of inactivity.",
                      "Terkunci lagi otomatis setelah 15 menit tidak aktif.",
                    )}
            </span>
            <span>
              <Link href={PATHS.forgot}>
                {t(
                  "Forgot it? Ask an admin to give you access again.",
                  "Lupa? Minta admin memberimu akses lagi.",
                )}
              </Link>
            </span>
            <span>
              <Link href={PATHS.recover}>
                {t(
                  "Saved a recovery key? Use it instead.",
                  "Punya kunci pemulihan? Pakai itu saja.",
                )}
              </Link>
            </span>
          </div>
        </form>
      </div>
      <p class="center-line">
        <button type="button" class="link-btn" onClick={() => signOut()}>
          {t(`Not ${me.name}? Sign out`, `Bukan ${me.name}? Keluar`)}
        </button>
      </p>
    </Standalone>
  );
}
