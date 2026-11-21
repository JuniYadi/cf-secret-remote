import { useState } from "preact/hooks";
import { useLocation } from "wouter-preact";
import { Icon, PageTitle } from "../components/shared.tsx";
import { ApiError, api } from "../lib/api.ts";
import { useLang, useSession } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { isAcceptablePassword, MIN_PASSWORD_LENGTH } from "../lib/password.ts";
import { markVaultReady } from "../lib/session.ts";
import { relockWithNewPassword } from "../lib/vault.ts";
import { PATHS, pageCrumbs } from "../routes.ts";
import "../styles/settings.css";

/**
 * Change vault password (design board Password-Change, ADR 20). Only the lock on the private key changes. The
 * key and the public key stay the same, so group access does not change.
 */
export function PasswordChangePage() {
  useLang();
  const [, navigate] = useLocation();
  const { me } = useSession();
  const [current, setCurrent] = useState("");
  const [pw, setPw] = useState("");
  const [again, setAgain] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<"wrong-current" | "failed" | "network" | null>(null);
  const [done, setDone] = useState(false);

  const canSubmit =
    current !== "" && isAcceptablePassword(pw) && pw === again && pw !== current && !busy;

  async function onSubmit(event: Event) {
    event.preventDefault();
    if (!canSubmit || !me?.lockedKey || !me.publicKey) return;
    setBusy(true);
    setError(null);
    try {
      let next: { privateKey: string; lockedKey: string };
      try {
        next = await relockWithNewPassword(me.lockedKey, current, pw);
      } catch {
        setError("wrong-current");
        return;
      }
      await api.changeVaultPassword(next.lockedKey);
      // The in-memory session keeps the new locked copy, so a later unlock uses the new password.
      markVaultReady(me.publicKey, next.lockedKey);
      setCurrent("");
      setPw("");
      setAgain("");
      setDone(true);
    } catch (err) {
      setError(err instanceof ApiError && err.kind === "network" ? "network" : "failed");
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <div class="page-plain password-page">
        <PageTitle crumbs={pageCrumbs("password")} />
        <section class="card settings-card" role="status">
          <p class="sub">
            {t(
              "Your vault password is changed. Your group access is unchanged.",
              "Vault password-mu sudah diganti. Akses grupmu tidak berubah.",
            )}
          </p>
          <div class="row-actions">
            <button type="button" class="btn ghost" onClick={() => navigate(PATHS.secrets)}>
              {t("Back to Secrets", "Kembali ke Secret")}
            </button>
          </div>
        </section>
      </div>
    );
  }

  return (
    <div class="page-plain password-page">
      <div>
        <PageTitle crumbs={pageCrumbs("password")} />
        <p class="sub">
          {t(
            "Pick a new password for your vault. You'll use it the next time you unlock.",
            "Pilih password baru untuk vault-mu. Kamu memakainya saat membuka vault berikutnya.",
          )}
        </p>
      </div>

      <form class="card settings-card form-stack" onSubmit={onSubmit}>
        <div class="field">
          <label for="pw-current">{t("Current vault password", "Vault password saat ini")}</label>
          <input
            id="pw-current"
            type="password"
            autocomplete="current-password"
            value={current}
            onInput={(e) => setCurrent(e.currentTarget.value)}
            aria-invalid={error === "wrong-current" ? "true" : undefined}
          />
          {error === "wrong-current" ? (
            <span class="field-error" role="alert">
              {t("That vault password didn't work.", "Vault password itu tidak cocok.")}
            </span>
          ) : null}
        </div>
        <div class="field">
          <label for="pw-new">{t("New vault password", "Vault password baru")}</label>
          <input
            id="pw-new"
            type="password"
            autocomplete="new-password"
            value={pw}
            onInput={(e) => setPw(e.currentTarget.value)}
            aria-describedby="pw-new-help"
          />
          <span id="pw-new-help" class="note">
            {t(
              `At least ${MIN_PASSWORD_LENGTH} characters`,
              `Minimal ${MIN_PASSWORD_LENGTH} karakter`,
            )}
          </span>
        </div>
        <div class="field">
          <label for="pw-again">{t("Type the new one again", "Ketik ulang yang baru")}</label>
          <input
            id="pw-again"
            type="password"
            autocomplete="new-password"
            value={again}
            onInput={(e) => setAgain(e.currentTarget.value)}
          />
          {again !== "" && again !== pw ? (
            <span class="field-error" role="alert">
              {t("The two passwords don't match.", "Kedua password tidak sama.")}
            </span>
          ) : null}
        </div>

        <div class="warn-box">
          <Icon name="warning" size={18} />
          <span>
            <b>{t("We still can't reset it for you.", "Kami tetap tidak bisa mereset untukmu.")}</b>{" "}
            {t(
              "If you forget the new one, an admin has to give you access again. Save it in a password manager.",
              "Kalau lupa yang baru, admin harus memberimu akses lagi. Simpan di password manager.",
            )}
          </span>
        </div>

        {error === "failed" || error === "network" ? (
          <p class="field-error" role="alert">
            {error === "network"
              ? t(
                  "We couldn't reach the server. Check your connection and try again.",
                  "Kami tidak bisa menghubungi server. Periksa koneksi lalu coba lagi.",
                )
              : t(
                  "Your password wasn't changed. Try again.",
                  "Password-mu belum diganti. Coba lagi.",
                )}
          </p>
        ) : null}

        <div class="row-between">
          <button type="button" class="link-btn" onClick={() => navigate(PATHS.secrets)}>
            {t("Cancel", "Batal")}
          </button>
          <button type="submit" class="btn pri" disabled={!canSubmit}>
            {busy ? t("Changing...", "Mengganti...") : t("Change password", "Ganti password")}
          </button>
        </div>
      </form>

      <section class="card side-card" aria-labelledby="what-changes">
        <h2 id="what-changes" class="card-title">
          {t("What changes", "Yang berubah")}
        </h2>
        <ol class="steps-list">
          <li>
            <b>1</b>
            <span>
              {t(
                "Only the password that locks your key changes. Your key stays the same.",
                "Hanya password yang mengunci kuncimu yang berubah. Kuncimu tetap sama.",
              )}
            </span>
          </li>
          <li>
            <b>2</b>
            <span>
              {t(
                "You keep access to all your groups. Nobody needs to share anything again.",
                "Kamu tetap punya akses ke semua grupmu. Tidak ada yang perlu membagikan ulang.",
              )}
            </span>
          </li>
          <li>
            <b>3</b>
            <span>
              {t(
                "Other devices stay unlocked until they lock. After that they ask for the new password.",
                "Perangkat lain tetap terbuka sampai terkunci. Setelah itu mereka meminta password baru.",
              )}
            </span>
          </li>
        </ol>
      </section>
    </div>
  );
}
