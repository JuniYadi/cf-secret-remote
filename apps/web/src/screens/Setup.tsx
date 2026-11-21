import { useState } from "preact/hooks";
import { useLocation } from "wouter-preact";
import { Stepper } from "../components/Stepper.tsx";
import { BrandRow, Icon, LangToggle, PageTitle } from "../components/shared.tsx";
import { ApiError, api } from "../lib/api.ts";
import { useLang } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { unlock } from "../lib/keystore.ts";
import {
  isAcceptablePassword,
  MIN_PASSWORD_LENGTH,
  passwordStrength,
  type Strength,
} from "../lib/password.ts";
import { markVaultReady } from "../lib/session.ts";
import { createVault } from "../lib/vault.ts";
import { PATHS, pageCrumbs } from "../routes.ts";

const HINT: Record<Strength, () => string> = {
  weak: () =>
    t(
      `Too short or too repetitive: use at least ${MIN_PASSWORD_LENGTH} characters`,
      `Terlalu pendek atau terlalu berulang: pakai minimal ${MIN_PASSWORD_LENGTH} karakter`,
    ),
  fair: () =>
    t("Fair: a longer password is safer", "Cukup: password yang lebih panjang lebih aman"),
  good: () => t("Good", "Baik"),
  strong: () => t("Strong: four random words", "Kuat: empat kata acak"),
};

/** Step 2 of 4: create the vault password. Makes the key pair and locks the private key in the browser. */
export function SetupPage() {
  useLang();
  const [, navigate] = useLocation();
  const [password, setPassword] = useState("");
  const [again, setAgain] = useState("");
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const strength = passwordStrength(password);
  const mismatch = again !== "" && again !== password;
  const canSubmit = isAcceptablePassword(password) && password === again && saved && !busy;

  async function onSubmit(event: Event) {
    event.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      // The password and the unlocked key stay in this function. Only the public key and the locked key go out.
      const vault = await createVault(password);
      await api.createVault(vault.publicKey, vault.lockedKey);
      unlock({ publicKey: vault.publicKey, privateKey: vault.privateKey });
      markVaultReady(vault.publicKey, vault.lockedKey);
      setPassword("");
      setAgain("");
      navigate(PATHS.setupRecovery);
    } catch (err) {
      setBusy(false);
      if (err instanceof ApiError && err.kind === "conflict") {
        // Set up in another tab or earlier. Unlock with the password that was used then.
        navigate(PATHS.unlock);
        return;
      }
      setError(
        err instanceof ApiError && err.kind === "network"
          ? t(
              "We couldn't reach the server. Check your connection and try again.",
              "Kami tidak bisa menghubungi server. Periksa koneksi lalu coba lagi.",
            )
          : t("Your vault wasn't created. Try again.", "Vault belum dibuat. Coba lagi."),
      );
    }
  }

  return (
    <div class="setup-page">
      <div class="setup-top">
        <BrandRow />
        <div class="setup-steps">
          <Stepper current={2} />
          <LangToggle />
        </div>
      </div>

      <div class="setup-grid">
        <form class="card form-card" onSubmit={onSubmit} aria-labelledby="setup-title">
          <div>
            <PageTitle crumbs={pageCrumbs("setup")} />
            <p class="sub">
              {t(
                "This password locks your personal key. You'll enter it each time you open the vault. It's different from your work login.",
                "Password ini mengunci kunci pribadimu. Kamu memasukkannya setiap kali membuka vault. Ini berbeda dari login kerjamu.",
              )}
            </p>
          </div>

          <div class="field">
            <label for="setup-password">{t("Vault password", "Vault password")}</label>
            <input
              id="setup-password"
              type="password"
              autocomplete="new-password"
              value={password}
              onInput={(e) => setPassword(e.currentTarget.value)}
              aria-describedby="setup-strength"
              required
            />
          </div>
          <div id="setup-strength" class="strength" aria-live="polite">
            <div class={`meter ${password === "" ? "" : strength}`} aria-hidden="true">
              <i />
            </div>
            {password !== "" && <span class={`hint ${strength}`}>{HINT[strength]()}</span>}
          </div>

          <div class="field">
            <label for="setup-again">{t("Type it again", "Ketik ulang")}</label>
            <input
              id="setup-again"
              type="password"
              autocomplete="new-password"
              value={again}
              onInput={(e) => setAgain(e.currentTarget.value)}
              aria-invalid={mismatch ? "true" : undefined}
              aria-describedby={mismatch ? "setup-mismatch" : undefined}
              required
            />
            {mismatch && (
              <span id="setup-mismatch" class="field-error" role="alert">
                {t("The two passwords don't match.", "Kedua password tidak sama.")}
              </span>
            )}
          </div>

          <div class="warn-box">
            <Icon name="warning" size={18} />
            <span>
              <b>{t("We can't reset this password.", "Kami tidak bisa mereset password ini.")}</b>{" "}
              {t(
                "If you forget it, an admin has to give you access again. Save it in a password manager.",
                "Kalau lupa, admin harus memberimu akses lagi. Simpan di password manager.",
              )}
            </span>
          </div>

          <label class="check">
            <input
              type="checkbox"
              checked={saved}
              onChange={(e) => setSaved(e.currentTarget.checked)}
            />
            {t("I understand and I've saved it", "Saya mengerti dan sudah menyimpannya")}
          </label>

          {error && (
            <p class="field-error" role="alert">
              {error}
            </p>
          )}

          <button type="submit" class="btn pri block" disabled={!canSubmit}>
            {busy
              ? t("Creating your vault...", "Membuat vault...")
              : t("Create my vault", "Buat vault saya")}
          </button>
        </form>

        <aside class="card side-card" aria-labelledby="next-title">
          <h2 id="next-title" class="card-title">
            {t("What happens next", "Apa yang terjadi berikutnya")}
          </h2>
          <ol class="steps-list">
            <li>
              <b>1</b>
              <span>
                {t(
                  "Your browser makes a personal key, just for you.",
                  "Browsermu membuat kunci pribadi, khusus untukmu.",
                )}
              </span>
            </li>
            <li>
              <b>2</b>
              <span>
                {t(
                  "That key is locked with your vault password.",
                  "Kunci itu dikunci dengan vault password-mu.",
                )}
              </span>
            </li>
            <li>
              <b>3</b>
              <span>
                {t(
                  "Only the locked key is saved on our server. Your password never leaves your device.",
                  "Hanya kunci yang sudah terkunci yang disimpan di server. Passwordmu tidak pernah keluar dari perangkat.",
                )}
              </span>
            </li>
          </ol>
          <details class="tech">
            <summary>{t("Technical details", "Detail teknis")}</summary>
            <div class="code">
              public_key: {t("sent (SPKI, base64url)", "dikirim (SPKI, base64url)")}
              <br />
              locked_key:{" "}
              {t("sent (PBKDF2-SHA256 600k, AES-GCM)", "dikirim (PBKDF2-SHA256 600k, AES-GCM)")}
              <br />
              {t(
                "Never sent: your password, your unlocked key.",
                "Tidak pernah dikirim: passwordmu, kunci yang sudah terbuka.",
              )}
            </div>
          </details>
        </aside>
      </div>
    </div>
  );
}
