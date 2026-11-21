import { useState } from "preact/hooks";
import { Link, useLocation } from "wouter-preact";
import { Icon, PageTitle, Standalone } from "../components/shared.tsx";
import { ApiError, api } from "../lib/api.ts";
import { useLang } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { isAcceptablePassword, MIN_PASSWORD_LENGTH, passwordStrength } from "../lib/password.ts";
import { codeFor } from "../lib/recovery-code.ts";
import { getPendingRecovery, setPendingRecovery } from "../lib/recovery-flow.ts";
import { ACCESS_LOGOUT_PATH, getSession, loadSession } from "../lib/session.ts";
import { createVault } from "../lib/vault.ts";
import { PATHS, pageCrumbs } from "../routes.ts";
import "../styles/settings.css";

/**
 * Forgot your vault password (design board Forgot, ADR 20, DESIGN.md "Verifikasi"). The person signs in to
 * Access again, picks a new vault password, and gets a four-word code to send to an admin. The admin must type
 * the code before access is given. Nothing secret is kept after the request goes out.
 */
export function ForgotPage() {
  useLang();
  const [, navigate] = useLocation();
  const [pending, setPending] = useState(() => getPendingRecovery());
  const [pw, setPw] = useState("");
  const [again, setAgain] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<"stale-login" | "waiting" | "failed" | "network" | null>(null);
  const [copied, setCopied] = useState(false);
  const [notYet, setNotYet] = useState(false);

  const strong = isAcceptablePassword(pw);
  const canStart = strong && pw === again && !busy;

  async function onStart(event: Event) {
    event.preventDefault();
    if (!canStart) return;
    setBusy(true);
    setError(null);
    try {
      // The new key's private half is not kept: after the admin's grant, the person unlocks with the new
      // password, which opens the same key from the locked copy the server holds.
      const vault = await createVault(pw);
      const start = await api.startRecovery(vault.publicKey, vault.lockedKey);
      if ((await codeFor(vault.publicKey)) !== start.words) throw new Error("code mismatch");
      const next = {
        id: start.id,
        words: start.words,
        cancelToken: start.cancelToken,
        publicKey: vault.publicKey,
        lockedKey: vault.lockedKey,
      };
      setPendingRecovery(next);
      setPending(next);
      setPw("");
      setAgain("");
    } catch (err) {
      if (err instanceof ApiError && err.kind === "forbidden") setError("stale-login");
      else if (err instanceof ApiError && err.kind === "conflict") setError("waiting");
      else if (err instanceof ApiError && err.kind === "network") setError("network");
      else setError("failed");
    } finally {
      setBusy(false);
    }
  }

  async function onCheckAgain() {
    setNotYet(false);
    if (!pending) return;
    await loadSession();
    const current = getSession().me;
    if (current?.publicKey === pending.publicKey) {
      setPending(null);
      navigate(PATHS.unlock);
    } else setNotYet(true);
  }

  async function onCopy() {
    if (!pending) return;
    try {
      await navigator.clipboard.writeText(pending.words);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  const steps = (
    <ol class="steps-st" aria-label={t("What happens next", "Apa yang terjadi berikutnya")}>
      <li class="st done">
        <i aria-hidden="true">
          <Icon name="lock" size={14} />
        </i>
        <div class="body">
          {t(
            "You signed in again to confirm it's you",
            "Kamu masuk ulang untuk memastikan itu kamu",
          )}
          <small>
            {t("With your company login, just now.", "Dengan login perusahaan, baru saja.")}
          </small>
        </div>
      </li>
      <li class="st done">
        <i aria-hidden="true">
          <Icon name="lock" size={14} />
        </i>
        <div class="body">
          {t("You made a new vault password", "Kamu membuat vault password baru")}
          <small>
            {t(
              "It locks a brand-new key made just now.",
              "Password ini mengunci kunci baru yang baru saja dibuat.",
            )}
          </small>
        </div>
      </li>
      <li class={pending ? "st now" : "st"}>
        <i aria-hidden="true">3</i>
        <div class="body">
          {t("Send this code to an admin", "Kirim kode ini ke admin")}
          <small>
            {t(
              "Send it by DM, chat, or say it on a call. Don't put it in the request itself, so only the real you can pass it on.",
              "Kirim lewat DM, chat, atau sebutkan lewat telepon. Jangan taruh di permintaan itu sendiri, supaya hanya kamu yang asli yang bisa meneruskannya.",
            )}
          </small>
        </div>
      </li>
      <li class="st">
        <i aria-hidden="true">4</i>
        <div class="body">
          {t(
            "The admin types the code and gives you access",
            "Admin mengetik kode dan memberimu akses",
          )}
          <small>
            {t(
              "They can only continue if the code they type matches.",
              "Mereka hanya bisa lanjut kalau kode yang diketik cocok.",
            )}
          </small>
        </div>
      </li>
    </ol>
  );

  return (
    <Standalone>
      <div class="card forgot-card">
        <div>
          <PageTitle crumbs={pageCrumbs("forgot")} />
          <p class="sub">
            {t(
              "We can't reset it, because nobody but you can open your key. An admin can give you access with a new one, once they've checked it's you.",
              "Kami tidak bisa mereset, karena tidak ada yang bisa membuka kuncimu selain kamu. Admin bisa memberimu akses dengan kunci baru, setelah memastikan itu kamu.",
            )}
          </p>
        </div>

        {pending ? (
          <>
            {steps}
            <output class="code-box" aria-label={t("Your code", "Kodemu")}>
              {pending.words}
            </output>
            <div class="row-actions">
              <button type="button" class="btn ghost sm" onClick={onCopy}>
                {copied ? t("Copied", "Tersalin") : t("Copy code", "Salin kode")}
              </button>
            </div>
            <p class="note">
              {t(
                "We emailed you and your other signed-in devices. If this wasn't you, you can cancel it from there. Your secrets stay locked until an admin approves.",
                "Kami mengirim email ke kamu dan ke perangkat lain yang sedang masuk. Jika ini bukan kamu, kamu bisa membatalkannya dari sana. Secret-mu tetap terkunci sampai admin menyetujui.",
              )}
            </p>
            {notYet ? (
              <p class="note" role="status">
                {t(
                  "Not yet. Your admin still needs to give you access.",
                  "Belum. Admin-mu masih perlu memberimu akses.",
                )}
              </p>
            ) : null}
            <div class="row-between">
              <button type="button" class="btn pri" onClick={onCheckAgain}>
                {t("Check again", "Periksa lagi")}
              </button>
              <button type="button" class="link-btn" onClick={() => navigate(PATHS.wasYou)}>
                {t("Cancel this request", "Batalkan permintaan ini")}
              </button>
            </div>
          </>
        ) : (
          <form class="form-stack" onSubmit={onStart} aria-labelledby="forgot-form-title">
            <h2 id="forgot-form-title" class="visually-hidden">
              {t("New vault password", "Vault password baru")}
            </h2>
            <div class="field">
              <label for="forgot-password">{t("New vault password", "Vault password baru")}</label>
              <input
                id="forgot-password"
                type="password"
                autocomplete="new-password"
                value={pw}
                onInput={(e) => setPw(e.currentTarget.value)}
                aria-describedby="forgot-strength"
                required
              />
              <span id="forgot-strength" class="note">
                {pw === ""
                  ? t(
                      `At least ${MIN_PASSWORD_LENGTH} characters`,
                      `Minimal ${MIN_PASSWORD_LENGTH} karakter`,
                    )
                  : passwordStrength(pw) === "weak"
                    ? t("Too short or too repetitive", "Terlalu pendek atau terlalu berulang")
                    : t("Good enough to start", "Cukup untuk mulai")}
              </span>
            </div>
            <div class="field">
              <label for="forgot-again">{t("Type it again", "Ketik ulang")}</label>
              <input
                id="forgot-again"
                type="password"
                autocomplete="new-password"
                value={again}
                onInput={(e) => setAgain(e.currentTarget.value)}
                aria-invalid={again !== "" && again !== pw ? "true" : undefined}
                required
              />
              {again !== "" && again !== pw ? (
                <span class="field-error" role="alert">
                  {t("The two passwords don't match.", "Kedua password tidak sama.")}
                </span>
              ) : null}
            </div>
            {error ? (
              <p class="field-error" role="alert">
                {error === "stale-login"
                  ? t(
                      "Sign in again to confirm it's you. Your request needs a login from the last few minutes.",
                      "Masuk ulang untuk memastikan itu kamu. Permintaanmu perlu login dari beberapa menit terakhir.",
                    )
                  : error === "waiting"
                    ? t(
                        "A request is already waiting for an admin.",
                        "Sudah ada permintaan yang menunggu admin.",
                      )
                    : error === "network"
                      ? t(
                          "We couldn't reach the server. Check your connection and try again.",
                          "Kami tidak bisa menghubungi server. Periksa koneksi lalu coba lagi.",
                        )
                      : t(
                          "Your request wasn't sent. Try again.",
                          "Permintaanmu belum terkirim. Coba lagi.",
                        )}
              </p>
            ) : null}
            {error === "stale-login" ? (
              <button
                type="button"
                class="btn ghost block"
                onClick={() => window.location.assign(ACCESS_LOGOUT_PATH)}
              >
                {t("Sign in again", "Masuk lagi")}
              </button>
            ) : null}
            <button type="submit" class="btn pri block" disabled={!canStart}>
              {busy
                ? t("Making your key...", "Membuat kunci...")
                : t("Start recovery", "Mulai pemulihan")}
            </button>
          </form>
        )}

        <div class="help">
          <span>
            <Link href={PATHS.recover}>
              {t(
                "Saved a recovery key when you set up? Use it instead",
                "Sudah menyimpan kunci pemulihan saat menyiapkan? Pakai itu saja",
              )}
            </Link>
          </span>
        </div>
      </div>
    </Standalone>
  );
}
