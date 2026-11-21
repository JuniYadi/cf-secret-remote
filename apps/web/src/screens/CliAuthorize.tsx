import { useState } from "preact/hooks";
import { useLocation } from "wouter-preact";
import { PageTitle, Standalone } from "../components/shared.tsx";
import { formatTime } from "../lib/activity.ts";
import { ApiError, api, type CliLoginInfo } from "../lib/api.ts";
import { isCompleteCode, normalizeUserCode } from "../lib/cli-code.ts";
import { useLang, useSession } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { messageFor } from "../lib/messages.ts";
import { PATHS, pageCrumbs } from "../routes.ts";
import "../styles/activity.css";

/**
 * Authorize a terminal (ADR 11). The person types the code shown in their terminal, checks the device, and
 * approves. The code and the device name come from the Worker; nothing secret is on this page.
 */
export function CliAuthorizePage() {
  const lang = useLang();
  const { me } = useSession();
  const [, navigate] = useLocation();
  const [code, setCode] = useState("");
  const [info, setInfo] = useState<CliLoginInfo | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function check(event: Event) {
    event.preventDefault();
    if (!isCompleteCode(code)) {
      setError(
        t(
          "Enter the 8 characters from your terminal, such as ABCD-EFGH.",
          "Masukkan 8 karakter dari terminalmu, misalnya ABCD-EFGH.",
        ),
      );
      return;
    }
    setBusy(true);
    setError(null);
    try {
      setInfo(await api.cliLogin(normalizeUserCode(code)));
    } catch (err) {
      setInfo(null);
      setError(codeError(err));
    } finally {
      setBusy(false);
    }
  }

  async function authorize() {
    if (info === null) return;
    setBusy(true);
    setError(null);
    try {
      await api.cliApprove(info.userCode);
      navigate(PATHS.cliDone, { replace: true });
    } catch (err) {
      setError(codeError(err));
      setBusy(false);
    }
  }

  return (
    <Standalone>
      <div class="card authorize-card">
        <PageTitle crumbs={pageCrumbs("cliAuthorize")} />
        <p class="sub">
          {t(
            `A terminal is asking to sign in as ${me?.name ?? ""}. Only continue if you started this.`,
            `Sebuah terminal meminta masuk sebagai ${me?.name ?? ""}. Lanjutkan hanya jika kamu yang memulainya.`,
          )}
        </p>

        {info === null ? (
          <form class="form-stack" onSubmit={check} noValidate>
            <div class="field">
              <label for="cli-code">{t("Code from your terminal", "Kode dari terminalmu")}</label>
              <input
                id="cli-code"
                type="text"
                class="code-input mono"
                value={code}
                maxLength={12}
                autocomplete="off"
                autocapitalize="characters"
                spellcheck={false}
                inputMode="text"
                placeholder="ABCD-EFGH"
                onInput={(e) => setCode(e.currentTarget.value)}
                aria-invalid={error !== null ? "true" : undefined}
                aria-describedby={error !== null ? "cli-code-error" : "cli-code-hint"}
              />
              <span id="cli-code-hint" class="note">
                {t(
                  "Type it as shown. Upper case and the hyphen are added for you.",
                  "Ketik seperti yang tampil. Huruf besar dan tanda hubung ditambahkan otomatis.",
                )}
              </span>
            </div>
            {error !== null && (
              <p id="cli-code-error" class="field-error" role="alert">
                {error}
              </p>
            )}
            <button type="submit" class="btn block" disabled={busy}>
              {busy ? t("Checking...", "Memeriksa...") : t("Continue", "Lanjut")}
            </button>
          </form>
        ) : (
          <div class="stack">
            <div class="code-confirm" aria-live="polite">
              <div class="note">
                {t(
                  "Check this code matches your terminal",
                  "Pastikan kode ini sama dengan di terminalmu",
                )}
              </div>
              <div class="code-big mono">{info.userCode}</div>
            </div>
            <dl class="kv-list">
              <div>
                <dt>{t("Device", "Perangkat")}</dt>
                <dd>
                  {info.device !== "" ? info.device : t("Unnamed device", "Perangkat tanpa nama")}
                </dd>
              </div>
              <div>
                <dt>{t("Program", "Program")}</dt>
                <dd>cfs</dd>
              </div>
              <div>
                <dt>{t("Code expires", "Kode berakhir")}</dt>
                <dd>{formatTime(info.expiresAt, lang)}</dd>
              </div>
            </dl>
            {error !== null && (
              <p class="field-error" role="alert">
                {error}
              </p>
            )}
            <div class="row-actions">
              <button type="button" class="btn ghost" disabled={busy} onClick={() => setInfo(null)}>
                {t("Cancel", "Batal")}
              </button>
              <button type="button" class="btn" disabled={busy} onClick={() => void authorize()}>
                {t("Authorize", "Izinkan")}
              </button>
            </div>
          </div>
        )}

        <p class="note">
          {t(
            "This lets the device fetch your locked secrets. You'll still need your vault password to open them.",
            "Ini memungkinkan perangkat mengambil secret terkunci milikmu. Kamu tetap butuh vault password untuk membukanya.",
          )}
        </p>
      </div>
    </Standalone>
  );
}

/** The lookup and approve errors. A wrong code shows the attempts left (ADR 27); too many shows the wait. */
export function codeError(err: unknown): string {
  if (err instanceof ApiError && err.kind === "not-found") {
    const left = err.attemptsLeft;
    if (left === undefined) {
      return t(
        "That code doesn't match a waiting sign-in. Check your terminal and try again.",
        "Kode itu tidak cocok dengan permintaan masuk yang menunggu. Periksa terminalmu lalu coba lagi.",
      );
    }
    if (left === 0) {
      return t(
        "That code doesn't match. No tries are left, so you'll have to wait 10 minutes.",
        "Kode itu tidak cocok. Tidak ada percobaan tersisa, jadi kamu harus menunggu 10 menit.",
      );
    }
    return t(
      `That code doesn't match a waiting sign-in. ${left} ${left === 1 ? "try" : "tries"} left before a 10-minute wait.`,
      `Kode itu tidak cocok dengan permintaan masuk yang menunggu. Sisa ${left} percobaan sebelum menunggu 10 menit.`,
    );
  }
  if (err instanceof ApiError && err.kind === "rate-limited") {
    return t(
      "Too many wrong codes. Wait 10 minutes, then try again.",
      "Terlalu banyak kode salah. Tunggu 10 menit, lalu coba lagi.",
    );
  }
  return messageFor(err);
}
