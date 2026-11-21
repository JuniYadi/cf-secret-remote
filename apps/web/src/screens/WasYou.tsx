import { useState } from "preact/hooks";
import { Link, useLocation } from "wouter-preact";
import { Icon, PageTitle, Standalone } from "../components/shared.tsx";
import { ApiError, api } from "../lib/api.ts";
import { useLang, useSession } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { clearPendingRecovery, getPendingRecovery } from "../lib/recovery-flow.ts";
import { PATHS, pageCrumbs } from "../routes.ts";
import "../styles/settings.css";

type Outcome = "open" | "cancelled" | "closed" | "failed";

/**
 * "Was this you?" (design board WasYou). Cancelling throws the request away: nothing is unlocked and the admins
 * are told (ADR 20). The cancel token is the one the request returned; it is only in memory, never in a URL.
 */
export function WasYouPage() {
  useLang();
  const [, navigate] = useLocation();
  const { me } = useSession();
  const [pending] = useState(() => getPendingRecovery());
  const [outcome, setOutcome] = useState<Outcome>("open");
  const [busy, setBusy] = useState(false);

  async function onCancel() {
    if (!pending || busy) return;
    setBusy(true);
    try {
      await api.cancelRecovery(pending.id, pending.cancelToken);
      clearPendingRecovery();
      setOutcome("cancelled");
    } catch (err) {
      const closed =
        err instanceof ApiError && (err.kind === "not-found" || err.kind === "conflict");
      setOutcome(closed ? "closed" : "failed");
    } finally {
      setBusy(false);
    }
  }

  if (!pending) {
    return (
      <Standalone>
        <div class="card forgot-card">
          <PageTitle crumbs={pageCrumbs("wasYou")} />
          <p class="sub">
            {t(
              "There's no request to cancel on this device.",
              "Tidak ada permintaan yang bisa dibatalkan di perangkat ini.",
            )}
          </p>
          <Link class="btn pri block" href={PATHS.unlock}>
            {t("Back to unlock", "Kembali ke buka vault")}
          </Link>
        </div>
      </Standalone>
    );
  }

  if (outcome === "cancelled") {
    return (
      <Standalone>
        <div class="card forgot-card" role="status">
          <PageTitle crumbs={pageCrumbs("wasYou")} />
          <p class="sub">
            {t(
              "The request is cancelled. Nothing was unlocked.",
              "Permintaan dibatalkan. Tidak ada yang terbuka.",
            )}
          </p>
          <ul class="plain-list">
            <li>
              {t("The admins are told it wasn't you.", "Admin diberi tahu bahwa itu bukan kamu.")}
            </li>
            <li>
              {t(
                "Change your work password, since someone may have your account.",
                "Ganti password kerjamu, karena seseorang mungkin memegang akunmu.",
              )}
            </li>
          </ul>
          <Link class="btn pri block" href={PATHS.unlock}>
            {t("Back to unlock", "Kembali ke buka vault")}
          </Link>
        </div>
      </Standalone>
    );
  }

  const who = me?.name ?? t("your account", "akunmu");

  return (
    <Standalone>
      <div class="card forgot-card">
        <div>
          <PageTitle crumbs={pageCrumbs("wasYou")} />
          <p class="sub">
            {t(
              `Someone asked to reset the vault password for ${who} and get their groups back. If it wasn't you, cancel it now.`,
              `Seseorang meminta reset vault password untuk ${who} dan meminta grupnya kembali. Jika bukan kamu, batalkan sekarang.`,
            )}
          </p>
        </div>
        <dl class="kv">
          <div class="kv-row">
            <dt>{t("What was asked", "Yang diminta")}</dt>
            <dd>
              {t(
                "A new key for your vault and access to your groups",
                "Kunci baru untuk vault-mu dan akses ke grupmu",
              )}
            </dd>
          </div>
        </dl>
        {outcome === "failed" ? (
          <p class="field-error" role="alert">
            {t(
              "We couldn't cancel it. Check your connection and try again.",
              "Kami tidak bisa membatalkannya. Periksa koneksi lalu coba lagi.",
            )}
          </p>
        ) : null}
        {outcome === "closed" ? (
          <p class="note" role="status">
            {t("This request is already closed.", "Permintaan ini sudah ditutup.")}
          </p>
        ) : null}
        <div class="row-actions">
          <button type="button" class="btn ghost" onClick={() => navigate(PATHS.forgot)}>
            {t("Yes, that was me", "Ya, itu saya")}
          </button>
          <button type="button" class="btn danger" disabled={busy} onClick={onCancel}>
            {t("No, cancel it", "Bukan, batalkan")}
          </button>
        </div>
        <div class="warn-box">
          <Icon name="warning" size={18} />
          <span>
            <b>{t("If you cancel:", "Jika kamu membatalkan:")}</b>{" "}
            {t(
              "The request is thrown away. Nothing is unlocked.",
              "Permintaan dibuang. Tidak ada yang terbuka.",
            )}
          </span>
        </div>
      </div>
    </Standalone>
  );
}
