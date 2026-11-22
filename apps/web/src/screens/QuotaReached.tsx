import { Link } from "wouter-preact";
import { ErrorNote, Meter, useQuota } from "../components/parts.tsx";
import { Icon, PageTitle } from "../components/shared.tsx";
import { api } from "../lib/api.ts";
import { useLang, useSession } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { useLoad } from "../lib/use-load.ts";
import { PATHS, pageCrumbs } from "../routes.ts";
import "../styles/settings.css";

/**
 * Free plan limit reached (design board Quota-Reached). Shown at /quota, and the banner on every shell page links
 * here. Writes are paused until 00:00 UTC; reads, sign-in and the log keep working (ADR 19).
 */
export function QuotaReachedPage() {
  useLang();
  const { me } = useSession();
  const { active, secondsLeft } = useQuota();
  const isAdmin = me?.role === "admin";
  const usage = useLoad(() => (isAdmin ? api.usage() : Promise.resolve(null)), `quota-${isAdmin}`);

  const hours = Math.floor(secondsLeft / 3600);
  const minutes = Math.floor((secondsLeft % 3600) / 60);

  return (
    <div class="page-plain quota-page">
      <div>
        <PageTitle crumbs={pageCrumbs("quota")} />
        <p class="sub">
          {t(
            "You can see the names. The values open only for people in the right group.",
            "Nama terlihat oleh semua. Isinya hanya terbuka untuk orang di grup yang tepat.",
          )}
        </p>
      </div>

      {active ? (
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
        </div>
      ) : null}

      <section class="card settings-card" aria-labelledby="usage-title">
        <h2 id="usage-title" class="card-title">
          {t("Saves and log entries today", "Penyimpanan dan entri log hari ini")}
        </h2>
        {isAdmin ? (
          <>
            <ErrorNote error={usage.error} />
            {usage.data ? (
              <Meter
                label={t("Saves and log entries", "Penyimpanan dan entri log")}
                value={usage.data.writes}
                max={usage.data.limit}
              />
            ) : null}
          </>
        ) : null}
        <p class="note" role="status">
          {active
            ? t(
                `Resets in ${hours} h ${minutes} min, at 00:00 UTC.`,
                `Reset dalam ${hours} j ${minutes} mnt, pukul 00:00 UTC.`,
              )
            : t("Saving works again.", "Penyimpanan sudah berjalan lagi.")}
        </p>
      </section>

      <div class="quota-columns">
        <section class="card settings-card" aria-labelledby="works-title">
          <h2 id="works-title" class="card-title">
            {t("Still works", "Masih berjalan")}
          </h2>
          <ul class="plain-list ok-list">
            <li>
              {t(
                "Opening secrets, in the app and with cfs run.",
                "Membuka secret, di aplikasi dan dengan cfs run.",
              )}
            </li>
            <li>{t("Signing in and unlocking your vault.", "Masuk dan membuka vault.")}</li>
            <li>
              {t(
                "Reading Activity and the log you already have.",
                "Membaca Aktivitas dan log yang sudah ada.",
              )}
            </li>
          </ul>
        </section>
        <section class="card settings-card" aria-labelledby="paused-title">
          <h2 id="paused-title" class="card-title">
            {t("Paused until it resets", "Dijeda sampai reset")}
          </h2>
          <ul class="plain-list">
            <li>
              {t(
                "Saving new secrets or new versions, and changing groups.",
                "Menyimpan secret baru atau versi baru, dan mengubah grup.",
              )}
            </li>
            <li>
              {t(
                "New log entries. Opens are held and recorded as soon as space returns.",
                "Entri log baru. Pembukaan ditahan dan dicatat begitu ruang tersedia lagi.",
              )}
            </li>
          </ul>
        </section>
      </div>

      <section class="card side-card" aria-labelledby="avoid-title">
        <h2 id="avoid-title" class="card-title">
          {t("How to avoid this", "Cara menghindarinya")}
        </h2>
        <ol class="steps-list">
          <li>
            <b>1</b>
            <span>
              {t(
                "Set a per-hour limit on busy bots in Agent rules.",
                "Atur batas per jam untuk bot yang sibuk di Aturan agen.",
              )}
            </span>
          </li>
          <li>
            <b>2</b>
            <span>
              {t(
                "Use the Workers Paid plan from Cloudflare. It raises these limits a lot.",
                "Pakai paket Workers Paid dari Cloudflare. Ini menaikkan batas ini banyak sekali.",
              )}
            </span>
          </li>
          <li>
            <b>3</b>
            <span>
              {t(
                "Turn on the 80% warning in Alerts so you hear before it happens.",
                "Aktifkan peringatan 80% di Peringatan supaya tahu sebelum terjadi.",
              )}
            </span>
          </li>
        </ol>
        <p class="note">
          <Link href={PATHS.settings}>{t("Back to Settings", "Kembali ke Pengaturan")}</Link>
        </p>
      </section>
    </div>
  );
}
