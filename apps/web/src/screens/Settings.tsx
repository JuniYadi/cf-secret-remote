import { Link } from "wouter-preact";
import { ErrorNote, KeyRow, Meter, SettingsTabs } from "../components/parts.tsx";
import { PageTitle } from "../components/shared.tsx";
import { api, type Identity, type Usage } from "../lib/api.ts";
import { useLang, useSession } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { useLoad } from "../lib/use-load.ts";
import { PATHS, pageCrumbs } from "../routes.ts";
import "../styles/settings.css";

/** The server keeps the audit log at least this long (ADR 19, cron.ts MIN_RETENTION_DAYS). */
const MIN_RETENTION_DAYS = 90;

/**
 * Settings, General tab (design board Settings). Version and sign-in come from /api/health and the signed-in
 * session. Usage and the people count need an admin (GET /usage, GET /identities).
 */
export function SettingsPage() {
  useLang();
  const { me } = useSession();
  const isAdmin = me?.role === "admin";
  const health = useLoad(() => api.health(), "health");
  const usage = useLoad(() => (isAdmin ? api.usage() : Promise.resolve(null)), `usage-${isAdmin}`);
  const people = useLoad(
    () => (isAdmin ? api.identities() : Promise.resolve(null)),
    `people-${isAdmin}`,
  );

  const warning = usage.data?.warning ?? false;
  const deployOk = health.data?.ok === true && !warning;

  return (
    <div class="page-plain settings-page">
      <div>
        <PageTitle crumbs={pageCrumbs("settings")} />
        <p class="sub">
          {t(
            "How your vault is running, how much of the free plan you're using, and who looks after it.",
            "Bagaimana vault-mu berjalan, seberapa banyak paket gratis terpakai, dan siapa yang mengurusnya.",
          )}
        </p>
      </div>
      <SettingsTabs current="general" />

      <section class="card settings-card" aria-labelledby="deploy-title">
        <div class="card-head">
          <h2 id="deploy-title" class="card-title">
            {t("Your deployment", "Deployment-mu")}
          </h2>
          {health.loading ? null : (
            <span class={deployOk ? "pill ok" : "pill warn"}>
              {deployOk ? t("All good", "Semua baik") : t("Check usage", "Periksa pemakaian")}
            </span>
          )}
        </div>
        {health.error ? <ErrorNote error={health.error} /> : null}
        <dl class="kv">
          <KeyRow label={t("Worker version", "Versi Worker")}>
            <span class="mono">{health.data?.version ?? "..."}</span>
          </KeyRow>
          <KeyRow label={t("Address", "Alamat")}>
            <span class="mono">{window.location.host}</span>
          </KeyRow>
          <KeyRow label={t("Sign-in protection", "Perlindungan login")}>
            {t("Active, with Cloudflare Access", "Aktif, dengan Cloudflare Access")}
          </KeyRow>
          {isAdmin ? (
            <KeyRow label={t("People", "Orang")}>
              {people.data ? people.data.filter((p: Identity) => p.kind === "user").length : "..."}
            </KeyRow>
          ) : null}
        </dl>
      </section>

      <section class="card settings-card" aria-labelledby="usage-title">
        <h2 id="usage-title" class="card-title">
          {t("Free plan usage today", "Pemakaian paket gratis hari ini")}
        </h2>
        {isAdmin ? (
          <>
            <ErrorNote error={usage.error} />
            {usage.data ? (
              <UsageBlock usage={usage.data} />
            ) : (
              <p class="sub">{t("Loading...", "Memuat...")}</p>
            )}
          </>
        ) : (
          <p class="sub">
            {t(
              "Ask an admin to see today's usage.",
              "Minta admin untuk melihat pemakaian hari ini.",
            )}
          </p>
        )}
        <h3 class="sub-title">
          {t("What happens at the limit", "Yang terjadi saat batas tercapai")}
        </h3>
        <p class="sub">
          {t(
            "Saving pauses until 00:00 UTC. Opening secrets, signing in and reading Activity keep working.",
            "Penyimpanan dijeda sampai pukul 00:00 UTC. Membuka secret, masuk, dan membaca Aktivitas tetap berjalan.",
          )}
        </p>
      </section>

      <section class="card settings-card" aria-labelledby="log-title">
        <h2 id="log-title" class="card-title">
          {t("Activity log", "Log aktivitas")}
        </h2>
        <dl class="kv">
          <KeyRow label={t("Kept for", "Disimpan selama")}>
            {t(`At least ${MIN_RETENTION_DAYS} days`, `Minimal ${MIN_RETENTION_DAYS} hari`)}
          </KeyRow>
        </dl>
      </section>

      <section class="card settings-card" aria-labelledby="notif-title">
        <h2 id="notif-title" class="card-title">
          {t("Notifications", "Notifikasi")}
        </h2>
        <p class="sub">
          {t(
            "Alert channels (Slack, email) are set up in alert settings.",
            "Saluran peringatan (Slack, email) diatur di pengaturan peringatan.",
          )}
        </p>
        <p class="note">
          <Link href={PATHS.alerts}>{t("Alert settings", "Pengaturan peringatan")}</Link>
        </p>
      </section>
    </div>
  );
}

function UsageBlock({ usage }: { usage: Usage }) {
  useLang();
  return (
    <>
      <Meter
        label={t("Saves and log entries", "Penyimpanan dan entri log")}
        value={usage.writes}
        max={usage.limit}
      />
      <p class="note">
        {t(
          `Day ${usage.day}, UTC. Resets at 00:00 UTC.`,
          `Hari ${usage.day}, UTC. Reset pukul 00:00 UTC.`,
        )}
      </p>
      <p class="note">
        <Link href={PATHS.quota}>{t("What this means for you", "Artinya untukmu")}</Link>
      </p>
    </>
  );
}
