import { Link } from "wouter-preact";
import { Icon, PageTitle } from "../components/shared.tsx";
import { useLang } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { PATHS, pageCrumbs } from "../routes.ts";

/**
 * A secret the person's permissions do not cover. Shown inside the shell with a breadcrumb.
 * The "Ask for access" flow arrives with access requests (ADR 16).
 */
export function AccessDeniedPage({ name }: { name: string }) {
  useLang();
  return (
    <div class="denied">
      <div class="crumbs-spacer">
        <PageTitle crumbs={pageCrumbs("denied", name)} />
      </div>
      <div class="card denied-card">
        <div class="icon-circle danger">
          <Icon name="warning" size={26} />
        </div>
        <div>
          <p class="sub">
            {t(
              `You can't open ${name}, because your permissions don't include it.`,
              `Kamu tidak bisa membuka ${name}, karena izinmu tidak mencakupnya.`,
            )}
          </p>
        </div>
        <ul class="bullets">
          <li>
            {t(
              "Production secrets are limited to the Admin and Release roles.",
              "Secret produksi dibatasi untuk peran Admin dan Release.",
            )}
          </li>
          <li>
            {t(
              "You can still see that it exists, but not what's inside.",
              "Kamu masih bisa melihat bahwa ia ada, tapi tidak isinya.",
            )}
          </li>
        </ul>
        <div class="row-actions">
          <Link class="btn ghost" href={PATHS.secrets}>
            {t("Back to Secrets", "Kembali ke Secret")}
          </Link>
        </div>
        <p class="note">
          {t(
            "This attempt was recorded in Activity, so your team can see it was you.",
            "Percobaan ini tercatat di Aktivitas, jadi tim bisa melihat bahwa itu kamu.",
          )}
        </p>
      </div>
    </div>
  );
}
