import { Link } from "wouter-preact";
import { Icon, PageTitle, Standalone } from "../components/shared.tsx";
import { useLang } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { PATHS, pageCrumbs } from "../routes.ts";
import "../styles/activity.css";

/** Shown after the terminal is authorized (ADR 11, the Cli-Done board). Ends the one-task flow. */
export function CliDonePage() {
  useLang();
  return (
    <Standalone>
      <div class="card authorize-card center">
        <div class="done-icon" aria-hidden="true">
          <Icon name="check" size={28} />
        </div>
        <PageTitle crumbs={pageCrumbs("cliDone")} />
        <p class="sub">
          {t(
            "Go back to your terminal. You can close this tab.",
            "Kembali ke terminalmu. Tab ini boleh ditutup.",
          )}
        </p>
        <pre class="code-block">
          <span class="c">
            {t("# open your vault on this device", "# buka vault di perangkat ini")}
          </span>
          {"\n"}$ cfs unlock{"\n"}
          <span class="c">{t("# then run your project", "# lalu jalankan proyekmu")}</span>
          {"\n"}$ cfs run -- bun run dev
        </pre>
        <p class="note">
          {t(
            "cfs asks for your vault password once, then stays unlocked for an hour.",
            "cfs meminta vault password sekali, lalu tetap terbuka selama satu jam.",
          )}
        </p>
        <Link href={PATHS.devices}>
          {t("See all signed-in devices", "Lihat semua perangkat yang masuk")}
        </Link>
      </div>
    </Standalone>
  );
}
