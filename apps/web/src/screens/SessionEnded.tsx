import { Icon, PageTitle, Standalone } from "../components/shared.tsx";
import { useLang } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { pageCrumbs } from "../routes.ts";

/** Shown after Access signs the person out, or when the Worker answers 401. */
export function SessionEndedPage() {
  useLang();
  return (
    <Standalone>
      <div class="card center narrow">
        <div class="icon-circle warn">
          <Icon name="clock" size={28} />
        </div>
        <div>
          <PageTitle crumbs={pageCrumbs("sessionEnded")} />
          <p class="sub">
            {t(
              "For your safety you're signed out after 12 hours. Sign in again to carry on.",
              "Demi keamananmu, kamu keluar otomatis setelah 12 jam. Masuk lagi untuk melanjutkan.",
            )}
          </p>
        </div>
        <a class="btn pri block" href="/">
          {t("Sign in again", "Masuk lagi")}
        </a>
        <p class="note">
          {t(
            "Anything you were editing and hadn't saved wasn't kept, because unsaved values never leave your browser.",
            "Yang sedang kamu edit dan belum disimpan tidak tersimpan, karena nilai yang belum disimpan tidak pernah meninggalkan browsermu.",
          )}
        </p>
      </div>
    </Standalone>
  );
}
