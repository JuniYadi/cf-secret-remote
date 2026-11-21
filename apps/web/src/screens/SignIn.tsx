import { Icon, LangToggle, Mark, PageTitle } from "../components/shared.tsx";
import { useLang } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { pageCrumbs } from "../routes.ts";

/**
 * Sign in. Cloudflare Access does the sign-in at the hostname, so the button reloads the app root
 * and Access takes over. The app never sees a password for the work account.
 */
export function SignInPage() {
  useLang();
  return (
    <div class="split">
      <section class="hero">
        <div class="hero-brand">
          <span class="logo">
            <Mark size={28} />
          </span>
          <span class="brand-name light">cfs</span>
        </div>
        <div class="hero-body">
          <h2 class="hero-title">
            {t("Share secrets with your team, safely.", "Bagikan secret ke tim dengan aman.")}
          </h2>
          <div class="facts">
            <Fact
              icon="lock"
              title={t(
                "Locked before it leaves your device",
                "Dikunci sebelum keluar dari perangkatmu",
              )}
              text={t(
                "Only the people you choose can open a secret. Not even our server can read it.",
                "Hanya orang yang kamu pilih yang bisa membukanya. Server kami pun tidak bisa membacanya.",
              )}
            />
            <Fact
              icon="activity"
              title={t("See who opened what", "Lihat siapa membuka apa")}
              text={t(
                "Every access is recorded, including by AI agents.",
                "Setiap akses tercatat, termasuk oleh agen AI.",
              )}
            />
            <Fact
              icon="apps"
              title={t("New teammate? One command.", "Anggota baru? Cukup satu perintah.")}
              text={t(
                "They can run the project without ever seeing the passwords.",
                "Mereka bisa menjalankan proyek tanpa pernah melihat passwordnya.",
              )}
            />
          </div>
        </div>
        <span class="hero-foot">{t("Runs on Cloudflare.", "Berjalan di Cloudflare.")}</span>
      </section>
      <section class="form-side">
        <div class="form-top">
          <LangToggle />
        </div>
        <div class="form-center">
          <div class="form-col">
            <div>
              <PageTitle crumbs={pageCrumbs("signIn")} />
              <p class="sub">
                {t(
                  "Use your work account. After that you'll unlock the vault with your own vault password.",
                  "Pakai akun kerjamu. Setelah itu kamu membuka vault dengan vault password milikmu sendiri.",
                )}
              </p>
            </div>
            <a class="btn pri" href="/">
              {t("Sign in with your work account", "Masuk dengan akun kerja")}
            </a>
          </div>
        </div>
      </section>
    </div>
  );
}

function Fact({
  icon,
  title,
  text,
}: {
  icon: "lock" | "activity" | "apps";
  title: string;
  text: string;
}) {
  return (
    <div class="fact">
      <div class="dot">
        <Icon name={icon} size={15} />
      </div>
      <div>
        <b>{title}</b>
        <span>{text}</span>
      </div>
    </div>
  );
}
