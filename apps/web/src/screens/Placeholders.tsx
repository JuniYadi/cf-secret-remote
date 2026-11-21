import { Link } from "wouter-preact";
import { PageTitle, Standalone } from "../components/shared.tsx";
import { useLang } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { type Crumb, PATHS, type PageId, pageCrumbs } from "../routes.ts";

/**
 * Screens that come in later parts of the web app (ADR 24, build order). The sidebar links here
 * so the navigation is complete from the start.
 */
export function ComingSoonPage({ id, shell }: { id: PageId; shell: boolean }) {
  useLang();
  const body = (
    <div class="card center narrow">
      <PageTitle crumbs={pageCrumbs(id)} />
      <p class="sub">
        {t("This screen is coming in a later release.", "Layar ini hadir di rilis berikutnya.")}
      </p>
    </div>
  );
  return shell ? <div class="page-plain">{body}</div> : <Standalone>{body}</Standalone>;
}

export function NotFoundPage() {
  useLang();
  return (
    <Standalone>
      <div class="card center narrow">
        <PageTitle crumbs={pageCrumbs("notFound")} />
        <p class="sub">
          {t("The page you asked for doesn't exist.", "Halaman yang kamu cari tidak ada.")}
        </p>
        <Link class="btn pri block" href={PATHS.secrets}>
          {t("Go to Secrets", "Ke Secret")}
        </Link>
      </div>
    </Standalone>
  );
}

/** While /whoami is in flight. */
export function LoadingPage() {
  useLang();
  return (
    <div class="loading" role="status">
      {t("Loading...", "Memuat...")}
    </div>
  );
}

/** /whoami failed for a reason other than an expired session. */
export function LoadErrorPage({ onRetry }: { onRetry: () => void }) {
  useLang();
  const crumbs: Crumb[] = [{ label: t("Couldn't load cfs", "cfs tidak bisa dimuat") }];
  return (
    <Standalone>
      <div class="card center narrow">
        <PageTitle crumbs={crumbs} />
        <p class="sub">
          {t(
            "We couldn't reach the server. Check your connection and try again.",
            "Kami tidak bisa menghubungi server. Periksa koneksi lalu coba lagi.",
          )}
        </p>
        <button type="button" class="btn pri block" onClick={onRetry}>
          {t("Try again", "Coba lagi")}
        </button>
      </div>
    </Standalone>
  );
}
