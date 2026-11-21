// Access history tab (ADR 22, DESIGN.md "Riwayat akses per secret"). The numbers come from GET /secret/history,
// which counts fetches of the sealed value over 30 days. A fetch is "opened". What someone did with the
// value afterwards is not visible to the server, and the page says so.

import { useEffect, useState } from "preact/hooks";
import { InfoBox, Pill, SecretTabs, WarnBox } from "../components/secrets-ui.tsx";
import { PageTitle } from "../components/shared.tsx";
import { api, type SecretHistory } from "../lib/api.ts";
import { useLang } from "../lib/hooks.ts";
import { currentLang, t } from "../lib/i18n.ts";
import { relativeTime } from "../lib/secrets.ts";
import { pageCrumbs } from "../routes.ts";

export function SecretHistoryPage({ name }: { name: string }) {
  useLang();
  const [history, setHistory] = useState<SecretHistory | null>(null);
  const [failed, setFailed] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let live = true;
    setFailed(false);
    api
      .secretHistory(name)
      .then((h) => {
        if (!live) return;
        if (h && Array.isArray(h.people)) setHistory(h);
        else setFailed(true);
      })
      .catch(() => {
        if (live) setFailed(true);
      });
    return () => {
      live = false;
    };
  }, [name, attempt]);

  const head = (
    <div class="top">
      <div>
        <PageTitle crumbs={pageCrumbs("secretHistory", name)} />
        <p class="sub">
          {t(
            `Everyone who has opened ${name}, which version they saw, and when. Use it to decide which values to change after someone leaves.`,
            `Semua orang yang pernah membuka ${name}, versi mana yang mereka lihat, dan kapan. Pakai ini untuk memutuskan nilai mana yang perlu diganti setelah seseorang pergi.`,
          )}
        </p>
      </div>
    </div>
  );

  if (history === null) {
    return (
      <div class="secrets-page">
        {head}
        <SecretTabs name={name} active="history" />
        {failed ? (
          <div class="card center narrow">
            <p class="sub">
              {t("We couldn't load the access history.", "Riwayat akses tidak bisa dimuat.")}
            </p>
            <button type="button" class="btn" onClick={() => setAttempt((n) => n + 1)}>
              {t("Try again", "Coba lagi")}
            </button>
          </div>
        ) : (
          <p class="sub" role="status">
            {t("Loading...", "Memuat...")}
          </p>
        )}
      </div>
    );
  }

  const now = Date.now();
  const lang = currentLang();
  return (
    <div class="secrets-page">
      {head}
      <SecretTabs name={name} active="history" />

      <div class="stats">
        <div class="card stat">
          <b>{history.opens}</b>
          <span>
            {t(
              `opens in the last ${history.windowDays} days`,
              `pembukaan dalam ${history.windowDays} hari terakhir`,
            )}
          </span>
        </div>
        <div class="card stat">
          <b>{history.readers}</b>
          <span>{t("people and apps have opened it", "orang dan aplikasi pernah membukanya")}</span>
        </div>
        <div class="card stat">
          <b class="stat-name">{history.lastReader?.who ?? "—"}</b>
          <span>
            {history.lastReader
              ? t(
                  `opened it most recently, ${relativeTime(history.lastReader.at, now, lang)}`,
                  `terakhir membukanya, ${relativeTime(history.lastReader.at, now, lang)}`,
                )
              : t("nobody has opened it yet", "belum ada yang membukanya")}
          </span>
        </div>
        <div class={`card stat${history.lostAccess > 0 ? " stat-warn" : ""}`}>
          <b>{history.lostAccess}</b>
          <span>
            {t(
              "opened it but no longer has access",
              "pernah membukanya tapi tidak lagi punya akses",
            )}
          </span>
        </div>
      </div>

      {history.lostAccess > 0 && (
        <WarnBox>
          <b>{t("Careful with old values.", "Hati-hati dengan nilai lama.")}</b>{" "}
          {t(
            "Someone who lost access may still have copies of the values they opened. Change those values at their source, such as the database or the API provider.",
            "Seseorang yang kehilangan akses mungkin masih punya salinan nilai yang pernah dibukanya. Ganti nilai itu di sumbernya, seperti database atau penyedia API.",
          )}
        </WarnBox>
      )}

      <div class="card tw">
        <div class="table-head">
          <h2>
            {t("Who has seen the current values", "Siapa yang pernah melihat nilai saat ini")}
          </h2>
          <span class="note">
            {t(`Last ${history.windowDays} days`, `${history.windowDays} hari terakhir`)}
          </span>
        </div>
        {history.people.length === 0 ? (
          <p class="sub center-line">
            {t(
              "No one has opened this secret in the last 30 days.",
              "Belum ada yang membuka secret ini dalam 30 hari terakhir.",
            )}
          </p>
        ) : (
          <table class="tbl">
            <thead>
              <tr>
                <th scope="col">{t("Who", "Siapa")}</th>
                <th scope="col">{t("Times opened", "Jumlah dibuka")}</th>
                <th scope="col">{t("Last opened", "Terakhir dibuka")}</th>
                <th scope="col">{t("Version", "Versi")}</th>
                <th scope="col">{t("Access now", "Akses sekarang")}</th>
              </tr>
            </thead>
            <tbody>
              {history.people.map((p) => (
                <tr key={p.name} class={p.hasAccess ? undefined : "flag"}>
                  <td>
                    <b>{p.name}</b>
                  </td>
                  <td>{p.opens}</td>
                  <td>{relativeTime(p.lastOpened, now, lang)}</td>
                  <td>{p.lastVersion}</td>
                  <td>
                    {p.hasAccess ? (
                      <Pill tone="ok">{t("Has access", "Punya akses")}</Pill>
                    ) : (
                      <Pill tone="warn">{t("Removed", "Dikeluarkan")}</Pill>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <InfoBox>
        <b>{t("What “opened” means:", "Arti “dibuka”:")}</b>{" "}
        {t(
          "someone fetched the locked values. We can't see what they did with them afterwards, and the values themselves are never recorded.",
          "seseorang mengambil nilai terkunci. Kami tidak bisa melihat apa yang mereka lakukan sesudahnya, dan nilai aslinya tidak pernah dicatat.",
        )}
      </InfoBox>
    </div>
  );
}
