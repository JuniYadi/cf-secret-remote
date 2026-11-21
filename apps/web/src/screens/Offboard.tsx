import { useState } from "preact/hooks";
import { ErrorNote, KeyRow } from "../components/parts.tsx";
import { Icon, PageTitle } from "../components/shared.tsx";
import { api, type OffboardPlan } from "../lib/api.ts";
import { useLang, useSession } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import {
  OffboardBlocked,
  type OffboardEvent,
  type OffboardResult,
  type OffboardStep,
  reportText,
  runOffboarding,
} from "../lib/offboard.ts";
import { removeMemberFromGroup } from "../lib/rotation.ts";
import { useLoad } from "../lib/use-load.ts";
import { pageCrumbs } from "../routes.ts";
import "../styles/settings.css";

interface PlanView {
  plan: OffboardPlan;
  /** Secrets in the groups the person leaves. They get new keys. */
  lockCount: number;
}

async function loadPlanView(personId: string): Promise<PlanView> {
  const [plan, secrets] = await Promise.all([api.offboardPlan(personId), api.secrets()]);
  const groups = new Set(plan.groups);
  return {
    plan,
    lockCount: secrets.filter((s) => groups.has(s.path.split("/")[0] ?? "")).length,
  };
}

/**
 * Offboard a teammate (design board Offboard). Shows the plan from the server, runs the steps in the browser
 * (group rotation needs the keys, ADR 14), then shows the names-only report and the identity-provider reminder.
 */
export function OffboardPage() {
  useLang();
  const { me } = useSession();
  const directory = useLoad(() => api.identities(), "identities");
  const [personId, setPersonId] = useState("");
  const view = useLoad(
    () => (personId ? loadPlanView(personId) : Promise.resolve(null)),
    `plan-${personId}`,
  );
  const [choices, setChoices] = useState<Record<string, string>>({});
  const [running, setRunning] = useState(false);
  const [events, setEvents] = useState<OffboardEvent[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [blocked, setBlocked] = useState<OffboardPlan | null>(null);
  const [result, setResult] = useState<OffboardResult | null>(null);
  const [copied, setCopied] = useState(false);

  if (me?.role !== "admin") {
    return (
      <div class="page-plain">
        <PageTitle crumbs={pageCrumbs("offboard")} />
        <p class="sub">{t("Only admins can see this.", "Hanya admin yang bisa melihat ini.")}</p>
      </div>
    );
  }

  const people = (directory.data ?? []).filter((i) => i.kind === "user" && i.id !== me.id);
  const activeUsers = people.filter((i) => i.status === "active");
  const person = people.find((i) => i.id === personId) ?? null;
  const plan = view.data?.plan ?? null;

  const myId = me.id;

  async function run() {
    if (!plan || !person || running) return;
    setRunning(true);
    setError(null);
    setBlocked(null);
    setEvents([]);
    try {
      const out = await runOffboarding(
        {
          plan: (id) => api.offboardPlan(id),
          removeFromGroup: (prefix, id) => removeMemberFromGroup(prefix, id, myId, api),
          reassignApp: (id, appId, ownerId) => api.offboardReassign(id, appId, ownerId),
          disableApp: (appId) => api.disableApp(appId),
          finish: (id) => api.offboardFinish(id),
        },
        person.id,
        { reassign: choices },
        (event) => setEvents((list) => [...list, event]),
      );
      setResult(out);
      setPersonId("");
    } catch (err) {
      if (err instanceof OffboardBlocked) setBlocked(err.plan);
      else setError(err);
    } finally {
      setRunning(false);
    }
  }

  async function copyReport() {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(reportText(result.report, result.person.name));
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  if (result) {
    return (
      <div class="page-plain offboard-page">
        <PageTitle crumbs={pageCrumbs("offboard")} />
        <section class="card settings-card" role="status" aria-labelledby="done-title">
          <h2 id="done-title" class="card-title">
            {t(`${result.person.name} is offboarded`, `${result.person.name} sudah dikeluarkan`)}
          </h2>
          <dl class="kv">
            <KeyRow label={t("Devices signed out", "Perangkat yang keluar")}>
              {result.finish.sessionsEnded}
            </KeyRow>
            <KeyRow label={t("Policy links removed", "Tautan kebijakan dihapus")}>
              {result.finish.policiesRemoved}
            </KeyRow>
          </dl>
        </section>

        <section class="card settings-card" aria-labelledby="report-title">
          <div class="card-head">
            <h2 id="report-title" class="card-title">
              {t("Then change these at the source", "Lalu ganti ini di sumbernya")}
            </h2>
            <button type="button" class="btn ghost sm" onClick={copyReport}>
              {copied ? t("Copied", "Tersalin") : t("Copy report", "Salin laporan")}
            </button>
          </div>
          <p class="sub">
            {t(
              `They opened these values in the last ${result.report.windowDays} days. A new lock can't make them forget them. Names only, no values.`,
              `Mereka membuka nilai ini dalam ${result.report.windowDays} hari terakhir. Kunci baru tidak bisa membuat mereka lupa. Hanya nama, tanpa nilai.`,
            )}
          </p>
          {result.report.secrets.length === 0 ? (
            <p class="sub">
              {t("Nothing was opened in that window.", "Tidak ada yang dibuka dalam rentang itu.")}
            </p>
          ) : (
            <table class="data-table">
              <thead>
                <tr>
                  <th scope="col">{t("Secret", "Secret")}</th>
                  <th scope="col">{t("Names", "Nama")}</th>
                  <th scope="col">{t("Last opened", "Terakhir dibuka")}</th>
                </tr>
              </thead>
              <tbody>
                {result.report.secrets.map((s) => (
                  <tr key={s.path}>
                    <td class="mono">{s.path}</td>
                    <td class="mono">{s.names.length ? s.names.join(", ") : "-"}</td>
                    <td>
                      {new Date(s.lastOpened * 1000).toISOString().slice(0, 16).replace("T", " ")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        <section class="card side-card" aria-labelledby="idp-title">
          <h2 id="idp-title" class="card-title">
            {t("Also remove them from your company login.", "Hapus juga dari login perusahaanmu.")}
          </h2>
          <p class="sub">
            {t(
              "Signing in is managed there, not here. Until you do, they can still sign in, though they can't open anything.",
              "Proses masuk diatur di sana, bukan di sini. Sebelum itu, mereka masih bisa masuk, tapi tidak bisa membuka apa pun.",
            )}
          </p>
        </section>

        <button type="button" class="btn ghost" onClick={() => setResult(null)}>
          {t("Offboard someone else", "Keluarkan orang lain")}
        </button>
      </div>
    );
  }

  return (
    <div class="page-plain offboard-page">
      <div>
        <PageTitle crumbs={pageCrumbs("offboard")} />
        <p class="sub">
          {t(
            "Do everything in one go when someone leaves: remove them from groups, lock the secrets again, end their sessions, and see what to change.",
            "Lakukan semuanya sekaligus saat seseorang pergi: keluarkan dari grup, kunci ulang secret, akhiri sesinya, dan lihat apa yang perlu diganti.",
          )}
        </p>
      </div>

      <section class="card settings-card" aria-labelledby="who-title">
        <div class="field">
          <label for="offboard-who" id="who-title">
            {t("Who is leaving?", "Siapa yang pergi?")}
          </label>
          <select
            id="offboard-who"
            value={personId}
            onChange={(e) => {
              setPersonId(e.currentTarget.value);
              setChoices({});
              setBlocked(null);
              setError(null);
            }}
          >
            <option value="">{t("Choose a person", "Pilih orang")}</option>
            {people.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
                {p.status === "disabled" ? t(" (disabled)", " (nonaktif)") : ""}
              </option>
            ))}
          </select>
        </div>
        <ErrorNote error={directory.error ?? view.error} />
      </section>

      {view.loading && personId ? (
        <p class="sub">{t("Loading the plan...", "Memuat rencana...")}</p>
      ) : null}

      {plan && person ? (
        <>
          <section class="card settings-card" aria-labelledby="will-title">
            <h2 id="will-title" class="card-title">
              {t("This will", "Ini akan")}
            </h2>
            <ul class="plan-list">
              <li>
                {plan.groups.length
                  ? t(
                      `Remove ${person.name} from ${plan.groups.length} group(s): ${plan.groups.join(", ")}`,
                      `Keluarkan ${person.name} dari ${plan.groups.length} grup: ${plan.groups.join(", ")}`,
                    )
                  : t("Not in any group", "Tidak ada di grup mana pun")}
              </li>
              {plan.groups.length > 0 && view.data ? (
                <li>
                  {t(
                    `Lock ${view.data.lockCount} secret(s) again with new keys. Done in your browser, about a minute.`,
                    `Mengunci ulang ${view.data.lockCount} secret dengan kunci baru. Dilakukan di browsermu, sekitar satu menit.`,
                  )}
                </li>
              ) : null}
              <li>
                {t(
                  `End ${plan.sessions.length} signed-in device(s)`,
                  `Akhiri ${plan.sessions.length} perangkat yang masuk`,
                )}
              </li>
            </ul>

            {plan.blockers.twoAdmins ? (
              <div class="warn-box" role="status">
                <Icon name="warning" size={18} />
                <span>
                  {t(
                    "They are one of two admins with a vault. Make another admin first, then offboard.",
                    "Mereka salah satu dari dua admin yang memegang vault. Jadikan admin lain dulu, lalu keluarkan.",
                  )}
                </span>
              </div>
            ) : null}
          </section>

          {plan.apps.some((a) => a.status === "active") ? (
            <section class="card settings-card" aria-labelledby="apps-title">
              <h2 id="apps-title" class="card-title">
                {t("Apps they own", "Aplikasi miliknya")}
              </h2>
              <table class="data-table">
                <tbody>
                  {plan.apps
                    .filter((a) => a.status === "active")
                    .map((a) => (
                      <tr key={a.id}>
                        <td>{a.name}</td>
                        <td class="right">
                          <label class="visually-hidden" for={`app-${a.id}`}>
                            {t(`New owner for ${a.name}`, `Pemilik baru untuk ${a.name}`)}
                          </label>
                          <select
                            id={`app-${a.id}`}
                            value={choices[a.id] ?? ""}
                            onChange={(e) => {
                              const v = e.currentTarget.value;
                              setChoices((c) => {
                                const next = { ...c };
                                if (v) next[a.id] = v;
                                else delete next[a.id];
                                return next;
                              });
                            }}
                          >
                            <option value="">{t("Disable the app", "Nonaktifkan aplikasi")}</option>
                            {activeUsers.map((u) => (
                              <option key={u.id} value={u.id}>
                                {t(`Give to ${u.name}`, `Berikan ke ${u.name}`)}
                              </option>
                            ))}
                          </select>
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </section>
          ) : null}

          {blocked ? (
            <p class="field-error" role="alert">
              {t(
                "Offboarding is not finished. Something still blocks it: check the groups and apps above, then try again.",
                "Pengeluaran belum selesai. Masih ada yang menghalangi: periksa grup dan aplikasi di atas, lalu coba lagi.",
              )}
            </p>
          ) : null}
          <ErrorNote error={error} />

          {events.length > 0 ? (
            <ol class="plain-list" aria-label={t("Progress", "Kemajuan")}>
              {events
                .filter((e) => e.status === "done")
                .map((e, i) => (
                  <li key={`${i}-${e.step.kind}`}>{describe(e.step)}</li>
                ))}
            </ol>
          ) : null}

          <div class="row-between">
            <span class="note">
              {t(
                "If a step fails, run this again. Finished steps are not repeated.",
                "Jika ada langkah yang gagal, jalankan lagi. Langkah yang selesai tidak diulang.",
              )}
            </span>
            <button
              type="button"
              class="btn danger"
              disabled={running || plan.blockers.twoAdmins}
              onClick={run}
            >
              {running
                ? t("Working...", "Memproses...")
                : t(
                    `Offboard ${person.name} and re-lock`,
                    `Keluarkan ${person.name} dan kunci ulang`,
                  )}
            </button>
          </div>
        </>
      ) : null}
    </div>
  );
}

function describe(step: OffboardStep | { kind: "finish" }): string {
  switch (step.kind) {
    case "remove-group":
      return t(
        `Removed from ${step.prefix} (key rotated)`,
        `Dikeluarkan dari ${step.prefix} (kunci diganti)`,
      );
    case "reassign-app":
      return t(`${step.appName} given to a new owner`, `${step.appName} diberikan ke pemilik baru`);
    case "disable-app":
      return t(`${step.appName} disabled`, `${step.appName} dinonaktifkan`);
    default:
      return t("Person disabled, sessions ended", "Orang dinonaktifkan, sesi diakhiri");
  }
}
