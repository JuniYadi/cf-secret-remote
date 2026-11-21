import { useEffect, useState } from "preact/hooks";
import { PageTitle } from "../components/shared.tsx";
import { Tabs } from "../components/Tabs.tsx";
import {
  ACTION_NAMES,
  type AuditFilters,
  auditQuery,
  chainState,
  DATE_RANGE_SECONDS,
  type DateRange,
  formatClock,
  formatCount,
  formatTime,
  meterState,
  NO_FILTERS,
  PAGE_SIZE,
  usageLine,
  validPathFilter,
} from "../lib/activity.ts";
import { type AuditRow, api, type Usage, type Verify } from "../lib/api.ts";
import { useLang, useSession } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { messageFor } from "../lib/messages.ts";
import { PATHS, pageCrumbs } from "../routes.ts";
import "../styles/activity.css";

const RANGE_LABEL: Record<DateRange, () => string> = {
  "24h": () => t("Last 24 hours", "24 jam terakhir"),
  "7d": () => t("Last 7 days", "7 hari terakhir"),
  "30d": () => t("Last 30 days", "30 hari terakhir"),
  all: () => t("All kept", "Semua yang disimpan"),
};

const RESULT_LABEL = {
  ok: () => t("OK", "Berhasil"),
  denied: () => t("Denied", "Ditolak"),
  error: () => t("Error", "Galat"),
} as const;

/** Activity (ADR 6, 19): the log, the free-tier meter and the chain status. Admins only, as the Worker enforces. */
export function ActivityPage() {
  useLang();
  const { me } = useSession();
  return (
    <div class="page-plain activity-page">
      <PageTitle crumbs={pageCrumbs("activity")} />
      <p class="sub activity-sub">
        {t(
          "Who opened what, when, and why. Records can't be edited or deleted. Old records are removed only after the retention period, and a checkpoint is saved first.",
          "Siapa membuka apa, kapan, dan untuk apa. Catatan tidak bisa diubah atau dihapus. Catatan lama dihapus hanya setelah masa simpannya habis, dan titik periksa disimpan lebih dulu.",
        )}
      </p>
      {me?.role === "admin" ? <ActivityBody /> : <MemberNote />}
    </div>
  );
}

function MemberNote() {
  useLang();
  return (
    <div class="card activity-card">
      <p class="note">
        {t(
          "Activity is for admins. Your own access requests are under Permissions.",
          "Aktivitas hanya untuk admin. Permintaan aksesmu ada di Izin.",
        )}
      </p>
    </div>
  );
}

function ActivityBody() {
  useLang();
  return (
    <>
      <Tabs
        label={t("Activity sections", "Bagian aktivitas")}
        current={PATHS.activity}
        items={[
          { href: PATHS.activity, label: t("Log", "Log") },
          { href: PATHS.alerts, label: t("Alerts", "Peringatan") },
        ]}
      />
      <div class="activity-top">
        <UsageMeter />
        <ChainPanel />
      </div>
      <LogTable />
    </>
  );
}

/** The free-tier write meter (ADR 19). It warns at 80% of the daily quota. */
function UsageMeter() {
  const lang = useLang();
  const [usage, setUsage] = useState<Usage | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let live = true;
    api
      .usage()
      .then((u) => live && setUsage(u))
      .catch(() => live && setFailed(true));
    return () => {
      live = false;
    };
  }, []);

  if (failed) {
    return (
      <section class="card activity-card" aria-labelledby="meter-title">
        <h2 id="meter-title">{t("Free plan usage today", "Pemakaian paket gratis hari ini")}</h2>
        <p class="note">{t("Usage isn't available right now.", "Pemakaian belum bisa dimuat.")}</p>
      </section>
    );
  }
  if (usage === null) {
    return (
      <section class="card activity-card" aria-labelledby="meter-title">
        <h2 id="meter-title">{t("Free plan usage today", "Pemakaian paket gratis hari ini")}</h2>
        <p class="note" role="status">
          {t("Loading...", "Memuat...")}
        </p>
      </section>
    );
  }

  const state = meterState(usage.writes, usage.limit);
  return (
    <section class="card activity-card" aria-labelledby="meter-title">
      <div class="row-between">
        <h2 id="meter-title">{t("Free plan usage today", "Pemakaian paket gratis hari ini")}</h2>
        <span class="muted">{usageLine(usage, lang)}</span>
      </div>
      <div class={`usage-meter${state.warn ? " warn" : ""}`}>
        <progress
          class="usage-bar"
          max={usage.limit}
          value={usage.writes}
          aria-labelledby="meter-title"
        />
        <u aria-hidden="true" />
      </div>
      <p class="note">
        {state.warn
          ? t(
              `You've used ${state.percent}% of today's free writes. Once it's full, secret writes wait until 00:00 UTC. An agent that opens secrets in a loop uses this up fast. Set a limit in Agent rules.`,
              `Kamu sudah memakai ${state.percent}% dari tulis gratis hari ini. Saat penuh, penulisan secret menunggu sampai 00:00 UTC. Agen yang membuka secret berulang cepat menghabiskannya. Atur batas di Aturan agen.`,
            )
          : t(
              "You'll get a warning at 80%. An agent that opens secrets in a loop uses this up fast. Set a limit in Agent rules.",
              "Kamu akan diberi peringatan di 80%. Agen yang membuka secret berulang cepat menghabiskannya. Atur batas di Aturan agen.",
            )}
      </p>
    </section>
  );
}

/** The hash chain check (ADR 6, 19). "Broken" means an entry no longer matches the one before it. */
function ChainPanel() {
  useLang();
  const [verify, setVerify] = useState<Verify | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function check() {
    setBusy(true);
    setError(null);
    try {
      setVerify(await api.verify());
    } catch (err) {
      setError(messageFor(err));
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    void check();
  }, []);

  const state = chainState(verify);
  const pill =
    state === "verified"
      ? { cls: "pill ok", text: t("Verified", "Terverifikasi") }
      : state === "broken"
        ? { cls: "pill bad", text: t("Broken", "Rusak") }
        : { cls: "pill", text: t("Not checked yet", "Belum diperiksa") };

  return (
    <section class="card activity-card" aria-labelledby="chain-title">
      <div class="row-between">
        <h2 id="chain-title">{t("Log integrity", "Integritas log")}</h2>
        <span class={pill.cls}>{pill.text}</span>
      </div>
      {error !== null && (
        <p class="field-error" role="alert">
          {error}
        </p>
      )}
      {verify !== null && state === "verified" && (
        <p class="note">
          {t(
            `${formatCount(verify.rows, "en")} entries are chained together. Nothing has been changed or removed.`,
            `${formatCount(verify.rows, "id")} entri saling terikat. Tidak ada yang diubah atau dihapus.`,
          )}
        </p>
      )}
      {verify !== null && state === "broken" && (
        <p class="warn-box" role="status">
          {verify.firstBadSeq !== null
            ? t(
                `The check stopped at entry #${verify.firstBadSeq}. That entry or the one before it was changed or removed.`,
                `Pemeriksaan berhenti di entri #${verify.firstBadSeq}. Entri itu atau entri sebelumnya diubah atau dihapus.`,
              )
            : t(
                "A checkpoint no longer matches the log. An entry was changed or removed.",
                "Sebuah titik periksa tidak lagi cocok dengan log. Ada entri yang diubah atau dihapus.",
              )}
        </p>
      )}
      {verify === null && state === "unchecked" && (
        <p class="note">{t("Checking the log...", "Memeriksa log...")}</p>
      )}
      <p class="note">
        {t(
          "Every entry stores a hash of the one before it. If an entry is edited or deleted, the link breaks, and this check says where.",
          "Tiap entri menyimpan hash entri sebelumnya. Jika entri diubah atau dihapus, ikatannya putus, dan pemeriksaan ini menunjukkan di mana.",
        )}
      </p>
      {verify !== null && (
        <dl class="kv-list">
          <div>
            <dt>{t("Daily checkpoints", "Titik periksa harian")}</dt>
            <dd>
              {t(
                `${verify.checkpoints.verified} matched of ${verify.checkpoints.stored}`,
                `${verify.checkpoints.verified} cocok dari ${verify.checkpoints.stored}`,
              )}
              {verify.checkpoints.mismatched.length > 0 &&
                t(
                  `, ${verify.checkpoints.mismatched.length} do not match`,
                  `, ${verify.checkpoints.mismatched.length} tidak cocok`,
                )}
            </dd>
          </div>
          <div>
            <dt>{t("Latest hash", "Hash terbaru")}</dt>
            <dd class="mono small">{verify.head.slice(0, 16)}...</dd>
          </div>
        </dl>
      )}
      <div class="row-between">
        <span class="note">
          {t("Checked by the Worker on request.", "Diperiksa oleh server saat diminta.")}
        </span>
        <button type="button" class="btn ghost sm" onClick={() => void check()} disabled={busy}>
          {busy ? t("Checking...", "Memeriksa...") : t("Check now", "Periksa sekarang")}
        </button>
      </div>
    </section>
  );
}

/** The log table with filters and paging. Filters apply when the form is sent. */
function LogTable() {
  const lang = useLang();
  const [draft, setDraft] = useState<AuditFilters>(NO_FILTERS);
  const [applied, setApplied] = useState<AuditFilters>(NO_FILTERS);
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [pathError, setPathError] = useState(false);

  async function load(filters: AuditFilters, before?: number) {
    setLoading(true);
    setError(null);
    try {
      const page = await api.audit({ ...auditQuery(filters, nowSeconds(), before) });
      setRows((prev) => (before === undefined ? page : [...prev, ...page]));
      setHasMore(page.length === PAGE_SIZE);
    } catch (err) {
      setError(messageFor(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load(applied);
  }, [applied]);

  function onSubmit(event: Event) {
    event.preventDefault();
    if (!validPathFilter(draft.path)) {
      setPathError(true);
      return;
    }
    setPathError(false);
    setApplied({ ...draft });
  }

  const last = rows[rows.length - 1];

  return (
    <section class="activity-log" aria-labelledby="log-title">
      <h2 id="log-title" class="visually-hidden">
        {t("Log", "Log")}
      </h2>
      <form class="filters" onSubmit={onSubmit} aria-label={t("Filter the log", "Saring log")}>
        <div class="field">
          <label for="f-who">{t("Who", "Siapa")}</label>
          <input
            id="f-who"
            type="text"
            value={draft.who}
            placeholder={t("Everyone", "Semua")}
            onInput={(e) => setDraft({ ...draft, who: e.currentTarget.value })}
            autocomplete="off"
          />
        </div>
        <div class="field">
          <label for="f-action">{t("What", "Apa")}</label>
          <select
            id="f-action"
            value={draft.action}
            onChange={(e) => setDraft({ ...draft, action: e.currentTarget.value })}
          >
            <option value="">{t("All", "Semua")}</option>
            {ACTION_NAMES.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </div>
        <div class="field">
          <label for="f-path">{t("Secret", "Secret")}</label>
          <input
            id="f-path"
            type="text"
            value={draft.path}
            placeholder="backend/*"
            onInput={(e) => setDraft({ ...draft, path: e.currentTarget.value })}
            aria-invalid={pathError ? "true" : undefined}
            aria-describedby={pathError ? "f-path-error" : "f-path-hint"}
            autocomplete="off"
            class="mono"
          />
          {pathError ? (
            <span id="f-path-error" class="field-error">
              {t(
                "Use a path such as myapp/prod, or a prefix ending in * such as backend/*.",
                "Pakai path seperti myapp/prod, atau awalan yang diakhiri * seperti backend/*.",
              )}
            </span>
          ) : (
            <span id="f-path-hint" class="note">
              {t("A path, or a prefix ending in *", "Path, atau awalan yang diakhiri *")}
            </span>
          )}
        </div>
        <div class="field">
          <label for="f-result">{t("Result", "Hasil")}</label>
          <select
            id="f-result"
            value={draft.result}
            onChange={(e) =>
              setDraft({ ...draft, result: e.currentTarget.value as AuditFilters["result"] })
            }
          >
            <option value="">{t("All", "Semua")}</option>
            <option value="ok">{RESULT_LABEL.ok()}</option>
            <option value="denied">{RESULT_LABEL.denied()}</option>
            <option value="error">{RESULT_LABEL.error()}</option>
          </select>
        </div>
        <div class="field">
          <label for="f-range">{t("When", "Kapan")}</label>
          <select
            id="f-range"
            value={draft.range}
            onChange={(e) => setDraft({ ...draft, range: e.currentTarget.value as DateRange })}
          >
            {(Object.keys(DATE_RANGE_SECONDS) as DateRange[]).concat("all").map((r) => (
              <option key={r} value={r}>
                {RANGE_LABEL[r]()}
              </option>
            ))}
          </select>
        </div>
        <div class="filters-actions">
          <button type="submit" class="btn sm" disabled={loading}>
            {t("Apply filters", "Terapkan saringan")}
          </button>
        </div>
      </form>

      {error !== null && (
        <p class="field-error" role="alert">
          {error}
        </p>
      )}

      <div class="card tw">
        <table class="log-table">
          <caption class="visually-hidden">{t("Log entries", "Entri log")}</caption>
          <thead>
            <tr>
              <th scope="col">{t("Time", "Waktu")}</th>
              <th scope="col">{t("Who", "Siapa")}</th>
              <th scope="col">{t("What", "Apa")}</th>
              <th scope="col">{t("Secret", "Secret")}</th>
              <th scope="col">{t("Details", "Keterangan")}</th>
              <th scope="col">{t("Result", "Hasil")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.seq} class={row.result === "denied" ? "denied" : undefined}>
                <td class="time">
                  <time dateTime={new Date(row.at * 1000).toISOString()}>
                    {formatTime(row.at, lang)} {formatClock(row.at, lang)}
                  </time>
                </td>
                <td>{row.who}</td>
                <td class="mono small">{row.action}</td>
                <td class="mono small">{row.path ?? "-"}</td>
                <td class="details">{row.note ?? ""}</td>
                <td>
                  <span
                    class={`pill ${row.result === "ok" ? "ok" : row.result === "denied" ? "bad" : "warn"}`}
                  >
                    {RESULT_LABEL[row.result]()}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!loading && rows.length === 0 && error === null && (
          <p class="note empty">
            {t(
              "No entries match these filters.",
              "Tidak ada entri yang cocok dengan saringan ini.",
            )}
          </p>
        )}
        {loading && (
          <p class="note empty" role="status">
            {t("Loading...", "Memuat...")}
          </p>
        )}
      </div>

      {hasMore && last !== undefined && (
        <div class="row-actions">
          <button
            type="button"
            class="btn ghost"
            disabled={loading}
            onClick={() => void load(applied, last.seq)}
          >
            {t("Show older entries", "Tampilkan entri lebih lama")}
          </button>
        </div>
      )}

      <p class="note limit">
        <b>{t("What this shows:", "Yang ditunjukkan di sini:")}</b>{" "}
        {t(
          "who opened a secret, and when. We can't see what they did with it afterwards, and values are never recorded.",
          "siapa yang membuka secret, dan kapan. Kami tidak bisa melihat apa yang mereka lakukan sesudahnya, dan nilai tidak pernah dicatat.",
        )}
      </p>
    </section>
  );
}

const nowSeconds = () => Math.floor(Date.now() / 1000);
