import { useEffect, useState } from "preact/hooks";
import { Switch } from "../components/Switch.tsx";
import { PageTitle } from "../components/shared.tsx";
import { Tabs } from "../components/Tabs.tsx";
import { formatTime } from "../lib/activity.ts";
import { validWebhook, withChannel } from "../lib/alerts.ts";
import {
  type AlertSettings,
  type AlertTestResult,
  api,
  type ChannelToggles,
  type RecentAlert,
  RULE_NAMES,
  type RuleName,
} from "../lib/api.ts";
import { useLang, useSession } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { messageFor } from "../lib/messages.ts";
import { PATHS, pageCrumbs } from "../routes.ts";
import "../styles/activity.css";

/** What each rule means, in the words of the Alerts board. */
const RULE_COPY: Record<RuleName, { title: () => string; sub: () => string }> = {
  blocked: {
    title: () => t("A blocked attempt", "Percobaan yang diblokir"),
    sub: () =>
      t(
        "Someone or something was stopped by a permission.",
        "Seseorang atau sesuatu dihentikan oleh izin.",
      ),
  },
  agent_prod_read: {
    title: () => t("An AI agent opens a production secret", "Agen AI membuka secret produksi"),
    sub: () =>
      t(
        "Any secret ending in /prod, even when it was approved.",
        "Secret apa pun berakhiran /prod, walau sudah disetujui.",
      ),
  },
  new_network: {
    title: () => t("Sign-in from a new network", "Masuk dari jaringan baru"),
    sub: () =>
      t(
        "The first time a person or bot appears from an unfamiliar place.",
        "Saat pertama kali orang atau bot muncul dari tempat yang belum dikenal.",
      ),
  },
  read_burst: {
    title: () => t("Many opens in a short time", "Banyak pembukaan dalam waktu singkat"),
    sub: () => t("More than 20 opens within 5 minutes.", "Lebih dari 20 pembukaan dalam 5 menit."),
  },
  quota_80: {
    title: () => t("Free plan usage reaches 80%", "Pemakaian paket gratis mencapai 80%"),
    sub: () =>
      t(
        "Warns before today's free writes run out.",
        "Memberi peringatan sebelum tulis gratis hari ini habis.",
      ),
  },
  chain_broken: {
    title: () => t("The log chain breaks", "Rantai log putus"),
    sub: () =>
      t(
        "An entry was changed or removed. Check Activity right away.",
        "Sebuah entri diubah atau dihapus. Periksa Aktivitas sekarang.",
      ),
  },
  recovery_requested: {
    title: () => t("Someone asks for vault recovery", "Seseorang meminta pemulihan vault"),
    sub: () =>
      t(
        "A recovery request was made for an account.",
        "Permintaan pemulihan dibuat untuk sebuah akun.",
      ),
  },
  access_request: {
    title: () => t("Someone asks for access", "Seseorang meminta akses"),
    sub: () =>
      t(
        "A new access request is waiting for an approver.",
        "Permintaan akses baru menunggu approver.",
      ),
  },
};

/** Alert channels and rules (ADR 18). Admins only. */
export function AlertsPage() {
  useLang();
  const { me } = useSession();
  return (
    <div class="page-plain activity-page">
      <PageTitle crumbs={pageCrumbs("alerts")} />
      <Tabs
        label={t("Activity sections", "Bagian aktivitas")}
        current={PATHS.alerts}
        items={[
          { href: PATHS.activity, label: t("Log", "Log") },
          { href: PATHS.alerts, label: t("Alerts", "Peringatan") },
        ]}
      />
      <p class="sub activity-sub">
        {t(
          "Get a message when something looks wrong, so you don't have to watch the log.",
          "Dapatkan pesan saat ada yang mencurigakan, jadi kamu tidak perlu terus memantau log.",
        )}
      </p>
      {me?.role === "admin" ? (
        <AlertsBody />
      ) : (
        <div class="card activity-card">
          <p class="note">
            {t("Alert settings are for admins.", "Pengaturan peringatan hanya untuk admin.")}
          </p>
        </div>
      )}
    </div>
  );
}

function AlertsBody() {
  useLang();
  const [settings, setSettings] = useState<AlertSettings | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    api
      .alerts()
      .then((s) => live && setSettings(s))
      .catch((err: unknown) => live && setError(messageFor(err)));
    return () => {
      live = false;
    };
  }, []);

  if (error !== null) {
    return (
      <p class="field-error" role="alert">
        {error}
      </p>
    );
  }
  if (settings === null) {
    return (
      <p class="note" role="status">
        {t("Loading...", "Memuat...")}
      </p>
    );
  }
  return (
    <div class="alerts-grid">
      <div class="alerts-col">
        <WebhookCard settings={settings} onSaved={setSettings} />
        <RulesCard settings={settings} onSaved={setSettings} />
      </div>
      <div class="alerts-col">
        <RecentAlerts />
      </div>
    </div>
  );
}

function WebhookCard({
  settings,
  onSaved,
}: {
  settings: AlertSettings;
  onSaved: (next: AlertSettings) => void;
}) {
  useLang();
  // The typed URL lives only in this field. It is cleared once it is sent.
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [invalid, setInvalid] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);

  async function save(next: string | null) {
    if (next !== null && !validWebhook(next)) {
      setInvalid(true);
      return;
    }
    setInvalid(false);
    setBusy(true);
    setError(null);
    setSaved(null);
    try {
      const out = await api.setWebhook(next);
      setDraft("");
      onSaved(out);
      setSaved(
        next === null
          ? t("Webhook removed.", "Webhook dihapus.")
          : t(
              "Webhook saved. It's shown masked from now on.",
              "Webhook disimpan. Sekarang ditampilkan dengan disamarkan.",
            ),
      );
    } catch (err) {
      setError(messageFor(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section class="card activity-card" aria-labelledby="webhook-title">
      <h2 id="webhook-title">{t("Send alerts to", "Kirim peringatan ke")}</h2>
      <form
        class="form-stack"
        onSubmit={(e) => {
          e.preventDefault();
          if (draft.trim() !== "") void save(draft.trim());
        }}
      >
        <div class="field">
          <label for="webhook-url">
            {t("Slack-compatible webhook URL", "URL webhook kompatibel Slack")}
          </label>
          <input
            id="webhook-url"
            type="url"
            value={draft}
            onInput={(e) => setDraft(e.currentTarget.value)}
            placeholder="https://hooks.slack.com/services/..."
            autocomplete="off"
            spellcheck={false}
            aria-invalid={invalid ? "true" : undefined}
            aria-describedby="webhook-help"
          />
          <span id="webhook-help" class="note">
            {invalid
              ? t("Use an https:// address.", "Pakai alamat https://.")
              : t(
                  "Paste it once. We store it on the server and show only a masked form after that.",
                  "Tempel sekali. Kami menyimpannya di server dan hanya menampilkan bentuk yang disamarkan.",
                )}
          </span>
        </div>
        <div class="row-actions">
          <button type="submit" class="btn sm" disabled={busy || draft.trim() === ""}>
            {t("Save webhook", "Simpan webhook")}
          </button>
          {settings.webhook !== null && (
            <button
              type="button"
              class="btn ghost sm"
              disabled={busy}
              onClick={() => void save(null)}
            >
              {t("Remove webhook", "Hapus webhook")}
            </button>
          )}
        </div>
      </form>
      <p class="note">
        <span class="visually-hidden">{t("Current webhook: ", "Webhook saat ini: ")}</span>
        {settings.webhook !== null ? (
          <span class="mono small">{settings.webhook}</span>
        ) : (
          t("No webhook set.", "Belum ada webhook.")
        )}
      </p>
      {saved !== null && (
        <p class="note" role="status">
          {saved}
        </p>
      )}
      {error !== null && (
        <p class="field-error" role="alert">
          {error}
        </p>
      )}
      <SendTest />
      <div class="channel-row">
        <span class="channel-name">{t("Email", "Email")}</span>
        {settings.email.available ? (
          <span class="note">
            {settings.email.recipients.length > 0
              ? settings.email.recipients.join(", ")
              : t("No admin addresses yet.", "Belum ada alamat admin.")}
          </span>
        ) : (
          <span class="note">
            {t(
              "Email alerts aren't set up on this server.",
              "Peringatan email belum diatur di server ini.",
            )}
          </span>
        )}
      </div>
    </section>
  );
}

function RulesCard({
  settings,
  onSaved,
}: {
  settings: AlertSettings;
  onSaved: (next: AlertSettings) => void;
}) {
  useLang();
  const [rules, setRules] = useState(settings.rules);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function toggle(rule: RuleName, channel: keyof ChannelToggles, on: boolean) {
    const previous = rules;
    const next = withChannel(rules, rule, channel, on);
    setRules(next);
    setBusy(true);
    setError(null);
    try {
      const out = await api.setRules(next);
      setRules(out.rules);
      onSaved(out);
    } catch (err) {
      setRules(previous);
      setError(messageFor(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section class="card activity-card rules-card" aria-labelledby="rules-title">
      <h2 id="rules-title">{t("What to alert on", "Kapan memberi peringatan")}</h2>
      {error !== null && (
        <p class="field-error" role="alert">
          {error}
        </p>
      )}
      <ul class="rule-list">
        {RULE_NAMES.map((rule) => (
          <li key={rule} class="rule">
            <div class="rule-text">
              <b>{RULE_COPY[rule].title()}</b>
              <small>{RULE_COPY[rule].sub()}</small>
            </div>
            <div class="rule-channels">
              <Switch
                label={`${RULE_COPY[rule].title()}: ${t("webhook", "webhook")}`}
                checked={rules[rule].webhook}
                disabled={busy || settings.webhook === null}
                onChange={(on) => void toggle(rule, "webhook", on)}
              />
              <Switch
                label={`${RULE_COPY[rule].title()}: ${t("email", "email")}`}
                checked={rules[rule].email}
                disabled={busy || !settings.email.available}
                onChange={(on) => void toggle(rule, "email", on)}
              />
            </div>
          </li>
        ))}
      </ul>
      <p class="note">
        {t(
          "Each alert is sent once per 15 minutes for the same subject, and never contains a secret value.",
          "Setiap peringatan dikirim sekali per 15 menit untuk subjek yang sama, dan tidak pernah berisi nilai secret.",
        )}
      </p>
    </section>
  );
}

const OUTCOME: Record<AlertTestResult["webhook"], () => string> = {
  sent: () => t("sent", "terkirim"),
  failed: () => t("failed", "gagal"),
  off: () => t("not set up", "belum diatur"),
};

/** Sends one test message to each channel that is set up and says what happened to each. */
function SendTest() {
  useLang();
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<AlertTestResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function send() {
    setBusy(true);
    setError(null);
    try {
      setResult(await api.alertsTest());
    } catch (err) {
      setError(messageFor(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="stack">
      <div class="row-between">
        <span class="note">
          {t(
            "Check that a message arrives before you rely on it.",
            "Pastikan pesan sampai sebelum kamu mengandalkannya.",
          )}
        </span>
        <button type="button" class="btn ghost sm" disabled={busy} onClick={() => void send()}>
          {busy ? t("Sending...", "Mengirim...") : t("Send test", "Kirim tes")}
        </button>
      </div>
      {result !== null && (
        <p
          class={`note${result.webhook === "failed" || result.email === "failed" ? " field-error" : ""}`}
          role="status"
        >
          {`Webhook: ${OUTCOME[result.webhook]()}. Email: ${OUTCOME[result.email]()}.`}
        </p>
      )}
      {error !== null && (
        <p class="field-error" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}

/** The newest alerts that went out: one line per rule and subject, with the time of the latest. */
function RecentAlerts() {
  const lang = useLang();
  const [rows, setRows] = useState<RecentAlert[] | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let live = true;
    api
      .alertsRecent()
      .then((v) => live && setRows(v))
      .catch(() => live && setFailed(true));
    return () => {
      live = false;
    };
  }, []);

  const titleOf = (rule: string) =>
    (RULE_NAMES as readonly string[]).includes(rule) ? RULE_COPY[rule as RuleName].title() : rule;

  return (
    <section class="card activity-card" aria-labelledby="recent-title">
      <h2 id="recent-title">{t("Recent alerts", "Peringatan terbaru")}</h2>
      {failed && (
        <p class="note">
          {t("Recent alerts aren't available right now.", "Peringatan terbaru belum bisa dimuat.")}
        </p>
      )}
      {!failed && rows === null && <p class="note">{t("Loading...", "Memuat...")}</p>}
      {rows !== null && rows.length === 0 && (
        <p class="note">
          {t("No alerts have gone out yet.", "Belum ada peringatan yang terkirim.")}
        </p>
      )}
      {rows !== null && rows.length > 0 && (
        <ul class="recent-list">
          {rows.map((row) => (
            <li key={`${row.rule}:${row.subject}`}>
              <b>{titleOf(row.rule)}</b>
              <span class="mono small">{row.subject}</span>
              <time dateTime={new Date(row.at * 1000).toISOString()}>
                {formatTime(row.at, lang)}
              </time>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
