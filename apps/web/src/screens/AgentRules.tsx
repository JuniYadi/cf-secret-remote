import { useEffect, useState } from "preact/hooks";
import { Switch } from "../components/Switch.tsx";
import { PageTitle } from "../components/shared.tsx";
import { Tabs } from "../components/Tabs.tsx";
import {
  checkRule,
  DEFAULT_INJECT,
  DEFAULT_READS,
  isProdPath,
  MAX_READS,
  type RuleDraft,
  type RuleErrors,
  ruleInput,
} from "../lib/agent-rules.ts";
import { type AgentRule, type AppSummary, api } from "../lib/api.ts";
import { useLang, useSession } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { messageFor } from "../lib/messages.ts";
import { PATHS, pageCrumbs } from "../routes.ts";
import "../styles/activity.css";

const EMPTY_DRAFT: RuleDraft = {
  alias: "",
  secretPath: "",
  name: "",
  upstream: "https://",
  inject: DEFAULT_INJECT,
  maxReadsPerHour: String(DEFAULT_READS),
  requireReason: false,
  requireApproval: false,
};

/** Per-app agent rules (ADR 17). Admins only. The agent never sees the value; the local helper injects it. */
export function AgentRulesPage() {
  useLang();
  const { me } = useSession();
  return (
    <div class="page-plain activity-page">
      <PageTitle crumbs={pageCrumbs("agentRules")} />
      <Tabs
        label={t("Apps sections", "Bagian aplikasi")}
        current={PATHS.agentRules}
        items={[
          { href: PATHS.apps, label: t("Apps and bots", "Aplikasi dan bot") },
          { href: PATHS.agentRules, label: t("Agent rules", "Aturan agen") },
        ]}
      />
      <p class="sub activity-sub">
        {t(
          "Decide where an AI agent may use a secret and how much it may open. The agent uses the key without ever seeing it.",
          "Tentukan di mana agen AI boleh memakai secret dan seberapa banyak yang boleh dibukanya. Agen memakai key tanpa pernah melihatnya.",
        )}
      </p>
      {me?.role === "admin" ? (
        <RulesBody />
      ) : (
        <div class="card activity-card">
          <p class="note">
            {t("Agent rules are set by admins.", "Aturan agen diatur oleh admin.")}
          </p>
        </div>
      )}
    </div>
  );
}

function RulesBody() {
  useLang();
  const [apps, setApps] = useState<AppSummary[] | null>(null);
  const [appId, setAppId] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    api
      .apps()
      .then((list) => {
        if (!live) return;
        const agents = list.filter((a) => a.status !== "disabled");
        setApps(agents);
        setAppId((current) => current || (agents[0]?.id ?? ""));
      })
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
  if (apps === null)
    return (
      <p class="note" role="status">
        {t("Loading...", "Memuat...")}
      </p>
    );
  if (apps.length === 0) {
    return (
      <div class="card activity-card">
        <p class="note">
          {t(
            "There are no apps or bots yet. Create one under Apps & bots first.",
            "Belum ada aplikasi atau bot. Buat dulu di Aplikasi & bot.",
          )}
        </p>
      </div>
    );
  }

  const app = apps.find((a) => a.id === appId) ?? apps[0];
  return (
    <>
      <div class="app-picker">
        <label for="rules-app">{t("Rules for", "Aturan untuk")}</label>
        <select
          id="rules-app"
          value={app?.id ?? ""}
          onChange={(e) => setAppId(e.currentTarget.value)}
        >
          {apps.map((a) => (
            <option key={a.id} value={a.id}>
              {a.name}
            </option>
          ))}
        </select>
        <span class="pill acc">{t("AI agent", "Agen AI")}</span>
      </div>
      {app !== undefined && <RulesForApp key={app.id} appId={app.id} />}
    </>
  );
}

function RulesForApp({ appId }: { appId: string }) {
  useLang();
  const [rules, setRules] = useState<AgentRule[] | null>(null);
  const [editing, setEditing] = useState<AgentRule | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function reload() {
    try {
      setRules(await api.agentRules(appId));
      setError(null);
    } catch (err) {
      setError(messageFor(err));
    }
  }

  useEffect(() => {
    void reload();
  }, [appId]);

  async function remove(rule: AgentRule) {
    if (!window.confirm(t(`Delete the rule ${rule.alias}?`, `Hapus aturan ${rule.alias}?`))) return;
    try {
      await api.deleteAgentRule(appId, rule.alias);
      setNotice(t("Rule deleted.", "Aturan dihapus."));
      if (editing?.alias === rule.alias) setEditing(null);
      await reload();
    } catch (err) {
      setError(messageFor(err));
    }
  }

  return (
    <>
      <section class="card activity-card" aria-labelledby="flow-title">
        <h2 id="flow-title">
          {t(
            "How the agent uses a key without seeing it",
            "Cara agen memakai key tanpa melihatnya",
          )}
        </h2>
        <div class="flow">
          <div class="node">
            <b>{t("The agent", "Agen")}</b>
            <span>
              {t(
                "Asks to call the API. It has no key.",
                "Meminta memanggil API. Ia tidak punya key.",
              )}
            </span>
          </div>
          <div class="arrow" aria-hidden="true">
            →
          </div>
          <div class="node key">
            <b>{t("Local helper", "Pembantu lokal")}</b>
            <span>
              {t(
                "Runs on this machine. Opens the key and adds it to the request.",
                "Berjalan di mesin ini. Membuka key dan menambahkannya ke request.",
              )}
            </span>
          </div>
          <div class="arrow" aria-hidden="true">
            →
          </div>
          <div class="node">
            <b>{t("Allowed website", "Situs yang diizinkan")}</b>
            <span>
              {t(
                "Only the upstream of each rule. The agent only sees the reply.",
                "Hanya upstream tiap aturan. Agen hanya melihat balasannya.",
              )}
            </span>
          </div>
        </div>
      </section>

      {notice !== null && (
        <p class="note" role="status">
          {notice}
        </p>
      )}
      {error !== null && (
        <p class="field-error" role="alert">
          {error}
        </p>
      )}

      <section class="card activity-card" aria-labelledby="rules-list-title">
        <h2 id="rules-list-title">{t("Rules", "Aturan")}</h2>
        {rules === null && <p class="note">{t("Loading...", "Memuat...")}</p>}
        {rules !== null && rules.length === 0 && (
          <p class="note">
            {t(
              "No rules yet. This app can't read any secret through the helper.",
              "Belum ada aturan. Aplikasi ini belum bisa membaca secret lewat pembantu.",
            )}
          </p>
        )}
        {rules !== null && rules.length > 0 && (
          <div class="tw">
            <table class="log-table">
              <thead>
                <tr>
                  <th scope="col">{t("Alias", "Alias")}</th>
                  <th scope="col">{t("Secret", "Secret")}</th>
                  <th scope="col">{t("Upstream", "Upstream")}</th>
                  <th scope="col">{t("Opens per hour", "Pembukaan per jam")}</th>
                  <th scope="col">{t("Reason", "Alasan")}</th>
                  <th scope="col">{t("Approval", "Persetujuan")}</th>
                  <th scope="col">
                    <span class="visually-hidden">{t("Actions", "Aksi")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.alias}>
                    <td class="mono small">{rule.alias}</td>
                    <td class="mono small">{rule.secretPath}</td>
                    <td class="mono small">{rule.upstream}</td>
                    <td>{rule.maxReadsPerHour}</td>
                    <td>
                      {rule.requireReason ? t("Required", "Wajib") : t("Optional", "Opsional")}
                    </td>
                    <td>
                      <span class={rule.requireApproval ? "pill warn" : "pill"}>
                        {rule.requireApproval
                          ? t("Needs a person", "Perlu orang")
                          : t("Not needed", "Tidak perlu")}
                      </span>
                    </td>
                    <td class="row-actions-cell">
                      <button type="button" class="btn ghost sm" onClick={() => setEditing(rule)}>
                        {t(`Edit ${rule.alias}`, `Ubah ${rule.alias}`)}
                      </button>{" "}
                      <button
                        type="button"
                        class="btn ghost sm danger"
                        onClick={() => void remove(rule)}
                      >
                        {t(`Delete ${rule.alias}`, `Hapus ${rule.alias}`)}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <RuleForm
        key={editing?.alias ?? "new"}
        appId={appId}
        editing={editing}
        onCancel={() => setEditing(null)}
        onSaved={async () => {
          setEditing(null);
          setNotice(t("Rule saved.", "Aturan disimpan."));
          await reload();
        }}
      />
    </>
  );
}

function ruleToDraft(rule: AgentRule | null): RuleDraft {
  if (rule === null) return EMPTY_DRAFT;
  return {
    alias: rule.alias,
    secretPath: rule.secretPath,
    name: rule.name,
    upstream: rule.upstream,
    inject: rule.inject,
    maxReadsPerHour: String(rule.maxReadsPerHour),
    requireReason: rule.requireReason,
    requireApproval: rule.requireApproval,
  };
}

function RuleForm({
  appId,
  editing,
  onCancel,
  onSaved,
}: {
  appId: string;
  editing: AgentRule | null;
  onCancel: () => void;
  onSaved: () => Promise<void>;
}) {
  useLang();
  const [draft, setDraft] = useState<RuleDraft>(() => ruleToDraft(editing));
  // Once the person sets approval, the */prod default stops following the path.
  const [approvalTouched, setApprovalTouched] = useState(editing !== null);
  const [errors, setErrors] = useState<RuleErrors>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const isEditing = editing !== null;

  function setPath(secretPath: string) {
    setDraft((d) => ({
      ...d,
      secretPath,
      requireApproval: approvalTouched ? d.requireApproval : isProdPath(secretPath),
    }));
  }

  async function onSubmit(event: Event) {
    event.preventDefault();
    const found = checkRule(draft, isEditing);
    setErrors(found);
    if (Object.keys(found).length > 0) return;
    setBusy(true);
    setError(null);
    try {
      const input = ruleInput(draft);
      if (editing === null) {
        await api.createAgentRule(appId, input);
      } else {
        const { alias: _alias, ...patch } = input;
        await api.updateAgentRule(appId, editing.alias, patch);
      }
      await onSaved();
    } catch (err) {
      setError(messageFor(err));
      setBusy(false);
    }
  }

  const text = (key: keyof RuleDraft, label: string, hint?: string, mono = false) => (
    <div class="field">
      <label for={`rule-${key}`}>{label}</label>
      <input
        id={`rule-${key}`}
        type="text"
        class={mono ? "mono" : undefined}
        value={String(draft[key])}
        disabled={key === "alias" && isEditing}
        autocomplete="off"
        spellcheck={false}
        onInput={(e) => setDraft((d) => ({ ...d, [key]: e.currentTarget.value }))}
        aria-invalid={errors[key as keyof RuleErrors] ? "true" : undefined}
        aria-describedby={hint ? `rule-${key}-hint` : undefined}
      />
      {hint && (
        <span id={`rule-${key}-hint`} class="note">
          {hint}
        </span>
      )}
    </div>
  );

  return (
    <form
      class="card activity-card rule-form"
      onSubmit={onSubmit}
      aria-labelledby="rule-form-title"
      noValidate
    >
      <h2 id="rule-form-title">
        {isEditing
          ? t(`Edit rule ${editing.alias}`, `Ubah aturan ${editing.alias}`)
          : t("Add a rule", "Tambah aturan")}
      </h2>
      <div class="form-grid">
        {text(
          "alias",
          t("Alias", "Alias"),
          t(
            "What the agent calls, in lowercase letters, digits and dashes. It can't be changed later.",
            "Nama yang dipakai agen, huruf kecil, angka dan tanda hubung. Tidak bisa diubah nanti.",
          ),
        )}
        <div class="field">
          <label for="rule-secretPath">{t("Secret path", "Path secret")}</label>
          <input
            id="rule-secretPath"
            type="text"
            class="mono"
            value={draft.secretPath}
            placeholder="payments/prod"
            autocomplete="off"
            spellcheck={false}
            onInput={(e) => setPath(e.currentTarget.value)}
            aria-invalid={errors.secretPath ? "true" : undefined}
            aria-describedby="rule-secretPath-hint"
          />
          <span id="rule-secretPath-hint" class="note">
            {errors.secretPath
              ? t(
                  "Use one exact secret path, without *.",
                  "Pakai satu path secret yang tepat, tanpa *.",
                )
              : t("One exact path. No wildcards.", "Satu path yang tepat. Tanpa wildcard.")}
          </span>
        </div>
        {text(
          "name",
          t("Value name", "Nama nilai"),
          t(
            "The name of the value inside the secret, such as STRIPE_KEY.",
            "Nama nilai di dalam secret, misalnya STRIPE_KEY.",
          ),
          true,
        )}
        {text(
          "upstream",
          t("Upstream", "Upstream"),
          t(
            "An https address. The helper only talks to this site.",
            "Alamat https. Pembantu hanya berbicara dengan situs ini.",
          ),
          true,
        )}
        {text(
          "inject",
          t("Where the value goes", "Tempat nilai dipasang"),
          t(
            "header:Name:Template with {value} once, or query:name.",
            "header:Nama:Templat dengan {value} sekali, atau query:nama.",
          ),
          true,
        )}
        <div class="field">
          <label for="rule-maxReadsPerHour">{t("Opens per hour", "Pembukaan per jam")}</label>
          <input
            id="rule-maxReadsPerHour"
            type="number"
            min={1}
            max={MAX_READS}
            step={1}
            value={draft.maxReadsPerHour}
            onInput={(e) => setDraft((d) => ({ ...d, maxReadsPerHour: e.currentTarget.value }))}
            aria-invalid={errors.maxReadsPerHour ? "true" : undefined}
            aria-describedby="rule-maxReadsPerHour-hint"
          />
          <span id="rule-maxReadsPerHour-hint" class="note">
            {t(
              `From 1 to ${MAX_READS.toLocaleString("en-US")}. After this, the agent has to wait.`,
              `Dari 1 sampai ${MAX_READS.toLocaleString("id-ID")}. Setelah ini, agen harus menunggu.`,
            )}
          </span>
        </div>
      </div>

      <div class="toggle-row">
        <div>
          <b>{t("Must give a reason", "Wajib memberi alasan")}</b>
          <small class="note">
            {t(
              "Shown in Activity next to every open.",
              "Ditampilkan di Aktivitas di samping tiap pembukaan.",
            )}
          </small>
        </div>
        <Switch
          label={t("Must give a reason", "Wajib memberi alasan")}
          checked={draft.requireReason}
          onChange={(on) => setDraft((d) => ({ ...d, requireReason: on }))}
        />
      </div>
      <div class="toggle-row">
        <div>
          <b>{t("Production needs a person", "Produksi butuh persetujuan orang")}</b>
          <small class="note">
            {t(
              "Secrets ending in /prod wait for an approver. This is on by default for */prod paths, and you can turn it off for a rule you trust.",
              "Secret berakhiran /prod menunggu approver. Ini aktif otomatis untuk path */prod, dan bisa kamu matikan untuk aturan yang kamu percaya.",
            )}
          </small>
        </div>
        <Switch
          label={t("Production needs a person", "Produksi butuh persetujuan orang")}
          checked={draft.requireApproval}
          onChange={(on) => {
            setApprovalTouched(true);
            setDraft((d) => ({ ...d, requireApproval: on }));
          }}
        />
      </div>

      <div class="row-actions form-actions">
        <button type="button" class="btn ghost" onClick={onCancel} disabled={busy}>
          {t("Cancel", "Batal")}
        </button>
        <button type="submit" class="btn" disabled={busy}>
          {busy ? t("Saving...", "Menyimpan...") : t("Save rule", "Simpan aturan")}
        </button>
      </div>
      {error !== null && (
        <p class="field-error" role="alert">
          {error}
        </p>
      )}
      {Object.keys(errors).length > 0 && (
        <p class="field-error" role="alert">
          {t("Check the highlighted fields.", "Periksa kolom yang ditandai.")}
        </p>
      )}
      <details class="tech">
        <summary>{t("Technical details", "Detail teknis")}</summary>
        <pre class="code">{`$ cfs proxy --listen 127.0.0.1:8787
# the agent calls http://127.0.0.1:8787/<alias>/<path>
# the helper decrypts the key locally and adds it to the request`}</pre>
      </details>
    </form>
  );
}
