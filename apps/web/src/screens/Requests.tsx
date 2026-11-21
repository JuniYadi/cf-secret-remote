import { useEffect, useState } from "preact/hooks";
import { PageTitle } from "../components/shared.tsx";
import { Tabs } from "../components/Tabs.tsx";
import { type AccessRequest, api, type RequestStatus } from "../lib/api.ts";
import { useLang, useSession } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { getPrivateKey, getPublicKey } from "../lib/keystore.ts";
import { endsIn, messageFor } from "../lib/messages.ts";
import {
  approveWithGroupKey,
  checkRequest,
  MAX_REASON,
  REQUEST_DURATIONS,
  type RequestDraft,
  type RequestErrors,
} from "../lib/requests.ts";
import { PATHS, pageCrumbs } from "../routes.ts";
import "../styles/activity.css";

/** Duration labels for the form. The value is seconds, as the Worker takes it. */
function durationLabel(seconds: number): string {
  if (seconds < 3600) return t(`${seconds / 60} minutes`, `${seconds / 60} menit`);
  const hours = seconds / 3600;
  return t(hours === 1 ? "1 hour" : `${hours} hours`, hours === 1 ? "1 jam" : `${hours} jam`);
}

const STATUS_PILL: Record<RequestStatus, () => { cls: string; text: string }> = {
  pending: () => ({ cls: "pill warn", text: t("Waiting", "Menunggu") }),
  approved: () => ({ cls: "pill ok", text: t("Approved", "Disetujui") }),
  denied: () => ({ cls: "pill bad", text: t("Denied", "Ditolak") }),
  cancelled: () => ({ cls: "pill", text: t("Cancelled", "Dibatalkan") }),
  expired: () => ({ cls: "pill", text: t("Expired", "Kedaluwarsa") }),
};

const nowSeconds = () => Math.floor(Date.now() / 1000);

/** Access requests (ADR 16): the approver's queue, the request form, and the decisions. */
export function RequestsPage() {
  useLang();
  const { me } = useSession();
  const [rows, setRows] = useState<AccessRequest[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function reload() {
    try {
      setRows(await api.requests());
      setError(null);
    } catch (err) {
      setError(messageFor(err));
    }
  }

  useEffect(() => {
    void reload();
  }, []);

  const isAdmin = me?.role === "admin";
  const waiting = (rows ?? []).filter((r) => r.status === "pending");
  const decided = (rows ?? []).filter((r) => r.status !== "pending");

  return (
    <div class="page-plain activity-page">
      <PageTitle crumbs={pageCrumbs("requests")} />
      <Tabs
        label={t("Permissions sections", "Bagian izin")}
        current={PATHS.requests}
        items={[
          { href: PATHS.permissions, label: t("Who can do what", "Siapa boleh apa") },
          { href: PATHS.requests, label: t("Access requests", "Permintaan akses") },
        ]}
      />
      <p class="sub activity-sub">
        {t(
          "Ask for temporary access to a secret. Approvers say yes or no, and access ends on its own.",
          "Minta akses sementara ke sebuah secret. Approver menyetujui atau menolak, dan akses berakhir sendiri.",
        )}
      </p>

      {error !== null && (
        <p class="field-error" role="alert">
          {error}
        </p>
      )}

      <div class="requests-grid">
        <div class="requests-main">
          {isAdmin && (
            <section aria-labelledby="waiting-title" class="stack">
              <h2 id="waiting-title">{t("Waiting for you", "Menunggu kamu")}</h2>
              {rows !== null && waiting.length === 0 && (
                <p class="note">{t("Nothing is waiting.", "Tidak ada yang menunggu.")}</p>
              )}
              {waiting.map((row) => (
                <ApprovalCard
                  key={row.id}
                  request={row}
                  isMine={row.requesterId === me?.id}
                  onDone={reload}
                />
              ))}
              <div class="callout">
                <span>
                  {t(
                    "Approving shares the group key with them, using your unlocked vault. The server never sees it. You need to be online to approve.",
                    "Menyetujui berarti membagikan kunci grup kepada mereka, memakai vault-mu yang terbuka. Server tidak pernah melihatnya. Kamu harus online untuk menyetujui.",
                  )}
                </span>
              </div>
            </section>
          )}

          <section aria-labelledby="decisions-title" class="card activity-card">
            <h2 id="decisions-title">
              {isAdmin
                ? t("Recent decisions", "Keputusan terbaru")
                : t("Your requests", "Permintaanmu")}
            </h2>
            {rows === null && <p class="note">{t("Loading...", "Memuat...")}</p>}
            {rows !== null && (isAdmin ? decided : rows).length === 0 && (
              <p class="note">{t("No requests yet.", "Belum ada permintaan.")}</p>
            )}
            {rows !== null && (isAdmin ? decided : rows).length > 0 && (
              <div class="tw">
                <table class="log-table">
                  <thead>
                    <tr>
                      <th scope="col">{t("Who", "Siapa")}</th>
                      <th scope="col">{t("Secret", "Secret")}</th>
                      <th scope="col">{t("Status", "Status")}</th>
                      <th scope="col">{t("Access ends", "Akses berakhir")}</th>
                      <th scope="col">{t("Decided by", "Diputuskan oleh")}</th>
                      <th scope="col">
                        <span class="visually-hidden">{t("Actions", "Aksi")}</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {(isAdmin ? decided : rows).map((row) => (
                      <RequestRow
                        key={row.id}
                        row={row}
                        mine={row.requesterId === me?.id}
                        onDone={reload}
                      />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>

        <AskForm onSent={reload} />
      </div>
    </div>
  );
}

function RequestRow({
  row,
  mine,
  onDone,
}: {
  row: AccessRequest;
  mine: boolean;
  onDone: () => void;
}) {
  useLang();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pill = STATUS_PILL[row.status]();
  const ends =
    row.status === "approved" && row.expiresAt !== null ? endsIn(row.expiresAt, nowSeconds()) : "-";

  async function cancel() {
    setBusy(true);
    setError(null);
    try {
      await api.cancelRequest(row.id);
      onDone();
    } catch (err) {
      setError(messageFor(err));
      setBusy(false);
    }
  }

  return (
    <tr>
      <td>{row.requester}</td>
      <td class="mono small">{row.path}</td>
      <td>
        <span class={pill.cls}>{pill.text}</span>
      </td>
      <td>{ends}</td>
      <td>{row.approver ?? "-"}</td>
      <td>
        {mine && row.status === "pending" && (
          <button type="button" class="btn ghost sm" disabled={busy} onClick={() => void cancel()}>
            {t("Cancel request", "Batalkan permintaan")}
          </button>
        )}
        {error !== null && (
          <span class="field-error" role="alert">
            {error}
          </span>
        )}
      </td>
    </tr>
  );
}

/** One request waiting for the approver. Approve wraps the group key for the requester in the browser. */
function ApprovalCard({
  request,
  isMine,
  onDone,
}: {
  request: AccessRequest;
  isMine: boolean;
  onDone: () => void;
}) {
  useLang();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function approve() {
    const privateKey = getPrivateKey();
    const publicKey = getPublicKey();
    if (privateKey === null || publicKey === null) {
      setError(t("Unlock your vault to approve.", "Buka vault-mu untuk menyetujui."));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await approveWithGroupKey(
        { requesterId: request.requesterId, groupPrefix: request.groupPrefix },
        { publicKey, privateKey },
        {
          fetchGroupKey: (prefix) => api.groupKey(prefix),
          requesterPublicKey: async (id) => {
            const people = await api.identities();
            const found = people.find((p) => p.id === id);
            if (!found?.publicKey) throw new Error("requester has no vault");
            return found.publicKey;
          },
          send: async ({ wrappedKey, version }) => {
            await api.approveRequest(request.id, wrappedKey, version);
          },
        },
      );
      onDone();
    } catch (err) {
      setError(
        err instanceof Error && err.message === "requester has no vault"
          ? t(
              "This person hasn't set up their vault yet, so they can't receive access.",
              "Orang ini belum menyiapkan vault-nya, jadi belum bisa menerima akses.",
            )
          : messageFor(err),
      );
      setBusy(false);
    }
  }

  async function deny() {
    setBusy(true);
    setError(null);
    try {
      await api.denyRequest(request.id);
      onDone();
    } catch (err) {
      setError(messageFor(err));
      setBusy(false);
    }
  }

  return (
    <article class="card req" aria-labelledby={`req-${request.id}`}>
      <div class="row-between">
        <div id={`req-${request.id}`}>
          <b>{request.requester}</b>{" "}
          <span class="muted">{t("wants to open", "ingin membuka")}</span>{" "}
          <span class="mono small">{request.path}</span>
        </div>
        <span class="note">
          {t(`For ${durationLabel(request.duration)}`, `Selama ${durationLabel(request.duration)}`)}
        </span>
      </div>
      {request.reason !== "" && <div class="why">“{request.reason}”</div>}
      {isMine ? (
        <p class="note">
          {t(
            "This is your own request. Another admin has to approve it.",
            "Ini permintaanmu sendiri. Admin lain yang harus menyetujuinya.",
          )}
        </p>
      ) : (
        <div class="row-actions">
          <button type="button" class="btn sm" disabled={busy} onClick={() => void approve()}>
            {t(
              `Approve for ${durationLabel(request.duration)}`,
              `Setujui selama ${durationLabel(request.duration)}`,
            )}
          </button>
          <button type="button" class="btn ghost sm" disabled={busy} onClick={() => void deny()}>
            {t("Deny", "Tolak")}
          </button>
        </div>
      )}
      {error !== null && (
        <p class="field-error" role="alert">
          {error}
        </p>
      )}
    </article>
  );
}

/** The request form. The duration is a choice from the allowed lengths, so the Worker's 24 h limit always holds. */
function AskForm({ onSent }: { onSent: () => void }) {
  useLang();
  const [draft, setDraft] = useState<RequestDraft>({
    path: "",
    reason: "",
    duration: REQUEST_DURATIONS[1] ?? 3600,
  });
  const [errors, setErrors] = useState<RequestErrors>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState(false);

  async function onSubmit(event: Event) {
    event.preventDefault();
    const found = checkRequest(draft);
    setErrors(found);
    setSent(false);
    if (Object.keys(found).length > 0) return;
    setBusy(true);
    setError(null);
    try {
      await api.createRequest({
        path: draft.path.trim(),
        reason: draft.reason.trim(),
        duration: draft.duration,
      });
      setDraft({ ...draft, reason: "" });
      setSent(true);
      onSent();
    } catch (err) {
      setError(messageFor(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form
      class="card activity-card ask-form"
      onSubmit={onSubmit}
      aria-labelledby="ask-title"
      noValidate
    >
      <h2 id="ask-title">{t("Ask for access", "Minta akses")}</h2>
      <div class="field">
        <label for="ask-path">{t("Secret", "Secret")}</label>
        <input
          id="ask-path"
          type="text"
          class="mono"
          value={draft.path}
          placeholder="myapp/prod"
          autocomplete="off"
          spellcheck={false}
          onInput={(e) => setDraft({ ...draft, path: e.currentTarget.value })}
          aria-invalid={errors.path ? "true" : undefined}
          aria-describedby={errors.path ? "ask-path-error" : undefined}
        />
        {errors.path && (
          <span id="ask-path-error" class="field-error">
            {t(
              "Use a path such as myapp/prod. The first part is the group.",
              "Pakai path seperti myapp/prod. Bagian pertama adalah grupnya.",
            )}
          </span>
        )}
      </div>
      <div class="field">
        <label for="ask-duration">{t("For how long", "Berapa lama")}</label>
        <select
          id="ask-duration"
          value={String(draft.duration)}
          onChange={(e) => setDraft({ ...draft, duration: Number(e.currentTarget.value) })}
        >
          {REQUEST_DURATIONS.map((seconds) => (
            <option key={seconds} value={String(seconds)}>
              {durationLabel(seconds)}
            </option>
          ))}
        </select>
        <span class="note">{t("Up to 24 hours.", "Sampai 24 jam.")}</span>
      </div>
      <div class="field">
        <label for="ask-reason">{t("Why do you need it?", "Kenapa kamu butuh?")}</label>
        <textarea
          id="ask-reason"
          rows={3}
          maxLength={MAX_REASON}
          value={draft.reason}
          onInput={(e) => setDraft({ ...draft, reason: e.currentTarget.value })}
          aria-invalid={errors.reason ? "true" : undefined}
          aria-describedby={errors.reason ? "ask-reason-error" : "ask-reason-hint"}
        />
        {errors.reason ? (
          <span id="ask-reason-error" class="field-error">
            {t(
              `Add a short reason, up to ${MAX_REASON} characters.`,
              `Tambahkan alasan singkat, sampai ${MAX_REASON} karakter.`,
            )}
          </span>
        ) : (
          <span id="ask-reason-hint" class="note">
            {t(
              "A short reason helps the approver decide.",
              "Alasan singkat membantu approver memutuskan.",
            )}
          </span>
        )}
      </div>
      <button type="submit" class="btn" disabled={busy}>
        {busy ? t("Sending...", "Mengirim...") : t("Send request", "Kirim permintaan")}
      </button>
      {sent && (
        <p class="note" role="status">
          {t(
            "Request sent. An approver will see it under Waiting for you.",
            "Permintaan terkirim. Approver akan melihatnya di Menunggu kamu.",
          )}
        </p>
      )}
      {error !== null && (
        <p class="field-error" role="alert">
          {error}
        </p>
      )}
    </form>
  );
}
