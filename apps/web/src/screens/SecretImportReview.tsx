import { isReservedSecretPath } from "@cfs/core";
// Import, step 2 of 2: review on its own screen, full width. Shows names, types and what will happen to each
// name, without values, until the person presses Show. Pick where it goes and the merge strategy, then
// save. Only here are the values sealed and written (ADR 22, DESIGN.md "Import").

import type { Values } from "@cfs/core";
import { useEffect, useState } from "preact/hooks";
import { Link, useLocation } from "wouter-preact";
import { ReasonForm } from "../components/reason-form.tsx";
import {
  MASK,
  Pill,
  type PillTone,
  typeLabel,
  useReveal,
  WarnBox,
} from "../components/secrets-ui.tsx";
import { PageTitle } from "../components/shared.tsx";
import { api, type SecretSummary } from "../lib/api.ts";
import { useLang } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import {
  clearImportDraft,
  getImportDraft,
  type ImportDraft,
  setImportDraft,
} from "../lib/import-draft.ts";
import {
  groupKeyFor,
  isConflict,
  isNoKey,
  saveValues,
  secretConflictMessage,
} from "../lib/secret-store.ts";
import {
  groupOf,
  type MergeRow,
  type MergeStrategy,
  mergeValues,
  typeOf,
  validSecretPath,
} from "../lib/secrets.ts";
import { useSecret } from "../lib/use-secret.ts";
import { PATHS, pageCrumbs, secretHref } from "../routes.ts";
import { Steps } from "./SecretImport.tsx";

export function SecretImportReviewPage() {
  useLang();
  const [, navigate] = useLocation();
  // Read once: the draft is in memory and lives until the import is saved or cancelled.
  const [draft] = useState<ImportDraft | null>(() => getImportDraft());

  useEffect(() => {
    if (draft === null) navigate(PATHS.secretsImport);
  }, [draft, navigate]);

  if (draft === null) return null;
  return (
    <ReviewBody
      initial={draft}
      onDone={(path) => {
        clearImportDraft();
        navigate(secretHref(path));
      }}
    />
  );
}

function ReviewBody({ initial, onDone }: { initial: ImportDraft; onDone: (path: string) => void }) {
  useLang();
  const [target, setTarget] = useState<ImportDraft["target"]>(initial.target);
  const [strategy, setStrategy] = useState<MergeStrategy>(initial.strategy);
  const [secrets, setSecrets] = useState<SecretSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let live = true;
    api
      .secrets()
      .then((rows) => {
        if (live && Array.isArray(rows)) setSecrets(rows);
      })
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, []);

  // The choices are kept in the draft, so Back and the review see the same thing.
  useEffect(() => {
    setImportDraft({ ...initial, target, strategy });
  }, [target, strategy, initial]);

  const path = target.path;
  const existing = target.mode === "existing";
  const loaded = useSecret(path, undefined, existing && path !== "");
  // Only the secret for the chosen path counts. The state can lag one render behind a path change.
  const loadedSecret =
    loaded.state.status === "ready" && loaded.state.secret.path === path
      ? loaded.state.secret
      : null;
  const current: Values | null = existing ? (loadedSecret?.values ?? null) : {};

  const incoming = initial.values;
  const merged =
    current === null ? null : mergeValues(current, incoming, existing ? strategy : "add");
  const skipped: MergeRow[] = [
    ...initial.empty.map((name) => ({ name, status: "skipped" as const })),
    ...initial.invalid.map((name) => ({ name, status: "invalid" as const })),
  ];
  const incomingCount = Object.keys(incoming).length;
  const canSave =
    !busy &&
    validSecretPath(path) &&
    (existing || !isReservedSecretPath(path)) &&
    incomingCount > 0 &&
    merged !== null &&
    (!existing || loadedSecret !== null);

  const save = async () => {
    if (!canSave) return;
    setError(null);
    setBusy(true);
    try {
      if (existing) {
        if (loadedSecret === null || merged === null) return;
        await saveValues({
          path,
          values: merged.result,
          currentVersion: loadedSecret.version,
          groupKey: loadedSecret.groupKey,
          keyVersion: loadedSecret.keyVersion,
        });
      } else {
        const { groupKey, keyVersion } = await groupKeyFor(groupOf(path));
        await saveValues({ path, values: incoming, currentVersion: 0, groupKey, keyVersion });
      }
      onDone(path);
    } catch (err) {
      setBusy(false);
      if (secretConflictMessage(err)) {
        setError(secretConflictMessage(err) as string);
      } else if (isConflict(err)) {
        setError(
          t(
            "This secret changed while you were reviewing. We reloaded it, so check the table again and save once more. Nothing was saved.",
            "Secret ini berubah saat kamu meninjau. Kami memuatnya ulang, jadi periksa tabel lalu simpan sekali lagi. Tidak ada yang tersimpan.",
          ),
        );
        loaded.reload();
      } else if (isNoKey(err)) {
        setError(
          t(
            `You don't have a key for the group ${groupOf(path)}. Ask someone in the group to give you access first.`,
            `Kamu tidak punya kunci untuk grup ${groupOf(path)}. Minta anggota grup memberimu akses dulu.`,
          ),
        );
      } else {
        setError(
          t(
            "We couldn't save. Check your connection and try again. Nothing was changed.",
            "Kami tidak bisa menyimpan. Periksa koneksi lalu coba lagi. Tidak ada yang berubah.",
          ),
        );
      }
    }
  };

  const version = existing && loadedSecret !== null ? loadedSecret.version + 1 : 1;
  const rows: MergeRow[] = [...(merged?.rows ?? []), ...skipped];
  const toSave = merged ? Object.keys(merged.result).length : 0;

  return (
    <div class="secrets-page import-page">
      <div class="top">
        <div>
          <Steps current={2} />
          <PageTitle crumbs={pageCrumbs("secretsImportReview")} />
          <p class="sub">
            {t(
              "Here's what we found in your file. Nothing is saved until you press the button at the bottom.",
              "Ini yang kami temukan di filemu. Tidak ada yang disimpan sampai kamu menekan tombol di bawah.",
            )}
          </p>
        </div>
      </div>

      <div class="review-split">
        <div class="card tw review-card">
          <div class="review-head">
            <h2>{t("What we found", "Yang kami temukan")}</h2>
            <Pill tone="acc">
              {t(
                `${incomingCount + skipped.length} items found`,
                `${incomingCount + skipped.length} item ditemukan`,
              )}
            </Pill>
          </div>
          {merged === null && existing ? (
            <div class="sub center-line" role="status">
              {loaded.state.status === "reason-required" ? (
                <ReasonForm onSubmit={loaded.submitReason} />
              ) : loaded.state.status === "loading" || loaded.state.status === "ready" ? (
                t("Loading the current values...", "Memuat nilai yang ada...")
              ) : (
                loadProblem(loaded.state.status)
              )}
            </div>
          ) : (
            <table class="tbl">
              <thead>
                <tr>
                  <th scope="col">{t("Name", "Nama")}</th>
                  <th scope="col">{t("Type", "Tipe")}</th>
                  <th scope="col">{t("Value", "Nilai")}</th>
                  <th scope="col">{t("What happens", "Yang terjadi")}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <ReviewRow key={`${r.status}:${r.name}`} row={r} value={incoming[r.name]} />
                ))}
              </tbody>
            </table>
          )}
          <p class="review-foot">
            {t(
              "True/false and number values were detected automatically. Comments (#) are ignored.",
              "Nilai benar/salah dan angka dikenali otomatis. Komentar (#) diabaikan.",
            )}
          </p>
        </div>

        <div class="review-side">
          <div class="card side-card">
            <h2>{t("Save to", "Simpan ke")}</h2>
            <label class={`opt${existing ? " on" : ""}`}>
              <input
                type="radio"
                name="target"
                checked={existing}
                onChange={() =>
                  setTarget({ mode: "existing", path: existingDefault(secrets, path) })
                }
              />
              <span>
                {t("Existing secret", "Secret yang ada")}
                <small>
                  {t(
                    `Creates version ${version}. The current version stays in history.`,
                    `Membuat versi ${version}. Versi sebelumnya tetap di riwayat.`,
                  )}
                </small>
              </span>
            </label>
            {existing && (
              <div class="f">
                <label for="target-secret">{t("Secret", "Secret")}</label>
                <select
                  id="target-secret"
                  value={path}
                  onChange={(e) => setTarget({ mode: "existing", path: e.currentTarget.value })}
                >
                  {secrets.length === 0 && (
                    <option value="">{t("No secrets yet", "Belum ada secret")}</option>
                  )}
                  {secrets.map((s) => (
                    <option key={s.path} value={s.path}>
                      {s.path}
                    </option>
                  ))}
                </select>
              </div>
            )}
            <label class={`opt${existing ? "" : " on"}`}>
              <input
                type="radio"
                name="target"
                checked={!existing}
                onChange={() => setTarget({ mode: "new", path })}
              />
              <span>
                {t("A new secret", "Secret baru")}
                <small>{t("Pick a name and a group.", "Pilih nama dan grup.")}</small>
              </span>
            </label>
            {!existing && (
              <div class="f">
                <label for="target-name">{t("Name", "Nama")}</label>
                <input
                  id="target-name"
                  type="text"
                  value={path}
                  autocomplete="off"
                  spellcheck={false}
                  placeholder="myapp/staging"
                  onInput={(e) => setTarget({ mode: "new", path: e.currentTarget.value.trim() })}
                />
                {isReservedSecretPath(path) && (
                  <span class="field-error" role="alert">
                    {t(
                      "This name is reserved for a web page.",
                      "Nama ini dicadangkan untuk halaman web.",
                    )}
                  </span>
                )}
              </div>
            )}
          </div>

          {existing && (
            <fieldset class="card side-card strategy">
              <legend>{t("If a name already exists", "Jika nama sudah ada")}</legend>
              {STRATEGIES.map((s) => (
                <label key={s.id} class={`opt${strategy === s.id ? " on" : ""}`}>
                  <input
                    type="radio"
                    name="strategy"
                    value={s.id}
                    checked={strategy === s.id}
                    onChange={() => setStrategy(s.id)}
                  />
                  <span>
                    {s.label()}
                    <small>{s.sub()}</small>
                  </span>
                </label>
              ))}
            </fieldset>
          )}
        </div>
      </div>

      {error && <WarnBox>{error}</WarnBox>}

      <div class="review-actions">
        <span class="note">
          {merged
            ? t(
                `${toSave} items will be locked and saved. ${skipped.length} skipped.`,
                `${toSave} item akan dikunci dan disimpan. ${skipped.length} dilewati.`,
              )
            : ""}
        </span>
        <div class="row-actions">
          <Link class="btn ghost" href={PATHS.secretsImport}>
            {t("Back", "Kembali")}
          </Link>
          <button type="button" class="btn" onClick={save} disabled={!canSave}>
            {existing
              ? t(`Save as version ${version}`, `Simpan sebagai versi ${version}`)
              : t("Create and save", "Buat dan simpan")}
          </button>
        </div>
      </div>
    </div>
  );
}

const STRATEGIES: { id: MergeStrategy; label: () => string; sub: () => string }[] = [
  {
    id: "add",
    label: () => t("Only add new names", "Hanya tambah nama baru"),
    sub: () =>
      t(
        "Names that already exist keep their current value.",
        "Nama yang sudah ada tetap dengan nilai lamanya.",
      ),
  },
  {
    id: "overwrite",
    label: () => t("Replace the current value", "Ganti nilai yang ada"),
    sub: () =>
      t(
        "Names in the file get the new value. Other names stay.",
        "Nama di file mendapat nilai baru. Nama lain tetap.",
      ),
  },
  {
    id: "replace",
    label: () => t("Replace all", "Ganti semua"),
    sub: () =>
      t(
        "The secret becomes exactly the file. Names missing from it are removed.",
        "Secret menjadi persis seperti file. Nama yang tidak ada di file dihapus.",
      ),
  },
];

/** When the target changes to "existing", keep the path that was typed, or the first secret. */
function existingDefault(secrets: SecretSummary[], path: string): string {
  if (path !== "" && secrets.some((s) => s.path === path)) return path;
  return secrets[0]?.path ?? path;
}

function loadProblem(status: string): string {
  if (status === "nokey") {
    return t(
      "You can't merge into this secret yet. You need a key for its group first.",
      "Kamu belum bisa menggabung ke secret ini. Kamu perlu kunci untuk grupnya dulu.",
    );
  }
  if (status === "denied") {
    return t("You can't change this secret.", "Kamu tidak bisa mengubah secret ini.");
  }
  return t("We couldn't load the current values.", "Nilai yang ada tidak bisa dimuat.");
}

/** One name in the review. The value stays as dots until Show, and hides again after 30 seconds. */
function ReviewRow({ row, value }: { row: MergeRow; value: string | undefined }) {
  useLang();
  const reveal = useReveal();
  const skipped = row.status === "skipped" || row.status === "invalid";
  const status = statusLabel(row.status);
  const tone: PillTone =
    row.status === "replaced"
      ? "warn"
      : row.status === "removed"
        ? "bad"
        : row.status === "new"
          ? "ok"
          : "";
  return (
    <tr>
      <td class="name">{row.name}</td>
      <td class="tag">{value !== undefined ? typeLabel(typeOf(value)) : "—"}</td>
      <td>
        {skipped || value === undefined ? (
          <span class="muted">{row.status === "skipped" ? t("(empty)", "(kosong)") : "—"}</span>
        ) : reveal.shown ? (
          <span class="clear">{value}</span>
        ) : (
          <span class="mask">
            <span class="visually-hidden">{t("Hidden value", "Nilai tersembunyi")}</span>
            <span aria-hidden="true">{MASK}</span>
          </span>
        )}{" "}
        {value !== undefined && !skipped && (
          <button
            type="button"
            class="btn ghost sm"
            onClick={reveal.shown ? reveal.hide : reveal.show}
          >
            {reveal.shown ? t("Hide", "Sembunyikan") : t("Show", "Tampilkan")}
          </button>
        )}
      </td>
      <td>
        <Pill tone={tone}>{status}</Pill>
      </td>
    </tr>
  );
}

function statusLabel(status: MergeRow["status"]): string {
  switch (status) {
    case "new":
      return t("New", "Baru");
    case "same":
      return t("Same", "Sama");
    case "replaced":
      return t("Replaces current", "Mengganti yang ada");
    case "kept":
      return t("Keeps current", "Mempertahankan yang ada");
    case "removed":
      return t("Removed", "Dihapus");
    case "skipped":
      return t("Skipped", "Dilewati");
    case "invalid":
      return t("Skipped: invalid name", "Dilewati: nama tidak valid");
  }
}
