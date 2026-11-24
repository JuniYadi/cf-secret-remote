// ADR 36: environment collections. Names and paths only. The list, the form (create and edit) and the detail
// page with compare and reconcile. Every write goes through a preview first, and removals need a confirmation.
import { useState } from "preact/hooks";
import { Link, useLocation } from "wouter-preact";
import { failureText, LoadStatus, Notice, Pill, useLoad } from "../components/Admin.tsx";
import { PageTitle } from "../components/shared.tsx";
import {
  ApiError,
  api,
  type CollectionCompare,
  type CollectionDefinition,
  type CollectionPreview,
  type DiscoverResult,
  type EnvCompare,
  type ReconcilePreview,
} from "../lib/api.ts";
import {
  collectionHref,
  type DraftErrors,
  draftBody,
  type EnvRow,
  extraNames,
  type KeyRow,
  LABEL_RE,
  MAX_ENVS,
  MAX_KEYS,
  removalsOf,
  resultHelp,
  resultLabel,
  resultTone,
  rowsFrom,
  validateDraft,
} from "../lib/collections.ts";
import { useLang } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { collectionEditPath, collectionPath, PATHS, pageCrumbs } from "../routes.ts";

/** Conflict codes from the API (ADR 36) get their own sentence. Anything else falls back to the shared text. */
function collectionFailure(err: unknown): string {
  if (err instanceof ApiError && err.kind === "conflict") {
    if (err.code === "source_changed")
      return t(
        "A secret changed after its names were read. Preview again.",
        "Sebuah secret berubah setelah namanya dibaca. Pratinjau lagi.",
      );
    if (err.code === "name_exists")
      return t("A collection with this name already exists.", "Koleksi dengan nama ini sudah ada.");
    return t(
      "This collection changed while you were working. Reload and try again.",
      "Koleksi ini berubah saat kamu bekerja. Muat ulang lalu coba lagi.",
    );
  }
  return failureText(err);
}

const ERROR_TEXT = {
  name: {
    empty: () => t("Give the collection a name.", "Beri nama koleksi."),
    shape: () =>
      t(
        "Use letters, numbers, dots and dashes. Start with a letter or number.",
        "Pakai huruf, angka, titik, dan tanda hubung. Mulai dengan huruf atau angka.",
      ),
    reserved: () =>
      t("new is reserved. Pick another name.", "new dipakai sistem. Pilih nama lain."),
    tooLong: () => t("Keep the name under 64 characters.", "Buat nama kurang dari 64 karakter."),
  },
  label: {
    empty: () => t("Give this environment a label, such as dev.", "Beri label, misalnya dev."),
    shape: () =>
      t("Use letters, numbers, dots and dashes.", "Pakai huruf, angka, titik, dan tanda hubung."),
    tooLong: () => t("Keep the label under 32 characters.", "Buat label kurang dari 32 karakter."),
  },
  path: {
    empty: () =>
      t("Write the secret path, such as myapp/dev.", "Tulis path secret, misalnya myapp/dev."),
    shape: () =>
      t(
        "Use letters, numbers, dots and dashes, separated by /. Example: myapp/dev.",
        "Pakai huruf, angka, titik, dan tanda hubung, dipisah /. Contoh: myapp/dev.",
      ),
    tooLong: () => t("That path is too long.", "Path itu terlalu panjang."),
  },
  key: {
    empty: () => t("Give the key a name.", "Beri nama key."),
    shape: () =>
      t(
        "Use letters, numbers and underscores. Start with a letter or underscore, such as API_KEY.",
        "Pakai huruf, angka, dan garis bawah. Mulai dengan huruf atau garis bawah, misalnya API_KEY.",
      ),
  },
  description: {
    tooLong: () =>
      t("Keep the description under 200 characters.", "Buat deskripsi kurang dari 200 karakter."),
  },
};

/** The first sentence that explains the form's problem. Describes only the shape of the input, never a value. */
function firstProblem(e: DraftErrors): string | null {
  if (e.name) return ERROR_TEXT.name[e.name]();
  if (e.noEnvs) return t("Add at least one environment.", "Tambah minimal satu environment.");
  if (e.tooManyEnvs)
    return t(
      `Use at most ${MAX_ENVS} environments.`,
      `Pakai paling banyak ${MAX_ENVS} environment.`,
    );
  if (e.tooManyKeys)
    return t(`Use at most ${MAX_KEYS} keys.`, `Pakai paling banyak ${MAX_KEYS} key.`);
  if (e.duplicateLabels)
    return t("Two environments use the same label.", "Dua environment memakai label yang sama.");
  if (e.duplicatePaths)
    return t(
      "Two environments point at the same path.",
      "Dua environment menunjuk path yang sama.",
    );
  if (e.duplicateKeys)
    return t("Two rows use the same key name.", "Dua baris memakai nama key yang sama.");
  for (const row of e.envs) {
    if (row.label) return ERROR_TEXT.label[row.label as "empty"]?.() ?? null;
    if (row.path) return ERROR_TEXT.path[row.path as "empty"]?.() ?? null;
  }
  for (const row of e.keys) {
    if (row.name) return ERROR_TEXT.key[row.name as "empty"]?.() ?? null;
    if (row.description) return ERROR_TEXT.description.tooLong();
  }
  return null;
}

/** The list of collections the person can read. Names and counts only. */
export function CollectionsPage() {
  useLang();
  const list = useLoad(() => api.collections(), "collections");
  return (
    <div class="page">
      <PageTitle crumbs={pageCrumbs("collections")} />
      <div class="page-head">
        <p class="sub page-sub">
          {t(
            "Declare the key names each environment should have, such as dev, staging and prod. Values stay separate.",
            "Deklarasikan nama key yang harus dimiliki tiap environment, misalnya dev, staging, dan prod. Nilainya tetap terpisah.",
          )}
        </p>
        <Link class="btn" href={PATHS.collectionsNew}>
          {t("New collection", "Koleksi baru")}
        </Link>
      </div>
      <LoadStatus state={list} />
      {list.data && list.data.length === 0 && (
        <Notice tone="info">
          {t(
            "No collections you can see yet. Ask a maintainer to share one, or create one if you maintain this project.",
            "Belum ada koleksi yang bisa kamu lihat. Minta maintainer membagikannya, atau buat sendiri jika kamu mengurus proyek ini.",
          )}
        </Notice>
      )}
      {list.data && list.data.length > 0 && (
        <div class="card">
          <table class="data-table">
            <thead>
              <tr>
                <th scope="col">{t("Collection", "Koleksi")}</th>
                <th scope="col">{t("Environments", "Environment")}</th>
                <th scope="col">{t("Keys", "Key")}</th>
                <th scope="col">{t("Revision", "Revisi")}</th>
              </tr>
            </thead>
            <tbody>
              {list.data.map((c) => (
                <tr key={c.name}>
                  <td>
                    <Link class="mono" href={collectionHref(c.name)}>
                      {c.name}
                    </Link>
                  </td>
                  <td>{c.envCount}</td>
                  <td>{c.keyCount}</td>
                  <td>{c.revision}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function EnvRows({
  rows,
  errors,
  onChange,
  onRemove,
  onAdd,
}: {
  rows: EnvRow[];
  errors: DraftErrors["envs"];
  onChange: (i: number, patch: Partial<EnvRow>) => void;
  onRemove: (i: number) => void;
  onAdd: () => void;
}) {
  useLang();
  return (
    <>
      {rows.map((row, i) => (
        <div class="rule-row" key={`env-${i}`}>
          <div class="field">
            <label for={`env-label-${i}`}>{t("Label", "Label")}</label>
            <input
              id={`env-label-${i}`}
              type="text"
              value={row.label}
              placeholder="dev"
              autocomplete="off"
              aria-invalid={errors[i]?.label ? "true" : undefined}
              onInput={(e) => onChange(i, { label: e.currentTarget.value })}
            />
            {errors[i]?.label && (
              <span class="field-error" role="alert">
                {ERROR_TEXT.label[errors[i]?.label as "empty"]()}
              </span>
            )}
          </div>
          <div class="field">
            <label for={`env-path-${i}`}>{t("Secret path", "Path secret")}</label>
            <input
              id={`env-path-${i}`}
              type="text"
              value={row.path}
              placeholder="myapp/dev"
              autocomplete="off"
              class="mono-input"
              aria-invalid={errors[i]?.path ? "true" : undefined}
              onInput={(e) => onChange(i, { path: e.currentTarget.value })}
            />
            {errors[i]?.path && (
              <span class="field-error" role="alert">
                {ERROR_TEXT.path[errors[i]?.path as "empty"]()}
              </span>
            )}
          </div>
          <button type="button" class="link-btn" onClick={() => onRemove(i)}>
            {t("Remove", "Hapus")}
            <span class="visually-hidden"> {i + 1}</span>
          </button>
        </div>
      ))}
      <div>
        <button
          type="button"
          class="btn ghost sm"
          onClick={onAdd}
          disabled={rows.length >= MAX_ENVS}
        >
          {t("+ Add environment", "+ Tambah environment")}
        </button>
      </div>
    </>
  );
}

function KeyRows({
  rows,
  errors,
  onChange,
  onRemove,
  onAdd,
}: {
  rows: KeyRow[];
  errors: DraftErrors["keys"];
  onChange: (i: number, patch: Partial<KeyRow>) => void;
  onRemove: (i: number) => void;
  onAdd: () => void;
}) {
  useLang();
  return (
    <>
      {rows.map((row, i) => (
        <div class="rule-row" key={`key-${i}`}>
          <div class="field">
            <label for={`key-name-${i}`}>{t("Key name", "Nama key")}</label>
            <input
              id={`key-name-${i}`}
              type="text"
              value={row.name}
              placeholder="API_KEY"
              autocomplete="off"
              class="mono-input"
              aria-invalid={errors[i]?.name ? "true" : undefined}
              onInput={(e) => onChange(i, { name: e.currentTarget.value })}
            />
            {errors[i]?.name && (
              <span class="field-error" role="alert">
                {ERROR_TEXT.key.shape()}
              </span>
            )}
          </div>
          <div class="field">
            <label for={`key-desc-${i}`}>
              {t("Description (optional, no secrets)", "Deskripsi (opsional, jangan isi rahasia)")}
            </label>
            <input
              id={`key-desc-${i}`}
              type="text"
              value={row.description}
              autocomplete="off"
              aria-invalid={errors[i]?.description ? "true" : undefined}
              onInput={(e) => onChange(i, { description: e.currentTarget.value })}
            />
            {errors[i]?.description && (
              <span class="field-error" role="alert">
                {ERROR_TEXT.description.tooLong()}
              </span>
            )}
          </div>
          <button type="button" class="link-btn" onClick={() => onRemove(i)}>
            {t("Remove", "Hapus")}
            <span class="visually-hidden"> {i + 1}</span>
          </button>
        </div>
      ))}
      <div>
        <button
          type="button"
          class="btn ghost sm"
          onClick={onAdd}
          disabled={rows.length >= MAX_KEYS}
        >
          {t("+ Add key", "+ Tambah key")}
        </button>
      </div>
    </>
  );
}

/** New collection, or edit an existing one (initial is the stored definition, revision its version). */
function CollectionForm({
  mode,
  initial,
  revision,
  source = "",
}: {
  mode: "new" | "edit";
  initial: { name: string; envs: EnvRow[]; keys: KeyRow[] };
  revision: number;
  source?: string;
}) {
  useLang();
  const [, navigate] = useLocation();
  const [name, setName] = useState(initial.name);
  const [envs, setEnvs] = useState<EnvRow[]>(
    initial.envs.length ? initial.envs : [{ label: "", path: "" }],
  );
  const [keys, setKeys] = useState<KeyRow[]>(initial.keys);
  const [from, setFrom] = useState(source);
  const [discovered, setDiscovered] = useState<DiscoverResult | null>(null);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [sourceVersions, setSourceVersions] = useState<Record<string, number> | undefined>(
    undefined,
  );
  const [preview, setPreview] = useState<CollectionPreview | null>(null);
  const [previewedFor, setPreviewedFor] = useState<string | null>(null);
  const [confirmRemoval, setConfirmRemoval] = useState(false);
  const [tried, setTried] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const check = validateDraft(name, envs, keys, { nameEditable: mode === "new" });
  const body = draftBody(envs, keys);
  const bodyKey = JSON.stringify({ name: name.trim(), ...body });
  const fresh = preview !== null && previewedFor === bodyKey;
  const removals = preview && fresh ? removalsOf(preview.changes) : { keys: [], envs: [] };
  const hasRemovals = removals.keys.length + removals.envs.length > 0;
  const firstIssue = tried ? firstProblem(check.errors) : null;

  // Any edit to the body makes the last preview stale. The person must preview again before saving.
  async function runPreview() {
    setTried(true);
    setError(null);
    if (!check.valid) return;
    setBusy(true);
    try {
      const p = await api.collectionPreview({ name: name.trim(), ...body });
      setPreview(p);
      setPreviewedFor(bodyKey);
      setConfirmRemoval(false);
    } catch (err) {
      setError(collectionFailure(err));
    } finally {
      setBusy(false);
    }
  }

  async function readPaths() {
    setError(null);
    setDiscovered(null);
    const paths = from
      .split(",")
      .map((p) => p.trim())
      .filter((p) => p !== "");
    if (paths.length === 0) return;
    setBusy(true);
    try {
      const d = await api.discoverPaths(paths);
      setDiscovered(d);
      setPicked(new Set(d.union));
    } catch (err) {
      setError(collectionFailure(err));
    } finally {
      setBusy(false);
    }
  }

  function useUnion() {
    const have = new Set(keys.map((k) => k.name.trim()));
    const added = [...picked]
      .filter((n) => !have.has(n))
      .map((n) => ({ name: n, description: "" }));
    if (added.length && discovered) {
      const versions = Object.fromEntries(
        discovered.sources.flatMap((s) =>
          s.status === "ok" ? [[s.path, s.version] as const] : [],
        ),
      );
      setSourceVersions((previous) => ({ ...versions, ...previous }));
    }
    setKeys([...keys, ...added]);
  }

  async function save() {
    setTried(true);
    setError(null);
    if (!check.valid || !fresh || busy) return;
    if (hasRemovals && !confirmRemoval) return;
    setBusy(true);
    try {
      if (mode === "new") {
        await api.createCollection({
          name: name.trim(),
          ...body,
          ...(sourceVersions && Object.keys(sourceVersions).length ? { sourceVersions } : {}),
        });
        navigate(collectionPath(name.trim()));
      } else {
        await api.updateCollection(name.trim(), { revision, ...body, removed: removals });
        navigate(collectionPath(name.trim()));
      }
    } catch (err) {
      setBusy(false);
      setError(collectionFailure(err));
    }
  }

  const nameError = tried && check.errors.name ? ERROR_TEXT.name[check.errors.name]() : null;

  return (
    <div class="page">
      <PageTitle
        crumbs={pageCrumbs(mode === "new" ? "collectionNew" : "collectionEdit", initial.name)}
      />
      <div class="cols">
        <form
          class="card form-stack col-main"
          aria-labelledby="collection-form-title"
          onSubmit={(e) => {
            e.preventDefault();
            void save();
          }}
        >
          <h2 id="collection-form-title" class="visually-hidden">
            {mode === "new"
              ? t("New collection", "Koleksi baru")
              : t("Edit collection", "Ubah koleksi")}
          </h2>

          <div class="field">
            <label for="collection-name">{t("Name", "Nama")}</label>
            <input
              id="collection-name"
              type="text"
              value={name}
              disabled={mode === "edit"}
              autocomplete="off"
              class="mono-input"
              aria-invalid={nameError ? "true" : undefined}
              onInput={(e) => {
                setName(e.currentTarget.value);
                setError(null);
              }}
            />
            {nameError && (
              <span class="field-error" role="alert">
                {nameError}
              </span>
            )}
          </div>

          <h2 class="section-title">{t("Environments", "Environment")}</h2>
          <p class="note">
            {t(
              "Each label points at one secret path. Labels are yours to choose.",
              "Setiap label menunjuk satu path secret. Labelnya bebas kamu pilih.",
            )}
          </p>
          <EnvRows
            rows={envs}
            errors={check.errors.envs}
            onChange={(i, patch) => {
              setError(null);
              setEnvs((prev) => prev.map((r, j) => (j === i ? { ...r, ...patch } : r)));
            }}
            onRemove={(i) => {
              setError(null);
              setEnvs((prev) => prev.filter((_, j) => j !== i));
            }}
            onAdd={() => {
              setError(null);
              setEnvs((prev) => [...prev, { label: "", path: "" }]);
            }}
          />

          <h2 class="section-title">{t("Key names", "Nama key")}</h2>
          <p class="note">
            {t(
              "Names only. Do not put a secret value in a description.",
              "Hanya nama. Jangan tulis nilai secret di deskripsi.",
            )}
          </p>
          {source && (
            <p class="note">
              {t(
                "Read the source names below, choose the ones to copy, and add your other environment paths. The collection tracks missing names; it does not create secrets or copy values.",
                "Baca nama sumber di bawah, pilih yang akan disalin, lalu tambahkan path environment lainnya. Koleksi melacak nama yang belum ada; koleksi tidak membuat secret atau menyalin nilai.",
              )}
            </p>
          )}
          {mode === "new" && (
            <div class="field">
              <label for="collection-from">
                {t(
                  "Start from existing paths (comma separated, optional)",
                  "Mulai dari path yang ada (pisahkan dengan koma, opsional)",
                )}
              </label>
              <div class="row-inline">
                <input
                  id="collection-from"
                  type="text"
                  value={from}
                  placeholder="myapp/dev, myapp/prod"
                  class="mono-input"
                  autocomplete="off"
                  onInput={(e) => {
                    setFrom(e.currentTarget.value);
                    setDiscovered(null);
                  }}
                />
                <button
                  type="button"
                  class="btn ghost sm"
                  disabled={busy}
                  onClick={() => void readPaths()}
                >
                  {t("Read names", "Baca nama")}
                </button>
              </div>
              {discovered && (
                <fieldset class="field fieldset">
                  <legend>
                    {t(
                      "Names found. Pick the ones to declare.",
                      "Nama yang ditemukan. Pilih yang akan dideklarasikan.",
                    )}
                  </legend>
                  {discovered.sources.map((s) => (
                    <p class="note" key={s.path}>
                      <span class="mono">{s.path}</span>:{" "}
                      {s.status === "ok"
                        ? t("read", "terbaca")
                        : t("path does not exist", "path tidak ada")}
                    </p>
                  ))}
                  <div class="cap-toggles">
                    {discovered.union.map((n) => (
                      <label key={n} class="cap">
                        <input
                          type="checkbox"
                          checked={picked.has(n)}
                          onChange={(e) => {
                            const next = new Set(picked);
                            if (e.currentTarget.checked) next.add(n);
                            else next.delete(n);
                            setPicked(next);
                          }}
                        />{" "}
                        <span class="mono">{n}</span>
                      </label>
                    ))}
                  </div>
                  <button type="button" class="btn ghost sm" onClick={useUnion}>
                    {t("Add selected names", "Tambah nama terpilih")}
                  </button>
                </fieldset>
              )}
            </div>
          )}
          <KeyRows
            rows={keys}
            errors={check.errors.keys}
            onChange={(i, patch) => {
              setError(null);
              setKeys((prev) => prev.map((r, j) => (j === i ? { ...r, ...patch } : r)));
            }}
            onRemove={(i) => {
              setError(null);
              setKeys((prev) => prev.filter((_, j) => j !== i));
            }}
            onAdd={() => {
              setError(null);
              setKeys((prev) => [...prev, { name: "", description: "" }]);
            }}
          />

          {firstIssue && (
            <span class="field-error" role="alert">
              {firstIssue}
            </span>
          )}
          {error && (
            <p class="field-error" role="alert">
              {error}
            </p>
          )}

          <div class="form-foot">
            <Link
              class="btn ghost"
              href={mode === "new" ? PATHS.collections : collectionHref(initial.name)}
            >
              {t("Cancel", "Batal")}
            </Link>
            <button
              type="button"
              class="btn ghost"
              disabled={busy}
              onClick={() => void runPreview()}
            >
              {t("Preview changes", "Pratinjau perubahan")}
            </button>
            <button
              type="submit"
              class="btn"
              disabled={busy || !fresh || (hasRemovals && !confirmRemoval)}
            >
              {mode === "new"
                ? t("Create collection", "Buat koleksi")
                : t("Save changes", "Simpan perubahan")}
            </button>
          </div>
        </form>

        <aside class="card side-note col-side" aria-labelledby="preview-title">
          <h2 id="preview-title">{t("What will change", "Yang akan berubah")}</h2>
          {!preview || !fresh ? (
            <p class="note">
              {t(
                "Preview first. The preview shows names and paths only, never values.",
                "Pratinjau dulu. Pratinjau hanya menampilkan nama dan path, tidak pernah nilai.",
              )}
            </p>
          ) : (
            <PreviewList preview={preview} />
          )}
          {preview && fresh && hasRemovals && (
            <label class="check-row">
              <input
                type="checkbox"
                checked={confirmRemoval}
                onChange={(e) => setConfirmRemoval(e.currentTarget.checked)}
              />{" "}
              {t(
                "I understand these names or environments are removed from the declaration. Stored values are kept.",
                "Saya paham nama atau environment ini dihapus dari deklarasi. Nilai yang tersimpan tetap ada.",
              )}
            </label>
          )}
          {preview && !fresh && (
            <Notice tone="warn">
              {t(
                "The form changed after the preview. Preview again.",
                "Form berubah setelah pratinjau. Pratinjau lagi.",
              )}
            </Notice>
          )}
        </aside>
      </div>
    </div>
  );
}

function PreviewList({ preview }: { preview: CollectionPreview }) {
  useLang();
  const c = preview.changes;
  const lines: { mark: string; text: string }[] = [
    ...c.addedKeys.map((k) => ({ mark: "+", text: `${t("key", "key")} ${k}` })),
    ...c.removedKeys.map((k) => ({ mark: "−", text: `${t("key", "key")} ${k}` })),
    ...c.changedKeys.map((k) => ({ mark: "~", text: `${t("description of", "deskripsi")} ${k}` })),
    ...c.addedEnvs.map((l) => ({ mark: "+", text: `${t("environment", "environment")} ${l}` })),
    ...c.removedEnvs.map((l) => ({ mark: "−", text: `${t("environment", "environment")} ${l}` })),
    ...c.changedEnvs.map((l) => ({ mark: "~", text: `${t("path of", "path")} ${l}` })),
  ];
  return (
    <>
      <p class="note">
        {preview.exists
          ? t(`Revision ${preview.revision} now.`, `Revisi ${preview.revision} sekarang.`)
          : t("This will be a new collection.", "Ini akan menjadi koleksi baru.")}
      </p>
      {lines.length === 0 ? (
        <p class="note">
          {t("No change to the declaration.", "Tidak ada perubahan pada deklarasi.")}
        </p>
      ) : (
        <ul class="plain-list">
          {lines.map((l, i) => (
            <li key={i}>
              <span aria-hidden="true">{l.mark}</span> {l.text}
            </li>
          ))}
        </ul>
      )}
      <h3 class="section-title">{t("Paths", "Path")}</h3>
      <ul class="plain-list">
        {preview.envs.map((e) => (
          <li key={e.label}>
            <span class="mono">{e.label}</span> <span class="mono">{e.path}</span>:{" "}
            {e.status === "ok"
              ? t("readable", "bisa dibaca")
              : e.status === "missing_path"
                ? t("does not exist yet", "belum ada")
                : t("you cannot see this path", "kamu tidak bisa melihat path ini")}
          </li>
        ))}
      </ul>
    </>
  );
}

export function CollectionNewPage() {
  const source = new URLSearchParams(window.location.search).get("source") ?? "";
  const label = source.split("/").pop() ?? "";
  return (
    <CollectionForm
      mode="new"
      initial={{
        name: "",
        envs: source ? [{ label: LABEL_RE.test(label) ? label : "", path: source }] : [],
        keys: [],
      }}
      revision={0}
      source={source}
    />
  );
}

/** Loads the stored definition, then opens the form on it. */
export function CollectionEditPage({ name }: { name: string }) {
  useLang();
  const def = useLoad(() => api.collection(name), `edit-${name}`);
  if (!def.data)
    return (
      <div class="page">
        <PageTitle crumbs={pageCrumbs("collectionEdit", name)} />
        <LoadStatus state={def} />
      </div>
    );
  const rows = rowsFrom(def.data);
  return (
    <CollectionForm
      key={`${name}-${def.data.revision}`}
      mode="edit"
      initial={{ name, envs: rows.envs, keys: rows.keys }}
      revision={def.data.revision}
    />
  );
}

/** The detail page: the declaration, the comparison, the reconcile flow, and delete. */
export function CollectionDetailPage({ name }: { name: string }) {
  useLang();
  const [, navigate] = useLocation();
  const def = useLoad<CollectionDefinition>(() => api.collection(name), `def-${name}`);
  const cmp = useLoad<CollectionCompare>(() => api.collectionCompare(name), `cmp-${name}`);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [plan, setPlan] = useState<ReconcilePreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const crumbs = pageCrumbs("collectionDetail", name);
  if (def.error) {
    return (
      <div class="page">
        <PageTitle crumbs={crumbs} />
        <LoadStatus state={def} />
      </div>
    );
  }
  const data = def.data;
  const result = cmp.data?.result;
  const candidates = cmp.data ? extraNames(cmp.data) : [];

  async function previewAdds() {
    setError(null);
    setBusy(true);
    try {
      setPlan(await api.reconcilePreview(name, [...picked]));
    } catch (err) {
      setError(collectionFailure(err));
    } finally {
      setBusy(false);
    }
  }

  async function applyAdds() {
    if (!plan) return;
    setError(null);
    setBusy(true);
    try {
      await api.reconcileApply(name, {
        revision: plan.revision,
        names: plan.names.map((n) => n.name),
        sourceVersions: plan.sourceVersions,
      });
      setPlan(null);
      setPicked(new Set());
      def.reload();
      cmp.reload();
    } catch (err) {
      setError(collectionFailure(err));
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!data) return;
    setError(null);
    setBusy(true);
    try {
      await api.deleteCollection(name, data.revision);
      navigate(PATHS.collections);
    } catch (err) {
      setBusy(false);
      setError(collectionFailure(err));
    }
  }

  return (
    <div class="page">
      <PageTitle crumbs={crumbs} />
      <div class="page-head">
        <p class="sub page-sub">
          {data ? t(`Revision ${data.revision}.`, `Revisi ${data.revision}.`) : ""}{" "}
          {t(
            "Values are not shown here. Each environment is read for names only.",
            "Nilai tidak ditampilkan di sini. Tiap environment dibaca hanya untuk namanya.",
          )}
        </p>
        <div class="row-inline">
          <Link class="btn ghost" href={collectionEditPath(name)}>
            {t("Edit", "Ubah")}
          </Link>
          <button type="button" class="btn ghost" onClick={() => setDeleting(true)} disabled={busy}>
            {t("Delete declaration", "Hapus deklarasi")}
          </button>
        </div>
      </div>

      {deleting && (
        <Notice tone="warn">
          {t(
            "This deletes the declaration only. Stored values in every environment are kept.",
            "Ini hanya menghapus deklarasi. Nilai yang tersimpan di semua environment tetap ada.",
          )}{" "}
          <button type="button" class="btn sm" disabled={busy} onClick={() => void remove()}>
            {t("Delete it", "Hapus")}
          </button>{" "}
          <button type="button" class="link-btn" onClick={() => setDeleting(false)}>
            {t("Keep it", "Simpan")}
          </button>
        </Notice>
      )}
      {error && <Notice tone="danger">{error}</Notice>}

      <section class="card" aria-labelledby="compare-title">
        <div class="card-head">
          <h2 id="compare-title" class="card-title">
            {t("Comparison", "Perbandingan")}
          </h2>
          {result && <Pill tone={resultTone(result)}>{resultLabel(result)}</Pill>}
        </div>
        {result && <p class="note">{resultHelp(result)}</p>}
        <LoadStatus state={cmp} />
        {cmp.data && (
          <CompareTable envs={cmp.data.envs} declared={data?.keys.map((k) => k.name) ?? []} />
        )}
      </section>

      <section class="card" aria-labelledby="reconcile-title">
        <h2 id="reconcile-title" class="card-title">
          {t("Names not declared yet", "Nama yang belum dideklarasikan")}
        </h2>
        {candidates.length === 0 ? (
          <p class="note">
            {t(
              "No extra names in the environments you can read.",
              "Tidak ada nama tambahan di environment yang bisa kamu baca.",
            )}
          </p>
        ) : (
          <>
            <p class="note">
              {t(
                "Adding a name to the declaration does not write any value. Each owner still fills their own environment.",
                "Menambah nama ke deklarasi tidak menulis nilai apa pun. Setiap pemilik tetap mengisi environment masing-masing.",
              )}
            </p>
            <div class="cap-toggles">
              {candidates.map((c) => (
                <label key={c.name} class="cap">
                  <input
                    type="checkbox"
                    checked={picked.has(c.name)}
                    onChange={(e) => {
                      const next = new Set(picked);
                      if (e.currentTarget.checked) next.add(c.name);
                      else next.delete(c.name);
                      setPicked(next);
                      setPlan(null);
                    }}
                  />{" "}
                  <span class="mono">{c.name}</span>{" "}
                  <span class="note">({c.labels.join(", ")})</span>
                </label>
              ))}
            </div>
            <div class="row-inline">
              <button
                type="button"
                class="btn ghost sm"
                disabled={busy || picked.size === 0}
                onClick={() => void previewAdds()}
              >
                {t("Preview adding them", "Pratinjau penambahan")}
              </button>
              {plan && (
                <button
                  type="button"
                  class="btn sm"
                  disabled={busy}
                  onClick={() => void applyAdds()}
                >
                  {t("Add to declaration", "Tambahkan ke deklarasi")}
                </button>
              )}
            </div>
            {plan && (
              <ul class="plain-list">
                {plan.names.map((n) => (
                  <li key={n.name}>
                    <span aria-hidden="true">+</span> <span class="mono">{n.name}</span>{" "}
                    {t(
                      `present in ${n.observedIn.join(", ")}`,
                      `ada di ${n.observedIn.join(", ")}`,
                    )}
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </section>

      {data && (
        <section class="card" aria-labelledby="declared-title">
          <h2 id="declared-title" class="card-title">
            {t("Declared keys", "Key yang dideklarasikan")}
          </h2>
          {data.keys.length === 0 ? (
            <p class="note">{t("No keys declared yet.", "Belum ada key yang dideklarasikan.")}</p>
          ) : (
            <ul class="plain-list">
              {data.keys.map((k) => (
                <li key={k.name}>
                  <span class="mono">{k.name}</span>
                  {k.description ? <span class="note"> {k.description}</span> : null}
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
    </div>
  );
}

function CompareTable({ envs, declared }: { envs: EnvCompare[]; declared: string[] }) {
  useLang();
  return (
    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th scope="col">{t("Environment", "Environment")}</th>
            <th scope="col">{t("Status", "Status")}</th>
            <th scope="col">{t("Missing", "Belum ada")}</th>
            <th scope="col">{t("Not declared", "Belum dideklarasikan")}</th>
          </tr>
        </thead>
        <tbody>
          {envs.map((e) => (
            <tr key={e.label}>
              <td>
                <span class="mono">{e.label}</span>
                <br />
                <span class="note mono">{e.path}</span>
              </td>
              <td>
                {e.status === "ok"
                  ? t(`Read, version ${e.version}`, `Terbaca, versi ${e.version}`)
                  : e.status === "missing_path"
                    ? t("Path does not exist", "Path tidak ada")
                    : t(
                        "You cannot see this environment",
                        "Kamu tidak bisa melihat environment ini",
                      )}
              </td>
              <td>
                {e.status !== "ok"
                  ? "—"
                  : e.missing && e.missing.length > 0
                    ? e.missing.map((n) => (
                        <span class="pill warn mono" key={n}>
                          {n}
                        </span>
                      ))
                    : declared.length === 0
                      ? "—"
                      : t("None", "Tidak ada")}
              </td>
              <td>
                {e.status !== "ok"
                  ? "—"
                  : e.extra && e.extra.length > 0
                    ? e.extra.map((n) => (
                        <span class="pill mono" key={n}>
                          {n}
                        </span>
                      ))
                    : t("None", "Tidak ada")}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
