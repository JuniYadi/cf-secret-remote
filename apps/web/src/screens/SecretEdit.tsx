// Edit a secret: the Fields tab (one row per item) and the JSON tab (the same data as text). Both tabs
// change the same values. Saving seals them in the browser and writes the next version (ADR 10, ADR 22).

import type { Values } from "@cfs/core";
import { useState } from "preact/hooks";
import { Link, useLocation } from "wouter-preact";
import { Pill, typeLabel, WarnBox } from "../components/secrets-ui.tsx";
import { PageTitle } from "../components/shared.tsx";
import { useLang } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { setImportHint } from "../lib/import-draft.ts";
import { isConflict, saveValues } from "../lib/secret-store.ts";
import {
  type Field,
  fieldsFromValues,
  parseJsonValues,
  toJsonText,
  type ValueType,
  validName,
  valuesFromFields,
} from "../lib/secrets.ts";
import { useSecret } from "../lib/use-secret.ts";
import { PATHS, pageCrumbs, secretHref } from "../routes.ts";
import { NoKeyView, SecretProblem } from "./SecretDetail.tsx";

/** The edit page: loads the current version, then shows the form for it. */
export function SecretEditPage({ name }: { name: string }) {
  useLang();
  const { state, reload } = useSecret(name);
  const [notice, setNotice] = useState<string | null>(null);

  const onConflict = () => {
    setNotice(
      t(
        "Someone else saved a new version while you were editing. We loaded the latest one. Your unsaved edits were not saved, so check them and save again.",
        "Orang lain menyimpan versi baru saat kamu mengubah. Kami memuat yang terbaru. Perubahanmu yang belum disimpan tidak tersimpan, jadi periksa lalu simpan lagi.",
      ),
    );
    reload();
  };

  if (state.status !== "ready") {
    return (
      <div class="secrets-page">
        <PageTitle crumbs={pageCrumbs("secretEdit", name)} />
        {state.status === "nokey" ? (
          <NoKeyView name={name} record={state.record} />
        ) : (
          <SecretProblem name={name} state={state} onRetry={reload} />
        )}
      </div>
    );
  }

  return (
    <div class="secrets-page">
      {notice && <WarnBox>{notice}</WarnBox>}
      <EditForm
        // A new version remounts the form, so it always starts from what is stored.
        key={state.secret.version}
        name={name}
        current={state.secret}
        onConflict={onConflict}
      />
    </div>
  );
}

interface FormProps {
  name: string;
  current: { version: number; values: Values; groupKey: Uint8Array; keyVersion: number };
  onConflict: () => void;
}

export function EditForm({ name, current, onConflict }: FormProps) {
  useLang();
  const [, navigate] = useLocation();
  const [tab, setTab] = useState<"fields" | "json">("fields");
  const [fields, setFields] = useState<Field[]>(() => fieldsFromValues(current.values));
  const [json, setJson] = useState("");
  const [error, setError] = useState<{ text: string; field?: number } | null>(null);
  const [busy, setBusy] = useState(false);

  const nextId = () => Math.max(0, ...fields.map((f) => f.id)) + 1;
  const updateField = (id: number, patch: Partial<Field>) =>
    setFields((rows) => rows.map((f) => (f.id === id ? { ...f, ...patch } : f)));

  /** Switching tabs carries the data over. A broken side stays where it is, with the reason shown. */
  const switchTo = (next: "fields" | "json") => {
    if (next === tab) return;
    if (next === "json") {
      const r = valuesFromFields(fields);
      if (!r.ok) {
        setError({ text: r.reason, field: r.field });
        return;
      }
      setJson(toJsonText(r.values));
    } else {
      const p = parseJsonValues(json);
      if (!p.ok) {
        setError({ text: p.reason });
        return;
      }
      setFields(fieldsFromValues(p.values));
    }
    setError(null);
    setTab(next);
  };

  /** The values to save, from whichever tab is open. */
  const collect = (): Values | null => {
    if (tab === "json") {
      const p = parseJsonValues(json);
      if (!p.ok) {
        setError({ text: p.reason });
        return null;
      }
      const bad = Object.keys(p.values).find((n) => !validName(n));
      if (bad !== undefined) {
        setError({
          text: t("Use letters, numbers and _ only.", "Pakai huruf, angka, dan _ saja."),
        });
        return null;
      }
      return p.values;
    }
    const r = valuesFromFields(fields);
    if (!r.ok) {
      setError({ text: r.reason, field: r.field });
      return null;
    }
    return r.values;
  };

  const save = async () => {
    if (busy) return;
    const values = collect();
    if (values === null) return;
    setError(null);
    setBusy(true);
    try {
      await saveValues({
        path: name,
        values,
        currentVersion: current.version,
        groupKey: current.groupKey,
        keyVersion: current.keyVersion,
      });
      navigate(secretHref(name));
    } catch (err) {
      setBusy(false);
      if (isConflict(err)) onConflict();
      else
        setError({
          text: t(
            "We couldn't save. Check your connection and try again. Nothing was changed.",
            "Kami tidak bisa menyimpan. Periksa koneksi lalu coba lagi. Tidak ada yang berubah.",
          ),
        });
    }
  };

  const jsonCount = tab === "json" ? parseJsonValues(json) : null;

  return (
    <>
      <div class="top">
        <div>
          <PageTitle crumbs={pageCrumbs("secretEdit", name)} />
          <p class="sub">
            {tab === "fields"
              ? t(
                  "Change items one by one. Prefer to edit everything at once? Use the JSON tab. Both tabs change the same data.",
                  "Ubah satu per satu. Mau edit sekaligus? Pakai tab JSON. Kedua tab mengubah data yang sama.",
                )
              : t(
                  "Edit everything at once as JSON. Switch back to Fields any time. Both tabs change the same data.",
                  "Edit semuanya sekaligus sebagai JSON. Kembali ke Kolom kapan saja. Kedua tab mengubah data yang sama.",
                )}
          </p>
        </div>
        <div class="row-actions">
          <Link
            class="btn ghost"
            href={PATHS.secretsImport}
            onClick={() => setImportHint({ mode: "existing", path: name })}
          >
            {t("Import .env", "Impor .env")}
          </Link>
          <Link class="btn ghost" href={secretHref(name)}>
            {t("Cancel", "Batal")}
          </Link>
          <button type="button" class="btn" onClick={save} disabled={busy}>
            {t(
              `Save as version ${current.version + 1}`,
              `Simpan sebagai versi ${current.version + 1}`,
            )}
          </button>
        </div>
      </div>

      <div class="seg" role="tablist" aria-label={t("Edit view", "Tampilan edit")}>
        <button
          type="button"
          role="tab"
          aria-selected={tab === "fields"}
          class={tab === "fields" ? "on" : ""}
          onClick={() => switchTo("fields")}
        >
          {t("Fields", "Kolom")}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === "json"}
          class={tab === "json" ? "on" : ""}
          onClick={() => switchTo("json")}
        >
          {t("JSON", "JSON")}
        </button>
      </div>

      {error && (
        <div class="field-error" role="alert">
          <span aria-hidden="true">⚠</span>
          <span>{error.text}</span>
        </div>
      )}

      {tab === "fields" ? (
        <div class="card fields-card">
          <div class="field-row head" aria-hidden="true">
            <span class="grow">{t("Name", "Nama")}</span>
            <span class="type">{t("Type", "Tipe")}</span>
            <span class="grow">{t("Value", "Nilai")}</span>
            <span class="remove-slot" />
          </div>
          {fields.map((f) => (
            <FieldRow
              key={f.id}
              field={f}
              invalid={error?.field === f.id}
              onChange={(patch) => updateField(f.id, patch)}
              onRemove={() => setFields((rows) => rows.filter((r) => r.id !== f.id))}
            />
          ))}
          <div class="add-row">
            <button
              type="button"
              class="btn ghost"
              onClick={() =>
                setFields((rows) => [...rows, { id: nextId(), name: "", type: "text", value: "" }])
              }
            >
              {t("+ Add item", "+ Tambah item")}
            </button>
          </div>
        </div>
      ) : (
        <div class="card json-card">
          <div class="json-head">
            <h2>{t("JSON view", "Tampilan JSON")}</h2>
            {jsonCount?.ok ? (
              <Pill tone="ok">
                {t(
                  `Valid · ${Object.keys(jsonCount.values).length} items`,
                  `Valid · ${Object.keys(jsonCount.values).length} item`,
                )}
              </Pill>
            ) : (
              <Pill tone="bad">{t("Not valid", "Tidak valid")}</Pill>
            )}
          </div>
          <label class="visually-hidden" for="json-text">
            {t("JSON view", "Tampilan JSON")}
          </label>
          <textarea
            id="json-text"
            class="json-text"
            spellcheck={false}
            value={json}
            onInput={(e) => setJson(e.currentTarget.value)}
            rows={12}
          />
          <div class="legend">
            <span>
              <b>true</b> / <b>false</b>{" "}
              {t("are real true/false values", "adalah nilai benar/salah sungguhan")}
            </span>
            <span>
              <b>20</b> {t("is a number", "adalah angka")}
            </span>
            <span>
              <b>"text"</b> {t("is text", "adalah teks")}
            </span>
          </div>
          <p class="note">
            {t(
              "True, false and numbers keep their type, so your app reads them as real booleans and numbers, not text.",
              "Benar, salah, dan angka tetap bertipe, jadi aplikasimu membacanya sebagai boolean dan angka sungguhan, bukan teks.",
            )}
          </p>
        </div>
      )}

      <div class="info-box" role="note">
        <span>
          {t(
            "Everything is locked in your browser before it's saved. Saving creates a new version; the old one stays in the history.",
            "Semuanya dikunci di browsermu sebelum disimpan. Menyimpan membuat versi baru; yang lama tetap ada di riwayat.",
          )}
        </span>
      </div>
    </>
  );
}

function FieldRow({
  field,
  invalid,
  onChange,
  onRemove,
}: {
  field: Field;
  invalid: boolean;
  onChange: (patch: Partial<Field>) => void;
  onRemove: () => void;
}) {
  useLang();
  const isBool = field.type === "boolean";
  const onType = (next: ValueType) => {
    if (next === "boolean")
      onChange({ type: next, value: field.value === "true" ? "true" : "false" });
    else onChange({ type: next });
  };
  return (
    <div class={`field-row${invalid ? " invalid" : ""}`}>
      <input
        class="in grow"
        aria-label={t("Name", "Nama")}
        value={field.name}
        autocomplete="off"
        spellcheck={false}
        onInput={(e) => onChange({ name: e.currentTarget.value })}
      />
      <select
        class="type"
        value={field.type}
        onChange={(e) => onType(e.currentTarget.value as ValueType)}
        aria-label={t("Type", "Tipe")}
      >
        {(["text", "boolean", "number"] as const).map((k) => (
          <option key={k} value={k}>
            {typeLabel(k)}
          </option>
        ))}
      </select>
      {isBool ? (
        <button
          type="button"
          class={`sw grow${field.value === "true" ? " on" : ""}`}
          role="switch"
          aria-checked={field.value === "true"}
          aria-label={field.name || t("Value", "Nilai")}
          onClick={() => onChange({ value: field.value === "true" ? "false" : "true" })}
        >
          <i aria-hidden="true" />
          <span>{field.value === "true" ? "true" : "false"}</span>
        </button>
      ) : (
        <input
          class="in grow"
          aria-label={`${field.name || t("Value", "Nilai")} ${t("value", "nilai")}`}
          aria-invalid={invalid ? "true" : undefined}
          value={field.value}
          autocomplete="off"
          spellcheck={false}
          onInput={(e) => onChange({ value: e.currentTarget.value })}
        />
      )}
      <button
        type="button"
        class="x"
        aria-label={t("Remove item", "Hapus item")}
        onClick={onRemove}
      >
        ✕
      </button>
    </div>
  );
}
