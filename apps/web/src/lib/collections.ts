// ADR 36: environment collections. Pure helpers for the forms and the comparison view (unit tested in
// collections.test.ts). They handle names, labels and paths only; no value is read or written here.
import type {
  CollectionCompare,
  CollectionDiff,
  CollectionEnv,
  CollectionKey,
  CompareResult,
} from "./api.ts";
import { t } from "./i18n.ts";

export const COLLECTION_NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/i;
export const LABEL_RE = /^[a-z0-9][a-z0-9._-]{0,31}$/i;
export const KEY_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const PATH_RE = /^[a-z0-9][a-z0-9._-]*(\/[a-z0-9][a-z0-9._-]*)*$/i;
export const MAX_ENVS = 10;
export const MAX_KEYS = 300;
export const MAX_DESCRIPTION = 200;
export const MAX_PATH = 200;

export interface EnvRow {
  label: string;
  path: string;
}
export interface KeyRow {
  name: string;
  description: string;
}

export type FieldError = "empty" | "shape" | "tooLong" | "reserved";

export interface DraftErrors {
  name?: FieldError;
  envs: { label?: FieldError; path?: FieldError }[];
  keys: { name?: FieldError; description?: FieldError }[];
  noEnvs?: boolean;
  tooManyEnvs?: boolean;
  tooManyKeys?: boolean;
  duplicateLabels?: boolean;
  duplicatePaths?: boolean;
  duplicateKeys?: boolean;
}

const blankEnv = (r: EnvRow) => r.label.trim() === "" && r.path.trim() === "";
const blankKey = (r: KeyRow) => r.name.trim() === "" && r.description.trim() === "";

/** Blank rows are ignored, so an unused row never blocks the form. */
export function validateDraft(
  name: string,
  envs: EnvRow[],
  keys: KeyRow[],
  opts: { nameEditable?: boolean } = {},
): { valid: boolean; errors: DraftErrors } {
  const errors: DraftErrors = { envs: envs.map(() => ({})), keys: keys.map(() => ({})) };
  const trimmed = name.trim();
  if (opts.nameEditable !== false) {
    if (trimmed === "") errors.name = "empty";
    else if (trimmed === "new") errors.name = "reserved";
    else if (!COLLECTION_NAME_RE.test(trimmed)) errors.name = "shape";
  }

  const activeEnvs = envs.map((r, i) => ({ r, i })).filter(({ r }) => !blankEnv(r));
  if (activeEnvs.length === 0) errors.noEnvs = true;
  if (activeEnvs.length > MAX_ENVS) errors.tooManyEnvs = true;
  const labels = new Set<string>();
  const paths = new Set<string>();
  for (const { r, i } of activeEnvs) {
    const label = r.label.trim();
    const path = r.path.trim();
    if (label === "") errors.envs[i] = { ...errors.envs[i], label: "empty" };
    else if (!LABEL_RE.test(label)) errors.envs[i] = { ...errors.envs[i], label: "shape" };
    if (path === "") errors.envs[i] = { ...errors.envs[i], path: "empty" };
    else if (path.length > MAX_PATH) errors.envs[i] = { ...errors.envs[i], path: "tooLong" };
    else if (!PATH_RE.test(path)) errors.envs[i] = { ...errors.envs[i], path: "shape" };
    if (labels.has(label)) errors.duplicateLabels = true;
    if (paths.has(path)) errors.duplicatePaths = true;
    labels.add(label);
    paths.add(path);
  }

  const activeKeys = keys.map((r, i) => ({ r, i })).filter(({ r }) => !blankKey(r));
  if (activeKeys.length > MAX_KEYS) errors.tooManyKeys = true;
  const names = new Set<string>();
  for (const { r, i } of activeKeys) {
    const key = r.name.trim();
    if (key === "") errors.keys[i] = { ...errors.keys[i], name: "empty" };
    else if (!KEY_NAME_RE.test(key)) errors.keys[i] = { ...errors.keys[i], name: "shape" };
    if (r.description.trim().length > MAX_DESCRIPTION)
      errors.keys[i] = { ...errors.keys[i], description: "tooLong" };
    if (names.has(key)) errors.duplicateKeys = true;
    names.add(key);
  }

  const valid =
    errors.name === undefined &&
    !errors.noEnvs &&
    errors.tooManyEnvs !== true &&
    errors.tooManyKeys !== true &&
    errors.duplicateLabels !== true &&
    errors.duplicatePaths !== true &&
    errors.duplicateKeys !== true &&
    errors.envs.every((e) => e.label === undefined && e.path === undefined) &&
    errors.keys.every((k) => k.name === undefined && k.description === undefined);
  return { valid, errors };
}

/** The request body for the API: trimmed, blank rows dropped, an empty description sent as null. */
export function draftBody(
  envs: EnvRow[],
  keys: KeyRow[],
): { envs: CollectionEnv[]; keys: CollectionKey[] } {
  return {
    envs: envs
      .filter((r) => !blankEnv(r))
      .map((r) => ({ label: r.label.trim(), path: r.path.trim() })),
    keys: keys
      .filter((r) => !blankKey(r))
      .map((r) => ({
        name: r.name.trim(),
        description: r.description.trim() === "" ? null : r.description.trim(),
      })),
  };
}

/** Rows for the edit form, from a stored definition. */
export function rowsFrom(def: { envs: CollectionEnv[]; keys: CollectionKey[] }): {
  envs: EnvRow[];
  keys: KeyRow[];
} {
  return {
    envs: def.envs.map((e) => ({ label: e.label, path: e.path })),
    keys: def.keys.map((k) => ({ name: k.name, description: k.description ?? "" })),
  };
}

export function hasChanges(d: CollectionDiff): boolean {
  return (
    d.addedKeys.length +
      d.removedKeys.length +
      d.changedKeys.length +
      d.addedEnvs.length +
      d.removedEnvs.length +
      d.changedEnvs.length >
    0
  );
}

/** Removals the person must confirm. Removing a name never touches a stored value. */
export function removalsOf(d: CollectionDiff): { keys: string[]; envs: string[] } {
  return { keys: d.removedKeys, envs: d.removedEnvs };
}

/** Each name that is extra somewhere, with the environments that hold it, for the reconcile list. */
export function extraNames(cmp: CollectionCompare): { name: string; labels: string[] }[] {
  const found = new Map<string, string[]>();
  for (const e of cmp.envs) {
    for (const n of e.extra ?? []) found.set(n, [...(found.get(n) ?? []), e.label]);
  }
  return [...found.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, labels]) => ({ name, labels }));
}

export function resultLabel(result: CompareResult): string {
  switch (result) {
    case "clean":
      return t("Clean", "Sesuai");
    case "drift":
      return t("Drift", "Berbeda");
    case "incomplete":
      return t("Incomplete", "Belum lengkap");
  }
}

export function resultHelp(result: CompareResult): string {
  switch (result) {
    case "clean":
      return t(
        "Every environment was read and has every declared name, and no extra names.",
        "Setiap environment sudah dibaca dan memiliki semua nama yang dideklarasikan, tanpa nama tambahan.",
      );
    case "drift":
      return t(
        "Every environment was read. Some declared names are missing, or some names are not declared.",
        "Semua environment sudah dibaca. Ada nama yang dideklarasikan tapi belum ada, atau ada nama yang belum dideklarasikan.",
      );
    case "incomplete":
      return t(
        "Not every environment could be read, or a path does not exist. This is not a clean result.",
        "Tidak semua environment bisa dibaca, atau ada path yang tidak ada. Ini bukan hasil yang sesuai.",
      );
  }
}

export function resultTone(result: CompareResult): "ok" | "warn" | "bad" {
  return result === "clean" ? "ok" : result === "drift" ? "warn" : "bad";
}

export const collectionHref = (name: string) => `/collections/${encodeURIComponent(name)}`;
