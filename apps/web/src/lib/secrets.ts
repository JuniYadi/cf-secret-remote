// Pure logic for the secrets screens: parsers for .env and JSON, the typed JSON view, merge strategies,
// the version diff view model, and list helpers. No crypto here except the fingerprint diff from @cfs/core,
// and nothing in this file touches the network or storage. Covered by secrets.test.ts.

import { diffFingerprints, type FingerprintDiff, type Fingerprints, type Values } from "@cfs/core";
import type { Meta, SecretSummary } from "./api.ts";
import { t } from "./i18n.ts";

/** Same rule as the API (apps/api/src/limits.ts NAME_RE): a key name is an identifier. */
export const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

/** Same rule as the API (apps/api/src/policy.ts validPath): slash-separated segments, up to 200 chars. */
export const PATH_RE = /^[a-z0-9][a-z0-9._-]*(\/[a-z0-9][a-z0-9._-]*)*$/i;

export const validName = (name: string): boolean => NAME_RE.test(name);
export const validSecretPath = (path: string): boolean => path.length <= 200 && PATH_RE.test(path);

/** The group of a secret is its first path segment (the keyring prefix on the server). */
export const groupOf = (path: string): string => path.split("/")[0] ?? "";

export type ValueType = "text" | "boolean" | "number";

/**
 * How a stored string is shown. "true"/"false" are booleans. A number only counts when its text is the
 * canonical form of the number, so "007" or "1e3" stay text and the JSON round trip never changes a value.
 */
export function typeOf(value: string): ValueType {
  if (value === "true" || value === "false") return "boolean";
  const n = Number(value);
  if (value !== "" && value.trim() === value && Number.isFinite(n) && String(n) === value) {
    return "number";
  }
  return "text";
}

// --- .env ---

export interface EnvParse {
  values: Values;
  /** Names that had an empty value. They are skipped on import. */
  empty: string[];
  /** Lines that could not be read, with the line number. */
  errors: { line: number; reason: string }[];
}

/**
 * Reads KEY=value lines. Supports comments (#), an optional `export `, double or single quotes, the
 * escapes \n \t \r \" \\ inside double quotes, and a trailing comment after an unquoted value.
 * A duplicate name keeps its last value, as dotenv does.
 */
export function parseEnv(text: string): EnvParse {
  const values: Values = {};
  const empty: string[] = [];
  const errors: { line: number; reason: string }[] = [];
  const lines = text.split(/\r?\n/);
  lines.forEach((raw, index) => {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) return;
    const body = line.replace(/^export\s+/, "");
    const m = body.match(/^([^=\s]+)\s*=(.*)$/);
    if (!m) {
      errors.push({ line: index + 1, reason: "not KEY=value" });
      return;
    }
    const name = m[1] as string;
    const parsed = parseEnvValue(m[2] as string);
    if (parsed === null) {
      errors.push({ line: index + 1, reason: "unclosed quote" });
      return;
    }
    if (parsed === "") {
      empty.push(name);
      delete values[name];
      return;
    }
    values[name] = parsed;
    const emptyAt = empty.indexOf(name);
    if (emptyAt >= 0) empty.splice(emptyAt, 1);
  });
  return { values, empty, errors };
}

/** The value part of a KEY=value line. Returns null for an unclosed quote. */
function parseEnvValue(rest: string): string | null {
  const v = rest.trimStart();
  const quote = v.charAt(0);
  if (quote === '"' || quote === "'") {
    let out = "";
    for (let i = 1; i < v.length; i++) {
      const ch = v.charAt(i);
      if (ch === quote) return out;
      if (quote === '"' && ch === "\\" && i + 1 < v.length) {
        const next = v.charAt(i + 1);
        const map: Record<string, string> = { n: "\n", t: "\t", r: "\r", '"': '"', "\\": "\\" };
        out += map[next] ?? next;
        i++;
        continue;
      }
      out += ch;
    }
    return null;
  }
  return v.replace(/\s+#.*$/, "").trim();
}

/** Writes values as .env lines. Values that need it are double quoted, so parseEnv reads them back. */
export function toEnvText(values: Values): string {
  return Object.entries(values)
    .map(
      ([name, value]) =>
        `${name}=${/^[A-Za-z0-9_./:@+%,-]*$/.test(value) ? value : JSON.stringify(value)}`,
    )
    .join("\n");
}

// --- JSON ---

export type JsonParse = { ok: true; values: Values } | { ok: false; reason: string };

/**
 * Reads a flat JSON object. Strings stay as they are. true/false and numbers become their text, which is
 * how they are stored (ADR 22). Nested objects, arrays and null are refused.
 */
export function parseJsonValues(text: string): JsonParse {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    return { ok: false, reason: t("This is not valid JSON.", "Ini bukan JSON yang valid.") };
  }
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    return {
      ok: false,
      reason: t("The top level must be an object.", "Level teratas harus objek."),
    };
  }
  const values: Values = {};
  for (const [name, value] of Object.entries(data)) {
    if (typeof value === "string") values[name] = value;
    else if (typeof value === "boolean") values[name] = value ? "true" : "false";
    else if (typeof value === "number" && Number.isFinite(value)) values[name] = String(value);
    else {
      return {
        ok: false,
        reason: t(
          `${name} must be a string, number or boolean.`,
          `${name} harus berupa teks, angka, atau benar/salah.`,
        ),
      };
    }
  }
  return { ok: true, values };
}

/**
 * The JSON tab text. Booleans and canonical numbers are written without quotes, text is quoted.
 * Round trip: parseJsonValues(toJsonText(v)) gives back v exactly.
 */
export function toJsonText(values: Values): string {
  const entries = Object.entries(values).map(
    ([name, value]) =>
      `  ${JSON.stringify(name)}: ${typeOf(value) === "text" ? JSON.stringify(value) : value}`,
  );
  return entries.length === 0 ? "{}" : `{\n${entries.join(",\n")}\n}`;
}

/** Reads a pasted or uploaded file: JSON if it looks like an object, otherwise .env. */
export function parseImportText(
  text: string,
):
  | { source: "json" | "env"; values: Values; empty: string[]; errors: string[] }
  | { source: "json"; error: string } {
  if (text.trim().startsWith("{")) {
    const parsed = parseJsonValues(text);
    if (!parsed.ok) return { source: "json", error: parsed.reason };
    const empty = Object.keys(parsed.values).filter((k) => parsed.values[k] === "");
    const values = Object.fromEntries(Object.entries(parsed.values).filter(([, v]) => v !== ""));
    return { source: "json", values, empty, errors: [] };
  }
  const env = parseEnv(text);
  return {
    source: "env",
    values: env.values,
    empty: env.empty,
    errors: env.errors.map((e) => t(`Line ${e.line}: ${e.reason}`, `Baris ${e.line}: ${e.reason}`)),
  };
}

// --- Merge ---

export type MergeStrategy = "add" | "overwrite" | "replace";
export const MERGE_STRATEGIES: readonly MergeStrategy[] = ["add", "overwrite", "replace"];

/** "skipped" (empty value) and "invalid" (bad name) are not merged. The review lists them with the rest. */
export type MergeStatus = "new" | "same" | "replaced" | "kept" | "removed" | "skipped" | "invalid";

export interface MergeRow {
  name: string;
  status: MergeStatus;
}

export interface MergeResult {
  /** The values that will be sealed as the next version. */
  result: Values;
  rows: MergeRow[];
}

/**
 * Applies an import to the current values.
 * add: only names that are not there yet. An existing name keeps its value ("kept").
 * overwrite: names in the import replace their values, every other current name stays.
 * replace: the result is exactly the import; current names missing from it are "removed".
 */
export function mergeValues(
  current: Values,
  incoming: Values,
  strategy: MergeStrategy,
): MergeResult {
  const result: Values = strategy === "replace" ? {} : { ...current };
  const rows: MergeRow[] = [];
  for (const [name, value] of Object.entries(incoming)) {
    const has = Object.hasOwn(current, name);
    if (!has) {
      result[name] = value;
      rows.push({ name, status: "new" });
      continue;
    }
    if (strategy === "add") {
      rows.push({ name, status: current[name] === value ? "same" : "kept" });
      continue;
    }
    result[name] = value;
    rows.push({ name, status: current[name] === value ? "same" : "replaced" });
  }
  if (strategy === "replace") {
    for (const name of Object.keys(current)) {
      if (!Object.hasOwn(incoming, name)) rows.push({ name, status: "removed" });
    }
  }
  return { result, rows };
}

// --- Diff between versions (names only) ---

export type DiffKind = "added" | "changed" | "removed" | "same";

export interface DiffRow {
  name: string;
  kind: DiffKind;
}

/**
 * The name-level diff between two versions, from their fingerprints (ADR 22). `from` is the older version.
 * Null when either version has no fingerprints (written before fingerprints existed), so the UI can say so.
 */
export function diffRows(
  from: Fingerprints | null | undefined,
  to: Fingerprints | null | undefined,
): DiffRow[] | null {
  if (!from || !to) return null;
  const d: FingerprintDiff = diffFingerprints(from, to);
  const same = Object.keys(to)
    .filter((n) => Object.hasOwn(from, n) && from[n] === to[n])
    .map((name) => ({ name, kind: "same" as const }));
  const rows: DiffRow[] = [
    ...d.added.map((name) => ({ name, kind: "added" as const })),
    ...d.changed.map((name) => ({ name, kind: "changed" as const })),
    ...d.removed.map((name) => ({ name, kind: "removed" as const })),
    ...same,
  ];
  return rows.sort((a, b) => a.name.localeCompare(b.name));
}

// --- Lists ---

export interface ListFilter {
  /** Free text, matched against the path, case-insensitively. */
  query?: string;
  /** Only this group (first path segment). */
  group?: string | null;
}

export function filterSecrets(list: readonly SecretSummary[], filter: ListFilter): SecretSummary[] {
  const q = (filter.query ?? "").trim().toLowerCase();
  return list.filter(
    (s) =>
      (!filter.group || groupOf(s.path) === filter.group) &&
      (q === "" || s.path.toLowerCase().includes(q)),
  );
}

/** Groups with their secret counts, sorted by name. */
export function groupCounts(list: readonly SecretSummary[]): { group: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const s of list) counts.set(groupOf(s.path), (counts.get(groupOf(s.path)) ?? 0) + 1);
  return [...counts.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([group, count]) => ({ group, count }));
}

/** Today's date as YYYY-MM-DD (UTC), the format of rotateBy. */
export const todayIso = (now: number = Date.now()): string =>
  new Date(now).toISOString().slice(0, 10);

/** "overdue" when rotateBy is before today, "due" when set and not yet passed, null when unset. */
export function rotationStatus(meta: Meta, today: string): "overdue" | "due" | null {
  if (!meta.rotateBy) return null;
  return meta.rotateBy < today ? "overdue" : "due";
}

/** Relative time for a server timestamp in epoch seconds, such as "2 hours ago" or "2 jam lalu". */
export function relativeTime(epochSeconds: number, nowMs: number, lang: "en" | "id"): string {
  const diff = epochSeconds - nowMs / 1000;
  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ["year", 31_536_000],
    ["month", 2_592_000],
    ["week", 604_800],
    ["day", 86_400],
    ["hour", 3_600],
    ["minute", 60],
  ];
  const rtf = new Intl.RelativeTimeFormat(lang === "id" ? "id" : "en", { numeric: "auto" });
  for (const [unit, seconds] of units) {
    if (Math.abs(diff) >= seconds) return rtf.format(Math.round(diff / seconds), unit);
  }
  return rtf.format(0, "second");
}

/** Keys of the values object, with the value kinds, for the Fields tab. */
export interface Field {
  id: number;
  name: string;
  type: ValueType;
  value: string;
}

export function fieldsFromValues(values: Values): Field[] {
  return Object.entries(values).map(([name, value], i) => ({
    id: i + 1,
    name,
    type: typeOf(value),
    value,
  }));
}

/** Turns the Fields tab back into values. Returns the first problem, or the values. */
export function valuesFromFields(
  fields: readonly Field[],
): { ok: true; values: Values } | { ok: false; field: number; reason: string } {
  const values: Values = {};
  for (const f of fields) {
    if (!validName(f.name)) {
      return {
        ok: false,
        field: f.id,
        reason: t("Use letters, numbers and _ only.", "Pakai huruf, angka, dan _ saja."),
      };
    }
    if (Object.hasOwn(values, f.name)) {
      return {
        ok: false,
        field: f.id,
        reason: t("This name is used twice.", "Nama ini dipakai dua kali."),
      };
    }
    if (f.type === "number" && typeOf(f.value) !== "number") {
      return { ok: false, field: f.id, reason: t("Not a number.", "Bukan angka.") };
    }
    if (f.type === "boolean" && f.value !== "true" && f.value !== "false") {
      return { ok: false, field: f.id, reason: t("True or false.", "Benar atau salah.") };
    }
    values[f.name] = f.value;
  }
  return { ok: true, values };
}
