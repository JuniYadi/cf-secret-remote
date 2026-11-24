// Permission sets: path globs and capabilities (ADR 5). Pure functions, unit tested (permissions.test.ts).
//
// The server's engine is default deny: a capability is granted when some rule lists it and its glob matches.
// There is no explicit deny rule, so a "Blocked" row would not stop a broader rule. The form therefore
// offers only grants. See DESIGN.md "Permissions" and the PR notes.

import type { Cap, CollectionCap, CollectionRule, PolicyRule, Rule } from "./api.ts";
import { t } from "./i18n.ts";

export const CAPS: readonly Cap[] = ["read", "update", "create", "delete", "list"];

/** The label the boards use for each capability. Index by the API name. */
export function capLabel(cap: Cap): string {
  switch (cap) {
    case "read":
      return t("View values", "Lihat nilai");
    case "update":
      return t("Edit", "Ubah");
    case "create":
      return t("Create", "Buat");
    case "delete":
      return t("Delete", "Hapus");
    case "list":
      return t("See names", "Lihat nama");
  }
}

/**
 * A glob is segments of letters, digits, dot, dash, underscore or `*`, joined by `/`.
 * `*` matches any characters, including `/` (server globMatch). A leading or trailing slash is refused.
 */
const GLOB_RE = /^[a-z0-9*][a-z0-9*._-]*(\/[a-z0-9*][a-z0-9*._-]*)*$/i;
export const MAX_GLOB = 200;

export type GlobError = "empty" | "tooLong" | "shape";

export function validateGlob(glob: string): GlobError | null {
  const value = glob.trim();
  if (value === "") return "empty";
  if (value.length > MAX_GLOB) return "tooLong";
  if (!GLOB_RE.test(value)) return "shape";
  return null;
}

export function globError(error: GlobError): string {
  switch (error) {
    case "empty":
      return t(
        "Write the folder or secret this applies to.",
        "Tulis folder atau secret yang dituju.",
      );
    case "tooLong":
      return t("That path is too long.", "Path itu terlalu panjang.");
    case "shape":
      return t(
        "Use letters, numbers, dots and dashes, separated by /. Use * for any part.",
        "Pakai huruf, angka, titik, dan tanda hubung, dipisah /. Pakai * untuk bagian apa pun.",
      );
  }
}

/** One row of the form. `caps` is what the person ticked. */
export interface RuleDraft {
  path: string;
  caps: Cap[];
}

export interface RuleDraftErrors {
  name?: "empty" | "tooLong";
  rules: { path?: GlobError; caps?: "none" }[];
  rulesEmpty?: boolean;
  /** Set when two rows have the same path, which would be ambiguous to read back. */
  duplicate?: boolean;
}

export const MAX_NAME = 80;

// ADR 36: collection rules. A collection rule is a name glob with view (read) or change (manage). It never
// grants a secret path, so it has its own rows and its own check.
export const COLLECTION_CAPS: readonly CollectionCap[] = ["read", "manage"];
export const COLLECTION_GLOB_RE = /^[a-z0-9*][a-z0-9*._-]{0,63}$/i;

export interface CollectionRuleDraft {
  collection: string;
  caps: CollectionCap[];
}

export function collectionCapLabel(cap: CollectionCap): string {
  return cap === "read"
    ? t("View collection", "Lihat koleksi")
    : t("Manage collection", "Kelola koleksi");
}

/** The message for a collection name pattern. Collections are named, not folders. */
export function collectionGlobError(error: GlobError): string {
  switch (error) {
    case "empty":
      return t("Write the collection name or a pattern.", "Tulis nama koleksi atau pola.");
    case "tooLong":
      return t("That name is too long.", "Nama itu terlalu panjang.");
    case "shape":
      return t(
        "Use letters, numbers, dots and dashes. Use * for any part, such as myapp*.",
        "Pakai huruf, angka, titik, dan tanda hubung. Pakai * untuk bagian apa pun, misalnya myapp*.",
      );
  }
}

export function validateCollectionGlob(glob: string): GlobError | null {
  const value = glob.trim();
  if (value === "") return "empty";
  if (value.length > MAX_GLOB) return "tooLong";
  if (!COLLECTION_GLOB_RE.test(value)) return "shape";
  return null;
}

const isBlankPath = (r: RuleDraft) => r.path.trim() === "" && r.caps.length === 0;
const isBlankCollection = (r: CollectionRuleDraft) =>
  r.collection.trim() === "" && r.caps.length === 0;

/**
 * Checks the whole form. Blank rows are ignored, so an unused row never blocks the form. `valid` is true only
 * when nothing is reported and at least one rule grants something.
 */
export function validatePermissionSet(
  name: string,
  rules: RuleDraft[],
  collections: CollectionRuleDraft[] = [],
): {
  valid: boolean;
  errors: RuleDraftErrors & { collections: { collection?: GlobError; caps?: "none" }[] };
} {
  const errors: RuleDraftErrors & { collections: { collection?: GlobError; caps?: "none" }[] } = {
    rules: rules.map(() => ({})),
    collections: collections.map(() => ({})),
  };
  const trimmed = name.trim();
  if (trimmed === "") errors.name = "empty";
  else if (trimmed.length > MAX_NAME) errors.name = "tooLong";

  const activePaths = rules.filter((r) => !isBlankPath(r)).length;
  const activeCollections = collections.filter((r) => !isBlankCollection(r)).length;
  if (activePaths + activeCollections === 0) errors.rulesEmpty = true;
  const seen = new Set<string>();
  rules.forEach((rule, i) => {
    if (isBlankPath(rule)) return;
    const row = errors.rules[i] ?? {};
    errors.rules[i] = row;
    const pathError = validateGlob(rule.path);
    if (pathError) row.path = pathError;
    if (rule.caps.length === 0) row.caps = "none";
    const key = rule.path.trim();
    if (key !== "" && seen.has(key)) errors.duplicate = true;
    seen.add(key);
  });
  collections.forEach((rule, i) => {
    if (isBlankCollection(rule)) return;
    const row = errors.collections[i] ?? {};
    errors.collections[i] = row;
    const globError = validateCollectionGlob(rule.collection);
    if (globError) row.collection = globError;
    if (rule.caps.length === 0) row.caps = "none";
  });
  const valid =
    errors.name === undefined &&
    !errors.rulesEmpty &&
    errors.duplicate !== true &&
    errors.rules.every((r) => r.path === undefined && r.caps === undefined) &&
    errors.collections.every((r) => r.collection === undefined && r.caps === undefined);
  return { valid, errors };
}

/** The rules as the API stores them: trimmed paths, capabilities in CAPS order. Blank rows are left out. */
export function toRules(drafts: RuleDraft[]): Rule[] {
  return drafts
    .filter((d) => !isBlankPath(d))
    .map((d) => ({
      path: d.path.trim(),
      caps: CAPS.filter((cap) => d.caps.includes(cap)),
    }));
}

/** ADR 36: collection rules as the API stores them. */
export function toCollectionRules(drafts: CollectionRuleDraft[]): CollectionRule[] {
  return drafts
    .filter((d) => !isBlankCollection(d))
    .map((d) => ({
      collection: d.collection.trim(),
      caps: COLLECTION_CAPS.filter((cap) => d.caps.includes(cap)),
    }));
}

const isCollectionRule = (r: PolicyRule): r is CollectionRule => "collection" in r;

/** Toggles one capability on a draft row, returning a new array (no mutation of the input). */
export function toggleCap(caps: Cap[], cap: Cap): Cap[] {
  return caps.includes(cap) ? caps.filter((c) => c !== cap) : [...caps, cap];
}

/**
 * Plain sentences for "What this allows": one line per rule that grants something.
 * Used by the preview on the forms and the permission list.
 */
export function describeRules(rules: PolicyRule[]): string[] {
  return rules
    .filter((r) => r.caps.length > 0)
    .map((r) => {
      if (isCollectionRule(r)) {
        const verbs = COLLECTION_CAPS.filter((c) => r.caps.includes(c)).map(collectionCapLabel);
        return `${verbs.join(", ")}: ${t("collections", "koleksi")} ${r.collection}`;
      }
      const verbs = CAPS.filter((c) => r.caps.includes(c)).map(capLabel);
      return `${verbs.join(", ")}: ${r.path}`;
    });
}

/** Pretty-printed rules for the Technical details block. Mirrors the boards' HCL-like text. */
export function rulesAsText(rules: PolicyRule[]): string {
  return rules
    .map((r) => {
      const caps = r.caps.map((c) => `"${c}"`).join(", ");
      return isCollectionRule(r)
        ? `collection "${r.collection}" {\n  capabilities = [${caps}]\n}`
        : `path "${r.path}" {\n  capabilities = [${caps}]\n}`;
    })
    .join("\n");
}
