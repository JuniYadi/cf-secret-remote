// ADR 36: environment collections. Pure logic: validation, quotas, definition diffs and the comparison.
// Nothing here reads a value. Names come from the cleartext `names` of each mapped path.
import { isReservedCollectionName } from "@cfs/core";
import { NAME_RE } from "./limits.ts";
import { validPath } from "./policy.ts";

export const MAX_COLLECTIONS = 50;
export const MAX_ENVS = 10;
export const MAX_KEYS = 300;
export const MAX_DESCRIPTION = 200;
export const MAX_DISCOVER_PATHS = 10;
export const MAX_RECONCILE_NAMES = 50;

export const COLLECTION_NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/i;
export const LABEL_RE = /^[a-z0-9][a-z0-9._-]{0,31}$/i;

export interface EnvMap {
  label: string;
  path: string;
}
export interface KeyDecl {
  name: string;
  description: string | null;
}
export interface Definition {
  envs: EnvMap[];
  keys: KeyDecl[];
}

export const EMPTY_DEFINITION: Definition = { envs: [], keys: [] };

export const validCollectionName = (name: unknown): name is string =>
  typeof name === "string" && COLLECTION_NAME_RE.test(name) && !isReservedCollectionName(name);

/** Validates an environment list and a key list. Labels and paths are unique; names follow NAME_RE. */
export function parseDefinition(raw: {
  envs?: unknown;
  keys?: unknown;
}): { def: Definition } | { error: string } {
  if (!Array.isArray(raw.envs) || raw.envs.length === 0 || raw.envs.length > MAX_ENVS)
    return { error: `envs must list 1 to ${MAX_ENVS} environments` };
  const envs: EnvMap[] = [];
  for (const e of raw.envs) {
    if (typeof e !== "object" || e === null) return { error: "each env must be an object" };
    const { label, path } = e as { label?: unknown; path?: unknown };
    if (typeof label !== "string" || !LABEL_RE.test(label))
      return { error: "env label is not valid" };
    if (typeof path !== "string" || !validPath(path)) return { error: "env path is not valid" };
    envs.push({ label, path });
  }
  if (new Set(envs.map((e) => e.label)).size !== envs.length)
    return { error: "env labels must be unique" };
  if (new Set(envs.map((e) => e.path)).size !== envs.length)
    return { error: "env paths must be unique" };

  const rawKeys = raw.keys === undefined ? [] : raw.keys;
  if (!Array.isArray(rawKeys) || rawKeys.length > MAX_KEYS)
    return { error: `keys must list at most ${MAX_KEYS} names` };
  const keys: KeyDecl[] = [];
  for (const k of rawKeys) {
    if (typeof k !== "object" || k === null) return { error: "each key must be an object" };
    const { name, description } = k as { name?: unknown; description?: unknown };
    if (typeof name !== "string" || !NAME_RE.test(name)) return { error: "bad key name" };
    if (description !== undefined && description !== null && typeof description !== "string")
      return { error: "key description must be a string" };
    const text = typeof description === "string" ? description.trim() : "";
    if (text.length > MAX_DESCRIPTION) return { error: "key description is too long" };
    keys.push({ name, description: text === "" ? null : text });
  }
  if (new Set(keys.map((k) => k.name)).size !== keys.length)
    return { error: "key names must be unique" };
  return { def: { envs, keys } };
}

/** The removals a maintainer must confirm. An empty list is explicit: the server compares it with the real diff. */
export function parseRemovals(
  raw: unknown,
): { keys: string[]; envs: string[] } | { error: string } {
  if (raw === undefined) return { keys: [], envs: [] };
  if (typeof raw !== "object" || raw === null) return { error: "removed must be an object" };
  const { keys, envs } = raw as { keys?: unknown; envs?: unknown };
  const list = (v: unknown) =>
    v === undefined ? [] : Array.isArray(v) && v.every((x) => typeof x === "string") ? v : null;
  const k = list(keys);
  const e = list(envs);
  if (k === null || e === null) return { error: "removed.keys and removed.envs must be lists" };
  return { keys: [...k].sort(), envs: [...e].sort() };
}

export interface Diff {
  addedKeys: string[];
  removedKeys: string[];
  changedKeys: string[];
  addedEnvs: string[];
  removedEnvs: string[];
  changedEnvs: string[];
}

const sameList = (a: string[], b: string[]) =>
  a.length === b.length && a.every((x, i) => x === b[i]);

/** The exact changes between two definitions. Values never appear here, only names and labels. */
export function diffDefinition(before: Definition, after: Definition): Diff {
  const oldKeys = new Map(before.keys.map((k) => [k.name, k.description]));
  const newKeys = new Map(after.keys.map((k) => [k.name, k.description]));
  const oldEnvs = new Map(before.envs.map((e) => [e.label, e.path]));
  const newEnvs = new Map(after.envs.map((e) => [e.label, e.path]));
  const sorted = (xs: Iterable<string>) => [...xs].sort();
  return {
    addedKeys: sorted([...newKeys.keys()].filter((k) => !oldKeys.has(k))),
    removedKeys: sorted([...oldKeys.keys()].filter((k) => !newKeys.has(k))),
    changedKeys: sorted(
      [...newKeys.keys()].filter((k) => oldKeys.has(k) && oldKeys.get(k) !== newKeys.get(k)),
    ),
    addedEnvs: sorted([...newEnvs.keys()].filter((l) => !oldEnvs.has(l))),
    removedEnvs: sorted([...oldEnvs.keys()].filter((l) => !newEnvs.has(l))),
    changedEnvs: sorted(
      [...newEnvs.keys()].filter((l) => oldEnvs.has(l) && oldEnvs.get(l) !== newEnvs.get(l)),
    ),
  };
}

/** Removals in the diff must be listed exactly by the caller (ADR 36: removal is explicit). */
export function removalsConfirmed(diff: Diff, listed: { keys: string[]; envs: string[] }): boolean {
  return sameList(diff.removedKeys, listed.keys) && sameList(diff.removedEnvs, listed.envs);
}

/** What the server could observe for one mapped environment. Only the states that matter for the result. */
export type Observation =
  | { status: "inaccessible" }
  | { status: "missing_path" }
  | { status: "ok"; version: number; updatedAt: number; names: string[] };

export interface EnvCompare {
  label: string;
  path: string;
  status: "ok" | "missing_path" | "inaccessible";
  version?: number;
  updatedAt?: number;
  present?: string[];
  missing?: string[];
  extra?: string[];
}

/**
 * clean: every environment was read and matches the declaration.
 * drift: every environment was read, and some declared name is missing or some name is extra.
 * incomplete: at least one environment was not read (no access) or its path does not exist. This never means clean.
 */
export type CompareResult = "clean" | "drift" | "incomplete";

export function compareEnvs(
  declared: string[],
  envs: { label: string; path: string; observed: Observation }[],
): { result: CompareResult; envs: EnvCompare[] } {
  const want = new Set(declared);
  const out: EnvCompare[] = envs.map(({ label, path, observed }) => {
    if (observed.status !== "ok") return { label, path, status: observed.status };
    const have = new Set(observed.names);
    return {
      label,
      path,
      status: "ok",
      version: observed.version,
      updatedAt: observed.updatedAt,
      present: declared.filter((n) => have.has(n)).sort(),
      missing: declared.filter((n) => !have.has(n)).sort(),
      extra: [...have].filter((n) => !want.has(n)).sort(),
    };
  });
  if (out.some((e) => e.status !== "ok")) return { result: "incomplete", envs: out };
  const drift = out.some((e) => (e.missing?.length ?? 0) > 0 || (e.extra?.length ?? 0) > 0);
  return { result: drift ? "drift" : "clean", envs: out };
}

/** Names that are present in at least one readable environment but not declared. Sorted, unique. */
export function extraNames(
  declared: string[],
  envs: { label: string; observed: Observation }[],
): Map<string, string[]> {
  const want = new Set(declared);
  const found = new Map<string, string[]>();
  for (const { label, observed } of envs) {
    if (observed.status !== "ok") continue;
    for (const n of observed.names) {
      if (want.has(n)) continue;
      found.set(n, [...(found.get(n) ?? []), label]);
    }
  }
  return new Map([...found.entries()].sort(([a], [b]) => a.localeCompare(b)));
}

/** Reconcile apply: the paths whose versions the caller must have seen (one per environment that reported a name). */
export function requiredSources(
  observedIn: Map<string, string[]>,
  envPaths: Map<string, string>,
): string[] {
  const labels = new Set([...observedIn.values()].flat());
  return [...labels].map((l) => envPaths.get(l) as string).sort();
}
