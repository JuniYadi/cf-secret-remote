import { diffFingerprints, type Fingerprints, type Values } from "@cfs/core";
import { flag, flagAll, parseEnv } from "../args.ts";
import {
  CliError,
  type Client,
  connect,
  currentValues,
  readSecret,
  saveVersion,
} from "../client.ts";
import type { Commands } from "./types.ts";

// ADR 22. Parsing and merging run on the client. Values are never printed: previews show names only.

const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
export const MERGES = ["add", "overwrite", "replace"] as const;
export type Merge = (typeof MERGES)[number];

/** Reads .env (via parseEnv) or a flat JSON object. Booleans and numbers become their text. */
export function parseImport(text: string, format: "env" | "json"): Values {
  const raw = new Map<string, string>();
  if (format === "env") {
    for (const [k, v] of Object.entries(parseEnv(text))) raw.set(k, v);
  } else {
    let obj: unknown;
    try {
      obj = JSON.parse(text);
    } catch {
      throw new CliError("The JSON file is not valid JSON.");
    }
    if (typeof obj !== "object" || obj === null || Array.isArray(obj))
      throw new CliError('The JSON file must be one flat object: { "NAME": value }.');
    for (const [k, v] of Object.entries(obj)) {
      if (typeof v === "string") raw.set(k, v);
      else if (typeof v === "boolean" || (typeof v === "number" && Number.isFinite(v)))
        raw.set(k, String(v));
      else throw new CliError(`"${k}" must be a string, boolean or number.`);
    }
  }
  for (const k of raw.keys())
    if (!NAME_RE.test(k) || k === "__proto__") throw new CliError(`"${k}" is not a valid name.`);
  return Object.fromEntries(raw);
}

export interface MergeResult {
  result: Values;
  added: string[];
  changed: string[];
  unchanged: string[];
  /** add mode only: the name exists with another value, so the current value stays. */
  kept: string[];
  removed: string[];
}

/** add: only new names. overwrite: incoming wins, other names stay. replace: the result is exactly the incoming set. */
export function mergeValues(current: Values, incoming: Values, strategy: Merge): MergeResult {
  const inNames = Object.keys(incoming).sort();
  const out: MergeResult = {
    result: {},
    added: [],
    changed: [],
    unchanged: [],
    kept: [],
    removed: [],
  };
  for (const n of inNames) {
    if (!Object.hasOwn(current, n)) out.added.push(n);
    else if (current[n] === incoming[n]) out.unchanged.push(n);
    else if (strategy === "add") out.kept.push(n);
    else out.changed.push(n);
  }
  if (strategy === "replace") {
    out.removed = Object.keys(current)
      .sort()
      .filter((n) => !Object.hasOwn(incoming, n));
    out.result = Object.fromEntries(inNames.map((n) => [n, incoming[n] as string]));
  } else {
    const merged = new Map(Object.entries(current));
    for (const n of inNames)
      if (!merged.has(n) || strategy === "overwrite") merged.set(n, incoming[n] as string);
    out.result = Object.fromEntries(merged);
  }
  return out;
}

const fmtDate = (s: number) => new Date(s * 1000).toISOString().slice(0, 16).replace("T", " ");
const takeFlag = (a: string[], name: string): boolean => {
  const i = a.indexOf(name);
  if (i < 0) return false;
  a.splice(i, 1);
  return true;
};
const usage = (text: string) => new CliError(`Usage: ${text}`);

interface VersionRow {
  version: number;
  names: string[];
  fps: Fingerprints | null;
  createdAt: number;
  createdBy: string;
}

async function listVersions(c: Client, path: string): Promise<VersionRow[]> {
  const r = await c.call<VersionRow[]>("GET", `/secret/versions?path=${encodeURIComponent(path)}`);
  if (r.status === 403)
    throw new CliError(`Not allowed: versions of ${path}. Ask an admin for access.`);
  if (r.status === 404) throw new CliError(`No secret at "${path}".`);
  if (r.status !== 200) throw new CliError(`Could not list versions of ${path}.`);
  return r.body;
}

/** Preview lines. Names and counts only: a preview never shows a value. */
export function previewLines(m: MergeResult): string[] {
  const lines: string[] = [];
  for (const n of m.added) lines.push(`  + ${n}`);
  for (const n of m.changed) lines.push(`  ~ ${n}`);
  for (const n of m.removed) lines.push(`  - ${n}`);
  for (const n of m.kept) lines.push(`  = ${n}  (exists; add mode keeps the current value)`);
  const kept = m.kept.length ? `, ${m.kept.length} kept` : "";
  lines.push(
    `${m.added.length} added, ${m.changed.length} changed, ${m.removed.length} removed, ${m.unchanged.length} unchanged${kept}. Values are not shown.`,
  );
  return lines;
}

const META_FLAGS = { description: "description", owner: "owner", "rotate-by": "rotateBy" } as const;

export const versions: Commands = {
  versions: {
    help: "cfs versions <secret>                   versions, who wrote them, names only",
    run: async (a, h) => {
      const [path] = a;
      if (!path) throw usage("cfs versions <secret>");
      const list = await listVersions(await connect(h), path);
      if (!list.length) return console.log(`No versions of ${path}.`);
      for (const v of list)
        console.log(
          `v${v.version}  ${fmtDate(v.createdAt)}  ${v.createdBy}  ${v.names.join(", ")}`,
        );
    },
  },
  diff: {
    help: "cfs diff <secret> [<from> <to>]        names added, changed, removed (no values)",
    run: async (a, h) => {
      const [path, fromArg, toArg] = a;
      if (!path || (fromArg === undefined) !== (toArg === undefined))
        throw usage("cfs diff <secret> [<from> <to>]");
      const c = await connect(h);
      const list = await listVersions(c, path);
      const to = toArg === undefined ? list[0]?.version : Number(toArg);
      const from = fromArg === undefined ? list[1]?.version : Number(fromArg);
      if (!Number.isInteger(to) || !Number.isInteger(from))
        throw new CliError("Versions must be whole numbers, for example: cfs diff pay/prod 2 3");
      const fv = list.find((v) => v.version === from);
      const tv = list.find((v) => v.version === to);
      if (!fv || !tv) throw new CliError(`${path} has no such version to compare.`);
      if (!fv.fps || !tv.fps)
        throw new CliError(
          `v${fv.fps ? to : from} was written before fingerprints existed, so it cannot be compared.`,
        );
      const d = diffFingerprints(fv.fps, tv.fps);
      console.log(`Changes in ${path} from v${from} to v${to}:`);
      if (!d.added.length && !d.changed.length && !d.removed.length)
        return console.log("  No name changes.");
      for (const n of d.added) console.log(`  added    ${n}`);
      for (const n of d.changed) console.log(`  changed  ${n}`);
      for (const n of d.removed) console.log(`  removed  ${n}`);
    },
  },
  restore: {
    help: "cfs restore <secret> <version> [--yes]  writes an old version back as a new version",
    run: async (a, h) => {
      const yes = takeFlag(a, "--yes");
      const [path, v] = a;
      const n = Number(v);
      if (!path || !Number.isInteger(n) || n < 1)
        throw usage("cfs restore <secret> <version> [--yes]");
      const c = await connect(h);
      const old = await readSecret(c, path, n);
      const cur = await currentValues(c, path);
      const m = mergeValues(cur.values, old.values, "replace");
      console.log(
        `Restoring ${path} to v${n}: ${m.added.length} added, ${m.changed.length} changed, ${m.removed.length} removed.`,
      );
      console.log(
        "Warning: old values may have leaked. Restoring brings them back. If they were exposed, rotate them at the source.",
      );
      if (!yes) return console.log("Preview only. Run again with --yes to restore.");
      if (!m.added.length && !m.changed.length && !m.removed.length)
        return console.log(`${path} already matches v${n}. Nothing saved.`);
      const nv = await saveVersion(c, path, () => old.values);
      console.log(`Restored v${n} of ${path} as version ${nv}.`);
    },
  },
  "restore-delete": {
    help: "cfs restore-delete <secret>             restore a recently deleted secret (admin)",
    run: async (a, h) => {
      if (a.length !== 1 || !a[0]) throw usage("cfs restore-delete <secret>");
      const path = a[0];
      const c = await connect(h);
      await restoreDeleted(c, path);
      console.log(`Restored deleted secret ${path}.`);
    },
  },
  import: {
    help: "cfs import <secret> <file> [--format env|json] [--merge add|overwrite|replace] [--yes]",
    run: async (a, h) => {
      const yes = takeFlag(a, "--yes");
      const formatFlag = flag(a, "--format");
      const merge = (flag(a, "--merge") ?? "add") as Merge;
      const [path, file] = a;
      if (!path || !file)
        throw usage(
          "cfs import <secret> <file> [--format env|json] [--merge add|overwrite|replace] [--yes]",
        );
      if (!(MERGES as readonly string[]).includes(merge))
        throw new CliError("--merge must be add, overwrite or replace.");
      const format = formatFlag ?? (file.toLowerCase().endsWith(".json") ? "json" : "env");
      if (format !== "env" && format !== "json")
        throw new CliError("--format must be env or json.");
      let text: string;
      try {
        text = await Bun.file(file).text();
      } catch {
        throw new CliError(`Cannot read ${file}.`);
      }
      const incoming = parseImport(text, format);
      if (!Object.keys(incoming).length) throw new CliError("No values found in the file.");
      const c = await connect(h);
      const cur = await currentValues(c, path);
      const m = mergeValues(cur.values, incoming, merge);
      for (const line of previewLines(m)) console.log(line);
      const changes = m.added.length + m.changed.length + m.removed.length;
      if (!changes) return console.log("Nothing to change.");
      if (!yes) return console.log("Preview only. Run again with --yes to save.");
      const v = await saveVersion(
        c,
        path,
        (current) => mergeValues(current, incoming, merge).result,
      );
      console.log(`Saved ${path} as version ${v}.`);
    },
  },
  meta: {
    help: "cfs meta <secret> [--description T] [--owner NAME] [--rotate-by DATE] [--clear FIELD]",
    run: async (a, h) => {
      const path = a.shift();
      if (!path)
        throw usage("cfs meta <secret> [--description T] [--owner NAME] [--rotate-by YYYY-MM-DD]");
      const c = await connect(h);
      const patch: Record<string, string | null> = {};
      for (const [flagName, key] of Object.entries(META_FLAGS)) {
        const value = flag(a, `--${flagName}`);
        if (value !== undefined) patch[key] = value;
      }
      for (const f of flagAll(a, "--clear")) {
        const key = META_FLAGS[f as keyof typeof META_FLAGS];
        if (!key) throw new CliError("--clear takes description, owner or rotate-by.");
        patch[key] = null;
      }
      if (Object.keys(patch).length) {
        const r = await c.call<{ error?: string }>("PUT", "/secret/meta", { path, meta: patch });
        if (r.status !== 200)
          throw new CliError(r.body.error ?? `Could not save metadata for ${path}.`);
        return console.log(`Saved metadata for ${path}.`);
      }
      const r = await c.call<{ path: string; meta: Record<string, string> }[]>("GET", "/secrets");
      if (r.status !== 200) throw new CliError("Could not read metadata.");
      const row = r.body.find((s) => s.path === path);
      if (!row) throw new CliError(`No secret at "${path}", or you cannot list it.`);
      const { description, owner, rotateBy } = row.meta;
      if (!description && !owner && !rotateBy) return console.log("No metadata set.");
      if (description) console.log(`description  ${description}`);
      if (owner) console.log(`owner        ${owner}`);
      if (rotateBy) {
        const today = new Date().toISOString().slice(0, 10);
        console.log(`rotate by    ${rotateBy}${rotateBy < today ? "  (overdue)" : ""}`);
      }
    },
  },
};

export async function restoreDeleted(c: Client, path: string) {
  const r = await c.call<{ error?: string }>(
    "POST",
    `/secret/restore-delete?path=${encodeURIComponent(path)}`,
    {},
  );
  if (r.status !== 200)
    throw new CliError(`Could not restore ${path}: ${r.body?.error ?? `status ${r.status}`}`);
}
