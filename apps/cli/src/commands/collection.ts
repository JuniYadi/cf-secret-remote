// ADR 36: environment collections from the terminal. Names and paths only. No command here reads or writes a value.

import { flagAll } from "../args.ts";
import { CliError, connect } from "../client.ts";
import { confirm } from "../prompt.ts";
import type { Commands } from "./types.ts";

/** Exit codes for `compare`, so a script can tell the outcomes apart. */
export const EXIT = { clean: 0, drift: 1, incomplete: 2, error: 3 } as const;

const NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/i;
const LABEL = /^[a-z0-9][a-z0-9._-]{0,31}$/i;
const KEY = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const USAGE =
  "Usage: cfs collection <list|show|create|edit|compare|add-keys|delete> ... (see cfs collection --help)";

export interface Def {
  name: string;
  revision: number;
  envs: { label: string; path: string }[];
  keys: { name: string; description: string | null }[];
}

export interface Preview {
  name: string;
  exists: boolean;
  revision: number | null;
  changes: {
    addedKeys: string[];
    removedKeys: string[];
    changedKeys: string[];
    addedEnvs: string[];
    removedEnvs: string[];
    changedEnvs: string[];
  };
  envs: { label: string; path: string; status: "ok" | "missing_path" | "inaccessible" }[];
}

export interface Compare {
  name: string;
  revision: number;
  result: "clean" | "drift" | "incomplete";
  observedAt: number;
  envs: {
    label: string;
    path: string;
    status: "ok" | "missing_path" | "inaccessible";
    version?: number;
    present?: string[];
    missing?: string[];
    extra?: string[];
  }[];
}

/** Removes a boolean switch from the arguments. Returns whether it was present. */
function takeBool(args: string[], name: string): boolean {
  const i = args.indexOf(name);
  if (i < 0) return false;
  args.splice(i, 1);
  return true;
}

/** Takes the first positional argument as the collection name. */
function takeName(args: string[]): string {
  const name = args.shift() ?? "";
  if (!NAME.test(name)) throw new CliError(`Collection name is not valid. ${USAGE}`);
  return name;
}

/** `label=path`, split at the first `=`. */
export function parseEnvFlag(text: string): { label: string; path: string } {
  const i = text.indexOf("=");
  const label = i < 0 ? "" : text.slice(0, i);
  const path = i < 0 ? "" : text.slice(i + 1);
  if (!LABEL.test(label)) throw new CliError(`Environment label is not valid: ${label || text}`);
  if (path === "") throw new CliError(`Use --env ${label}=<secret path>`);
  return { label, path };
}

/** `NAME` or `NAME=description`. An empty description after `=` clears the description. */
export function parseKeyFlag(text: string): { name: string; description?: string | null } {
  const i = text.indexOf("=");
  const name = i < 0 ? text : text.slice(0, i);
  if (!KEY.test(name)) throw new CliError(`Key name is not valid: ${name}`);
  if (i < 0) return { name };
  const description = text.slice(i + 1).trim();
  return { name, description: description === "" ? null : description };
}

const LABELS = {
  ok: "ok",
  missing_path: "path does not exist",
  inaccessible: "no access",
} as const;

/** Lines for a definition change. Shows names and labels only. */
export function formatPreview(p: Preview): string[] {
  const c = p.changes;
  const lines = [
    p.exists ? `collection ${p.name} (revision ${p.revision})` : `new collection ${p.name}`,
    ...c.addedKeys.map((k) => `  + key ${k}`),
    ...c.removedKeys.map((k) => `  - key ${k} (removed from the declaration; values are kept)`),
    ...c.changedKeys.map((k) => `  ~ key ${k} (description)`),
    ...c.addedEnvs.map((l) => `  + env ${l}`),
    ...c.removedEnvs.map((l) => `  - env ${l} (values are kept)`),
    ...c.changedEnvs.map((l) => `  ~ env ${l} (path)`),
  ];
  if (lines.length === 1 && p.exists) lines.push("  no change to the declaration");
  for (const e of p.envs) lines.push(`  ${e.label} ${e.path}: ${LABELS[e.status]}`);
  return lines;
}

/** Lines for a comparison, then the result word. Missing and extra are listed per environment. */
export function formatCompare(r: Compare): string[] {
  const lines = [`collection ${r.name}, revision ${r.revision}`];
  for (const e of r.envs) {
    if (e.status !== "ok") {
      lines.push(`  ${e.label} ${e.path}: ${LABELS[e.status]}`);
      continue;
    }
    const parts = [`  ${e.label} ${e.path} (version ${e.version})`];
    if (e.missing?.length) parts.push(`missing: ${e.missing.join(", ")}`);
    if (e.extra?.length) parts.push(`extra: ${e.extra.join(", ")}`);
    if (!e.missing?.length && !e.extra?.length) parts.push("matches");
    lines.push(parts.join("  "));
  }
  lines.push(`result: ${r.result}`);
  return lines;
}

/** Applies flag edits to a definition. Keeps the existing description unless a new one is given. */
export function applyEdits(
  cur: Pick<Def, "envs" | "keys">,
  edits: {
    env: { label: string; path: string }[];
    removeEnv: string[];
    key: { name: string; description?: string | null }[];
    removeKey: string[];
  },
): Pick<Def, "envs" | "keys"> {
  const envs = new Map(cur.envs.map((e) => [e.label, e.path]));
  for (const e of edits.env) envs.set(e.label, e.path);
  for (const l of edits.removeEnv) envs.delete(l);
  const keys = new Map(cur.keys.map((k) => [k.name, k.description]));
  for (const k of edits.key) {
    keys.set(k.name, "description" in k ? (k.description ?? null) : (keys.get(k.name) ?? null));
  }
  for (const n of edits.removeKey) keys.delete(n);
  return {
    envs: [...envs].map(([label, path]) => ({ label, path })),
    keys: [...keys].map(([name, description]) => ({ name, description })),
  };
}

async function confirmed(yes: boolean, question: string): Promise<boolean> {
  return yes || (await confirm(question));
}

async function list(args: string[], hostFlag?: string): Promise<void> {
  const json = takeBool(args, "--json");
  const c = await connect(hostFlag);
  const r = await c.call<{ name: string; revision: number; envCount: number; keyCount: number }[]>(
    "GET",
    "/collections",
  );
  if (r.status !== 200) throw new CliError(`Could not list collections (status ${r.status}).`);
  if (json) return void console.log(JSON.stringify(r.body));
  if (r.body.length === 0) return void console.log("No collections you can read.");
  for (const x of r.body) {
    console.log(`${x.name}  revision ${x.revision}  ${x.envCount} envs  ${x.keyCount} keys`);
  }
}

async function show(args: string[], hostFlag?: string): Promise<void> {
  const json = takeBool(args, "--json");
  const name = takeName(args);
  const c = await connect(hostFlag);
  const r = await c.call<Def>("GET", `/collections/${encodeURIComponent(name)}`);
  if (r.status === 403) throw new CliError("Access denied to this collection.");
  if (r.status === 404) throw new CliError(`No collection named ${name}.`);
  if (r.status !== 200) throw new CliError(`Could not read the collection (status ${r.status}).`);
  if (json) return void console.log(JSON.stringify(r.body));
  console.log(`collection ${name}, revision ${r.body.revision}`);
  for (const e of r.body.envs) console.log(`  env ${e.label}  ${e.path}`);
  for (const k of r.body.keys)
    console.log(`  key ${k.name}${k.description ? `  ${k.description}` : ""}`);
}

async function create(args: string[], hostFlag?: string): Promise<void> {
  const yes = takeBool(args, "--yes");
  const dryRun = takeBool(args, "--dry-run");
  const name = takeName(args);
  const envs = flagAll(args, "--env").map(parseEnvFlag);
  let keys = flagAll(args, "--key").map(parseKeyFlag);
  const from = flagAll(args, "--from");
  if (envs.length === 0) throw new CliError("Give at least one --env label=path.");
  if (args.length) throw new CliError(`Unexpected arguments: ${args.join(" ")}`);
  const c = await connect(hostFlag);

  let sourceVersions: Record<string, number> | undefined;
  if (from.length) {
    const d = await c.call<{
      sources: { path: string; status: string; version?: number }[];
      union: string[];
    }>("POST", "/collections/discover", { paths: from });
    if (d.status === 403)
      throw new CliError("You cannot list one of these paths, so no union was built.");
    if (d.status !== 200) throw new CliError(`Could not read the paths (status ${d.status}).`);
    sourceVersions = Object.fromEntries(
      d.body.sources.flatMap((s) => (s.status === "ok" && s.version ? [[s.path, s.version]] : [])),
    );
    const have = new Set(keys.map((k) => k.name));
    keys = [...keys, ...d.body.union.filter((n) => !have.has(n)).map((name) => ({ name }))];
    console.log(`union of ${from.length} path(s): ${d.body.union.join(", ") || "(no names)"}`);
  }

  const body = { name, envs, keys };
  const p = await c.call<Preview>("POST", "/collections/preview", body);
  if (p.status === 403) throw new CliError("You cannot create this collection.");
  if (p.status !== 200) throw new CliError(`Could not preview (status ${p.status}).`);
  for (const line of formatPreview(p.body)) console.log(line);
  if (dryRun) return;
  if (!(await confirmed(yes, "Create this collection? y/N ")))
    return void console.log("Cancelled. Nothing was created.");
  const r = await c.call<{ code?: string; error?: string }>("POST", "/collections", {
    ...body,
    ...(sourceVersions ? { sourceVersions } : {}),
  });
  if (r.status === 201) return void console.log(`Created ${name} (revision 1).`);
  if (r.status === 409 && r.body.code === "name_exists")
    throw new CliError(`A collection named ${name} already exists.`);
  if (r.status === 409 && r.body.code === "source_changed")
    throw new CliError("A source path changed after the union was read. Run the command again.");
  throw new CliError(r.body.error ?? `Could not create the collection (status ${r.status}).`);
}

async function edit(args: string[], hostFlag?: string): Promise<void> {
  const yes = takeBool(args, "--yes");
  const dryRun = takeBool(args, "--dry-run");
  const name = takeName(args);
  const edits = {
    env: flagAll(args, "--env").map(parseEnvFlag),
    removeEnv: flagAll(args, "--remove-env"),
    key: flagAll(args, "--key").map(parseKeyFlag),
    removeKey: flagAll(args, "--remove-key"),
  };
  if (args.length) throw new CliError(`Unexpected arguments: ${args.join(" ")}`);
  const c = await connect(hostFlag);
  const cur = await c.call<Def>("GET", `/collections/${encodeURIComponent(name)}`);
  if (cur.status === 403) throw new CliError("Access denied to this collection.");
  if (cur.status === 404) throw new CliError(`No collection named ${name}.`);
  if (cur.status !== 200)
    throw new CliError(`Could not read the collection (status ${cur.status}).`);
  const next = applyEdits(cur.body, edits);
  const body = { name, envs: next.envs, keys: next.keys };
  const p = await c.call<Preview>("POST", "/collections/preview", body);
  if (p.status !== 200) throw new CliError(`Could not preview (status ${p.status}).`);
  const ch = p.body.changes;
  const changed =
    ch.addedKeys.length +
      ch.removedKeys.length +
      ch.changedKeys.length +
      ch.addedEnvs.length +
      ch.removedEnvs.length +
      ch.changedEnvs.length >
    0;
  for (const line of formatPreview(p.body)) console.log(line);
  if (!changed) return void console.log("Nothing to change.");
  if (dryRun) return;
  if (!(await confirmed(yes, "Apply these changes? y/N ")))
    return void console.log("Cancelled. Nothing was changed.");
  // The removals listed are the ones the preview showed, so removal is never implicit.
  const r = await c.call<{ code?: string; error?: string }>(
    "PUT",
    `/collections/${encodeURIComponent(name)}`,
    {
      revision: cur.body.revision,
      envs: next.envs,
      keys: next.keys,
      removed: { keys: ch.removedKeys, envs: ch.removedEnvs },
    },
  );
  if (r.status === 200) return void console.log(`Saved ${name}.`);
  if (r.status === 409)
    throw new CliError("The collection changed since you read it. Run the command again.");
  throw new CliError(r.body.error ?? `Could not save (status ${r.status}).`);
}

async function compareCmd(args: string[], hostFlag?: string): Promise<void> {
  const json = takeBool(args, "--json");
  let name = "";
  try {
    name = takeName(args);
    const c = await connect(hostFlag);
    const r = await c.call<Compare>("GET", `/collections/${encodeURIComponent(name)}/compare`);
    if (r.status === 403) throw new CliError("Access denied to this collection.");
    if (r.status === 404) throw new CliError(`No collection named ${name}.`);
    if (r.status !== 200) throw new CliError(`Could not compare (status ${r.status}).`);
    if (json) console.log(JSON.stringify(r.body));
    else for (const line of formatCompare(r.body)) console.log(line);
    process.exitCode = EXIT[r.body.result];
  } catch (e) {
    // A failed check is an error, not drift, so scripts never mistake it for one.
    const message = e instanceof Error ? e.message : String(e);
    if (json) console.log(JSON.stringify({ name, result: "error", error: message }));
    else console.error(message);
    process.exitCode = EXIT.error;
  }
}

async function addKeys(args: string[], hostFlag?: string): Promise<void> {
  const yes = takeBool(args, "--yes");
  const dryRun = takeBool(args, "--dry-run");
  const name = takeName(args);
  const names = [...args];
  if (names.length === 0) throw new CliError("Give the key names to add.");
  const c = await connect(hostFlag);
  const p = await c.call<{
    revision: number;
    names: { name: string; declared: boolean; observedIn: string[] }[];
    sourceVersions: Record<string, number>;
  }>("POST", `/collections/${encodeURIComponent(name)}/reconcile/preview`, { names });
  if (p.status === 403) throw new CliError("Access denied to this collection.");
  if (p.status === 404) throw new CliError(`No collection named ${name}.`);
  if (p.status !== 200) throw new CliError(`Could not preview (status ${p.status}).`);
  for (const n of p.body.names) {
    if (n.declared) throw new CliError(`${n.name} is already declared.`);
    if (n.observedIn.length === 0)
      throw new CliError(`${n.name} is not present in any environment you can read.`);
    console.log(`  + key ${n.name} (present in ${n.observedIn.join(", ")})`);
  }
  if (dryRun) return;
  if (!(await confirmed(yes, "Add these keys to the declaration? y/N ")))
    return void console.log("Cancelled. Nothing was changed. No environment values were written.");
  const r = await c.call<{ code?: string; error?: string }>(
    "POST",
    `/collections/${encodeURIComponent(name)}/reconcile`,
    { revision: p.body.revision, names, sourceVersions: p.body.sourceVersions },
  );
  if (r.status === 200)
    return void console.log(
      `Added ${names.length} key(s) to ${name}. No environment values were written.`,
    );
  if (r.status === 409)
    throw new CliError(
      "The collection or a source changed since the preview. Run the command again.",
    );
  throw new CliError(r.body.error ?? `Could not add keys (status ${r.status}).`);
}

async function remove(args: string[], hostFlag?: string): Promise<void> {
  const yes = takeBool(args, "--yes");
  const name = takeName(args);
  const c = await connect(hostFlag);
  const cur = await c.call<Def>("GET", `/collections/${encodeURIComponent(name)}`);
  if (cur.status === 403) throw new CliError("Access denied to this collection.");
  if (cur.status === 404) throw new CliError(`No collection named ${name}.`);
  if (cur.status !== 200)
    throw new CliError(`Could not read the collection (status ${cur.status}).`);
  console.log(`Delete the declaration ${name}. Environment values are kept.`);
  if (!(await confirmed(yes, "Delete it? y/N ")))
    return void console.log("Cancelled. Nothing was deleted.");
  const r = await c.call<{ error?: string }>(
    "DELETE",
    `/collections/${encodeURIComponent(name)}?revision=${cur.body.revision}`,
  );
  if (r.status === 200) return void console.log(`Deleted ${name}.`);
  if (r.status === 409)
    throw new CliError("The collection changed since you read it. Run the command again.");
  throw new CliError(r.body.error ?? `Could not delete (status ${r.status}).`);
}

export const collection: Commands = {
  collection: {
    help: "cfs collection <list|show|create|edit|compare|add-keys|delete>   (environment key names; ADR 36)",
    run: (a, hostFlag) => {
      const sub = a.shift();
      switch (sub) {
        case "list":
          return list(a, hostFlag);
        case "show":
          return show(a, hostFlag);
        case "create":
          return create(a, hostFlag);
        case "edit":
          return edit(a, hostFlag);
        case "compare":
          return compareCmd(a, hostFlag);
        case "add-keys":
          return addKeys(a, hostFlag);
        case "delete":
          return remove(a, hostFlag);
        default:
          throw new CliError(USAGE);
      }
    },
  },
};
