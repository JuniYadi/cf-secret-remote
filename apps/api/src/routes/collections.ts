// ADR 36: environment collections. Each route checks the collection capability first, then the path list
// permission for every environment it reads. A denied caller gets the same 403 whether or not the name exists.
import { Hono } from "hono";
import { audit } from "../audit.ts";
import {
  compareEnvs,
  type Definition,
  diffDefinition,
  EMPTY_DEFINITION,
  type EnvMap,
  extraNames,
  MAX_COLLECTIONS,
  MAX_DISCOVER_PATHS,
  MAX_RECONCILE_NAMES,
  type Observation,
  parseDefinition,
  parseRemovals,
  removalsConfirmed,
  requiredSources,
  validCollectionName,
} from "../collections.ts";
import { NAME_RE } from "../limits.ts";
import {
  type CollectionCap,
  type CollectionRule,
  can,
  collectionCan,
  isCollectionRule,
  validPath,
} from "../policy.ts";
import * as repository from "../repository/collections.ts";
import * as secretRepository from "../repository/secrets.ts";
import type { AppEnv, Who } from "../types.ts";
import { newId, now } from "../util.ts";
import { rulesFor } from "./secrets.ts";

export const collections = new Hono<AppEnv>();

type Ctx = {
  env: { DB: D1Database };
  get: (k: "who") => Who;
  req: { header: (n: string) => string | undefined };
};

/** Collection rules from the caller's policies. Admins hold every collection capability, as they do for secrets. */
export async function collectionRulesFor(db: D1Database, who: Who): Promise<CollectionRule[]> {
  if (who.role === "admin") return [{ collection: "*", caps: ["read", "manage"] }];
  const rows = await secretRepository.policyRules(db, who.id, now());
  return rows.results.flatMap((r) => (JSON.parse(r.rules) as unknown[]).filter(isCollectionRule));
}

async function deny(c: Ctx, action: string, note: string): Promise<void> {
  const who = c.get("who");
  await audit(c.env.DB, {
    who: who.name,
    actor: who,
    action,
    result: "denied",
    note,
    ip: c.req.header("CF-Connecting-IP"),
  });
}

/** Checks a collection capability. A refusal is audited and looks the same for every name. */
async function allow(c: Ctx, name: string, cap: CollectionCap): Promise<boolean> {
  const ok = collectionCan(await collectionRulesFor(c.env.DB, c.get("who")), name, cap);
  if (!ok) await deny(c, `collection.${cap}`, name);
  return ok;
}

/** Reads each environment under the caller's secret list permission. Unlisted paths are never looked up. */
async function observe(
  c: Ctx,
  envs: EnvMap[],
): Promise<{ label: string; path: string; observed: Observation }[]> {
  const rules = await rulesFor(c.env.DB, c.get("who"));
  const listable = envs.filter((e) => can(rules, e.path, "list"));
  for (const e of envs) {
    if (!listable.includes(e)) await deny(c, "secret.list", e.path);
  }
  const rows = listable.length
    ? await repository.currentSecrets(
        c.env.DB,
        listable.map((e) => e.path),
      )
    : { results: [] };
  const byPath = new Map(rows.results.map((r) => [r.path, r]));
  return envs.map((e) => {
    if (!listable.includes(e)) return { ...e, observed: { status: "inaccessible" } };
    const row = byPath.get(e.path);
    if (!row) return { ...e, observed: { status: "missing_path" } };
    return {
      ...e,
      observed: {
        status: "ok",
        version: row.version,
        updatedAt: row.updatedAt,
        names: JSON.parse(row.names) as string[],
      },
    };
  });
}

async function loadDefinition(db: D1Database, name: string) {
  const row = await repository.findCollection(db, name);
  if (!row) return null;
  const [envs, keys] = await Promise.all([
    repository.collectionEnvs(db, row.id),
    repository.collectionKeys(db, row.id),
  ]);
  return {
    row,
    def: {
      envs: envs.results,
      keys: keys.results.map((k) => ({ name: k.name, description: k.description })),
    } as Definition,
  };
}

/** Only a uniqueness clash is a conflict. Any other D1 error propagates (quota errors become 503 in index.ts). */
async function onUnique<T>(p: Promise<T>, fallback: T): Promise<T> {
  return p.catch((e: unknown) => {
    if (/UNIQUE|constraint/i.test(String(e))) return fallback;
    throw e;
  });
}

const parseRevision = (v: unknown): number | null =>
  typeof v === "number" && Number.isInteger(v) && v >= 1 ? v : null;

/** sourceVersions: { path: version } for the secret versions the caller reviewed. */
function parseSourceVersions(raw: unknown, max: number): Record<string, number> | null {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null;
  const entries = Object.entries(raw);
  if (entries.length === 0 || entries.length > max) return null;
  for (const [path, v] of entries) {
    if (!validPath(path) || typeof v !== "number" || !Number.isInteger(v) || v < 1) return null;
  }
  return Object.fromEntries(entries) as Record<string, number>;
}

function parseNames(raw: unknown): string[] | null {
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > MAX_RECONCILE_NAMES) return null;
  if (!raw.every((n) => typeof n === "string" && NAME_RE.test(n))) return null;
  return raw.length === new Set(raw).size ? (raw as string[]) : null;
}

function diffNote(d: ReturnType<typeof diffDefinition>): string {
  const parts = [
    ...d.addedKeys.map((k) => `+key ${k}`),
    ...d.removedKeys.map((k) => `-key ${k}`),
    ...d.changedKeys.map((k) => `~key ${k}`),
    ...d.addedEnvs.map((l) => `+env ${l}`),
    ...d.removedEnvs.map((l) => `-env ${l}`),
    ...d.changedEnvs.map((l) => `~env ${l}`),
  ];
  return parts.length ? parts.join(", ") : "no change";
}

// List: the collections the caller may read. Names and counts only.
collections.get("/collections", async (c) => {
  const rules = await collectionRulesFor(c.env.DB, c.get("who"));
  const rows = await repository.listCollections(c.env.DB);
  return c.json(
    rows.results
      .filter((r) => collectionCan(rules, r.name, "read"))
      .map(({ name, revision, updatedAt, envCount, keyCount }) => ({
        name,
        revision,
        updatedAt,
        envCount,
        keyCount,
      })),
  );
});

// Discover: names at paths the caller can list, for initialising a collection from a reviewed union (ADR 36).
// No collection capability is needed: this only shows what the path list permission already shows.
collections.post("/collections/discover", async (c) => {
  const b = await c.req.json<{ paths?: unknown }>();
  const paths = b.paths;
  if (
    !Array.isArray(paths) ||
    paths.length === 0 ||
    paths.length > MAX_DISCOVER_PATHS ||
    !paths.every((p) => typeof p === "string" && validPath(p)) ||
    new Set(paths).size !== paths.length
  )
    return c.json({ error: "bad request" }, 400);
  const rules = await rulesFor(c.env.DB, c.get("who"));
  for (const p of paths as string[]) {
    if (!can(rules, p, "list")) {
      await deny(c, "secret.list", p);
      // Fail closed: one unreadable source refuses the whole union, and the message names no path.
      return c.json({ error: "denied" }, 403);
    }
  }
  const rows = await repository.currentSecrets(c.env.DB, paths as string[]);
  const byPath = new Map(rows.results.map((r) => [r.path, r]));
  const sources = (paths as string[]).map((path) => {
    const r = byPath.get(path);
    return r
      ? {
          path,
          status: "ok",
          version: r.version,
          updatedAt: r.updatedAt,
          names: JSON.parse(r.names) as string[],
        }
      : { path, status: "missing_path" };
  });
  const union = [...new Set(sources.flatMap((s) => ("names" in s ? s.names : [])))].sort();
  return c.json({ sources, union });
});

// Preview of a definition change. Shows exact additions, removals and the state of each new path. No values.
collections.post("/collections/preview", async (c) => {
  const b = await c.req.json<{ name?: unknown; envs?: unknown; keys?: unknown }>();
  if (!validCollectionName(b.name)) return c.json({ error: "bad collection name" }, 400);
  const parsed = parseDefinition(b);
  if ("error" in parsed) return c.json({ error: parsed.error }, 400);
  if (!(await allow(c, b.name, "manage"))) return c.json({ error: "denied" }, 403);
  const existing = await loadDefinition(c.env.DB, b.name);
  const diff = diffDefinition(existing?.def ?? EMPTY_DEFINITION, parsed.def);
  const envs = await observe(c, parsed.def.envs);
  return c.json({
    name: b.name,
    exists: existing !== null,
    revision: existing?.row.revision ?? null,
    changes: diff,
    envs: envs.map(({ label, path, observed }) => ({ label, path, status: observed.status })),
  });
});

// Create. A reviewed union of existing paths may be passed as sourceVersions; each must still be at that version.
collections.post("/collections", async (c) => {
  const b = await c.req.json<{
    name?: unknown;
    envs?: unknown;
    keys?: unknown;
    sourceVersions?: unknown;
  }>();
  if (!validCollectionName(b.name)) return c.json({ error: "bad collection name" }, 400);
  const parsed = parseDefinition(b);
  if ("error" in parsed) return c.json({ error: parsed.error }, 400);
  let sources: Record<string, number> | undefined;
  if (b.sourceVersions !== undefined) {
    const s = parseSourceVersions(b.sourceVersions, MAX_DISCOVER_PATHS);
    if (!s) return c.json({ error: "bad sourceVersions" }, 400);
    sources = s;
  }
  if (!(await allow(c, b.name, "manage"))) return c.json({ error: "denied" }, 403);
  if (await repository.findCollection(c.env.DB, b.name))
    return c.json({ error: "name already used", code: "name_exists" }, 409);
  const count = await repository.countCollections(c.env.DB);
  if ((count?.n ?? 0) >= MAX_COLLECTIONS)
    return c.json({ error: `collection limit reached (${MAX_COLLECTIONS})` }, 400);
  if (sources) {
    const rules = await rulesFor(c.env.DB, c.get("who"));
    for (const p of Object.keys(sources)) {
      if (!can(rules, p, "list")) {
        await deny(c, "secret.list", p);
        return c.json({ error: "denied" }, 403);
      }
    }
    const rows = await repository.currentSecrets(c.env.DB, Object.keys(sources));
    const byPath = new Map(rows.results.map((r) => [r.path, r.version]));
    for (const [p, v] of Object.entries(sources)) {
      if (byPath.get(p) !== v)
        return c.json(
          { error: "a source changed, refresh and retry", code: "source_changed" },
          409,
        );
    }
  }
  const created = await onUnique(
    repository.createCollection(
      c.env.DB,
      newId(),
      b.name,
      now(),
      parsed.def.envs,
      parsed.def.keys,
      sources,
    ),
    false,
  );
  if (!created) {
    if (await repository.findCollection(c.env.DB, b.name))
      return c.json({ error: "name already used", code: "name_exists" }, 409);
    return c.json({ error: "a source changed, refresh and retry", code: "source_changed" }, 409);
  }
  await audit(c.env.DB, {
    who: c.get("who").name,
    actor: c.get("who"),
    action: "collection.create",
    result: "ok",
    note: `${b.name}: ${parsed.def.keys.length} keys, ${parsed.def.envs.length} envs`,
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ name: b.name, revision: 1 }, 201);
});

// Read the definition: names, descriptions and mapped paths. Values are never stored here.
collections.get("/collections/:name", async (c) => {
  const name = c.req.param("name");
  if (!validCollectionName(name)) return c.json({ error: "bad collection name" }, 400);
  if (!(await allow(c, name, "read"))) return c.json({ error: "denied" }, 403);
  const found = await loadDefinition(c.env.DB, name);
  if (!found) return c.json({ error: "not found" }, 404);
  return c.json({
    name,
    revision: found.row.revision,
    createdAt: found.row.createdAt,
    updatedAt: found.row.updatedAt,
    envs: found.def.envs,
    keys: found.def.keys,
  });
});

// Compare: per environment, present, missing and extra names, with the observed version. Incomplete is never clean.
collections.get("/collections/:name/compare", async (c) => {
  const name = c.req.param("name");
  if (!validCollectionName(name)) return c.json({ error: "bad collection name" }, 400);
  if (!(await allow(c, name, "read"))) return c.json({ error: "denied" }, 403);
  const found = await loadDefinition(c.env.DB, name);
  if (!found) return c.json({ error: "not found" }, 404);
  const observed = await observe(c, found.def.envs);
  const result = compareEnvs(
    found.def.keys.map((k) => k.name),
    observed,
  );
  return c.json({
    name,
    revision: found.row.revision,
    observedAt: now(),
    result: result.result,
    envs: result.envs,
  });
});

// Replace the definition. Removed names and environments must be listed exactly, so removal is never implicit.
collections.put("/collections/:name", async (c) => {
  const name = c.req.param("name");
  if (!validCollectionName(name)) return c.json({ error: "bad collection name" }, 400);
  const b = await c.req.json<{
    revision?: unknown;
    envs?: unknown;
    keys?: unknown;
    removed?: unknown;
  }>();
  const revision = parseRevision(b.revision);
  if (revision === null) return c.json({ error: "revision is required" }, 400);
  const parsed = parseDefinition(b);
  if ("error" in parsed) return c.json({ error: parsed.error }, 400);
  const listed = parseRemovals(b.removed);
  if ("error" in listed) return c.json({ error: listed.error }, 400);
  if (!(await allow(c, name, "manage"))) return c.json({ error: "denied" }, 403);
  const found = await loadDefinition(c.env.DB, name);
  if (!found) return c.json({ error: "not found" }, 404);
  const diff = diffDefinition(found.def, parsed.def);
  if (!removalsConfirmed(diff, listed))
    return c.json(
      {
        error: "list every removed key and environment in removed",
        removals: { keys: diff.removedKeys, envs: diff.removedEnvs },
      },
      400,
    );
  const ok = await onUnique(
    repository.replaceDefinition(
      c.env.DB,
      found.row.id,
      revision,
      now(),
      parsed.def.envs,
      parsed.def.keys,
    ),
    false,
  );
  if (!ok)
    return c.json(
      { error: "the collection changed, reload and retry", code: "collection_changed" },
      409,
    );
  await audit(c.env.DB, {
    who: c.get("who").name,
    actor: c.get("who"),
    action: "collection.update",
    result: "ok",
    note: `${name}: ${diffNote(diff)}`,
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ name, revision: revision + 1 });
});

collections.delete("/collections/:name", async (c) => {
  const name = c.req.param("name");
  if (!validCollectionName(name)) return c.json({ error: "bad collection name" }, 400);
  const revision = parseRevision(Number(c.req.query("revision")));
  if (revision === null) return c.json({ error: "revision is required" }, 400);
  if (!(await allow(c, name, "manage"))) return c.json({ error: "denied" }, 403);
  const found = await repository.findCollection(c.env.DB, name);
  if (!found) return c.json({ error: "not found" }, 404);
  const ok = await repository.deleteCollection(c.env.DB, found.id, revision);
  if (!ok)
    return c.json(
      { error: "the collection changed, reload and retry", code: "collection_changed" },
      409,
    );
  await audit(c.env.DB, {
    who: c.get("who").name,
    actor: c.get("who"),
    action: "collection.delete",
    result: "ok",
    note: name,
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ ok: true });
});

// Reconcile preview: which names are extra, and in which environments. Returns the versions apply must match.
collections.post("/collections/:name/reconcile/preview", async (c) => {
  const name = c.req.param("name");
  if (!validCollectionName(name)) return c.json({ error: "bad collection name" }, 400);
  const b = await c.req.json<{ names?: unknown }>();
  const names = parseNames(b.names);
  if (!names) return c.json({ error: "names must be a list of unique key names" }, 400);
  if (!(await allow(c, name, "manage"))) return c.json({ error: "denied" }, 403);
  const found = await loadDefinition(c.env.DB, name);
  if (!found) return c.json({ error: "not found" }, 404);
  const declared = new Set(found.def.keys.map((k) => k.name));
  const observed = await observe(c, found.def.envs);
  const extras = extraNames([...declared], observed);
  const envPaths = new Map(found.def.envs.map((e) => [e.label, e.path]));
  const picked = new Map(names.map((n) => [n, extras.get(n) ?? []]));
  const sources = requiredSources(picked, envPaths);
  const versions = Object.fromEntries(
    sources.map((p) => {
      const o = observed.find((e) => e.path === p)?.observed;
      return [p, o?.status === "ok" ? o.version : 0];
    }),
  );
  return c.json({
    name,
    revision: found.row.revision,
    names: names.map((n) => ({
      name: n,
      declared: declared.has(n),
      observedIn: picked.get(n) ?? [],
    })),
    sourceVersions: versions,
  });
});

// Reconcile apply: adds the selected extra names to the declaration. Writes no environment value.
collections.post("/collections/:name/reconcile", async (c) => {
  const name = c.req.param("name");
  if (!validCollectionName(name)) return c.json({ error: "bad collection name" }, 400);
  const b = await c.req.json<{ revision?: unknown; names?: unknown; sourceVersions?: unknown }>();
  const revision = parseRevision(b.revision);
  if (revision === null) return c.json({ error: "revision is required" }, 400);
  const names = parseNames(b.names);
  if (!names) return c.json({ error: "names must be a list of unique key names" }, 400);
  const sourceVersions = parseSourceVersions(b.sourceVersions, MAX_DISCOVER_PATHS);
  if (!sourceVersions) return c.json({ error: "bad sourceVersions" }, 400);
  if (!(await allow(c, name, "manage"))) return c.json({ error: "denied" }, 403);
  const found = await loadDefinition(c.env.DB, name);
  if (!found) return c.json({ error: "not found" }, 404);
  if (found.row.revision !== revision)
    return c.json(
      { error: "the collection changed, reload and retry", code: "collection_changed" },
      409,
    );
  const declared = new Set(found.def.keys.map((k) => k.name));
  if (names.some((n) => declared.has(n)))
    return c.json({ error: "a name is already declared" }, 400);
  const observed = await observe(c, found.def.envs);
  const extras = extraNames([...declared], observed);
  const picked = new Map(names.map((n) => [n, extras.get(n) ?? []]));
  const envPaths = new Map(found.def.envs.map((e) => [e.label, e.path]));
  const required = requiredSources(picked, envPaths);
  const stale = () =>
    c.json(
      { error: "a source changed, reload the preview and retry", code: "source_changed" },
      409,
    );
  if ([...picked.values()].some((labels) => labels.length === 0)) return stale();
  const given = Object.keys(sourceVersions).sort();
  if (given.length !== required.length || given.some((p, i) => p !== required[i])) return stale();
  for (const p of required) {
    const o = observed.find((e) => e.path === p)?.observed;
    if (o?.status !== "ok" || o.version !== sourceVersions[p]) return stale();
  }
  const ok = await onUnique(
    repository.addKeys(
      c.env.DB,
      found.row.id,
      revision,
      now(),
      names.map((n) => ({ name: n, description: null })),
      sourceVersions,
    ),
    false,
  );
  if (!ok) {
    const current = await repository.findCollection(c.env.DB, name);
    if (!current || current.revision !== revision)
      return c.json(
        { error: "the collection changed, reload and retry", code: "collection_changed" },
        409,
      );
    return stale();
  }
  await audit(c.env.DB, {
    who: c.get("who").name,
    actor: c.get("who"),
    action: "collection.reconcile",
    result: "ok",
    note: `${name}: ${names.map((n) => `+key ${n}`).join(", ")}`,
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ name, revision: revision + 1, added: names });
});
