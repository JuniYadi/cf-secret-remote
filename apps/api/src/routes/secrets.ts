import { ConflictCode, isReservedSecretPath } from "@cfs/core";
import { Hono } from "hono";
import { agentGuard } from "../agent-guard.ts";
import { audit } from "../audit.ts";
import { lapsedGrant } from "../grants.ts";
import { NAME_RE } from "../limits.ts";
import { type Cap, can, prefixOf, type Rule, validPath } from "../policy.ts";
import { loadGroup } from "../repository/keyrings.ts";
import * as repository from "../repository/secrets.ts";
import type { AppEnv, Who } from "../types.ts";
import { newId, now } from "../util.ts";

export const secrets = new Hono<AppEnv>();

export async function rulesFor(db: D1Database, who: Who): Promise<Rule[]> {
  if (who.role === "admin")
    return [{ path: "*", caps: ["create", "read", "update", "delete", "list"] }];
  const rows = await repository.policyRules(db, who.id, now());
  return rows.results.flatMap((r) => JSON.parse(r.rules) as Rule[]);
}

export async function check(
  c: {
    env: { DB: D1Database };
    get: (k: "who") => Who;
    req: { header: (n: string) => string | undefined };
  },
  path: string,
  cap: Cap,
): Promise<boolean> {
  const who = c.get("who");
  const ok = can(await rulesFor(c.env.DB, who), path, cap);
  if (!ok)
    await audit(c.env.DB, {
      who: who.name,
      actor: who,
      action: `secret.${cap}`,
      path,
      result: "denied",
      ip: c.req.header("CF-Connecting-IP"),
    });
  return ok;
}

// ADR 22. Fingerprints are hex(8 bytes), one per name, computed by the client with the group key.
const FP_RE = /^[0-9a-f]{16}$/;
export const validFps = (fps: unknown, names: string[]): fps is Record<string, string> =>
  typeof fps === "object" &&
  fps !== null &&
  !Array.isArray(fps) &&
  Object.keys(fps).length === new Set(names).size &&
  names.every(
    (n) =>
      typeof (fps as Record<string, unknown>)[n] === "string" &&
      FP_RE.test((fps as Record<string, string>)[n] as string),
  );

// ADR 22. Metadata is cleartext and has exactly these fields. Anything else (e.g. a `values` key) is refused.
export const META_KEYS = ["description", "owner", "rotateBy"] as const;
export type MetaKey = (typeof META_KEYS)[number];
export type Meta = Partial<Record<MetaKey, string>>;
/** A patch: a string sets the field, null clears it, an absent key leaves it alone. */
export type MetaPatch = Partial<Record<MetaKey, string | null>>;

export function parseMetaPatch(raw: unknown): { patch: MetaPatch } | { error: string } {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw))
    return { error: "meta must be an object" };
  const patch: MetaPatch = {};
  for (const [k, v] of Object.entries(raw)) {
    if (!(META_KEYS as readonly string[]).includes(k)) return { error: `unknown meta field: ${k}` };
    if (v === null) {
      patch[k as MetaKey] = null;
      continue;
    }
    if (typeof v !== "string") return { error: `meta.${k} must be a string` };
    if (k === "description" && v.length > 200) return { error: "meta.description is too long" };
    if (k === "owner" && (v.length === 0 || v.length > 254))
      return { error: "meta.owner is not valid" };
    if (k === "rotateBy") {
      const d = new Date(`${v}T00:00:00Z`);
      if (
        !/^\d{4}-\d{2}-\d{2}$/.test(v) ||
        Number.isNaN(d.getTime()) ||
        d.toISOString().slice(0, 10) !== v
      )
        return { error: "meta.rotateBy must be a date, YYYY-MM-DD" };
    }
    patch[k as MetaKey] = v;
  }
  return { patch };
}

export function applyMeta(current: Meta, patch: MetaPatch): Meta {
  const out: Meta = { ...current };
  for (const k of META_KEYS) {
    if (!(k in patch)) continue;
    const v = patch[k];
    if (v === null || v === undefined) delete out[k];
    else out[k] = v;
  }
  return out;
}

/** The owner must be a known, active identity (ADR 22: owner is an identity). */
export async function ownerExists(db: D1Database, name: string): Promise<boolean> {
  const row = await repository.findOwner(db, name);
  return row !== null;
}

// List: names only, filtered by the caller's list permission. Never values.
secrets.get("/secrets", async (c) => {
  const who = c.get("who");
  const rules = await rulesFor(c.env.DB, who);
  const rows = await repository.listSecrets(c.env.DB);
  return c.json(
    rows.results
      .filter((r) => can(rules, r.path, "list"))
      .map((r) => ({
        path: r.path,
        version: r.version,
        updatedAt: r.updatedAt,
        names: JSON.parse(r.names) as string[],
        meta: r.meta ? (JSON.parse(r.meta) as Meta) : {},
        lastOpenedBy: r.lastOpenedBy,
        lastOpenedAt: r.lastOpenedAt,
      })),
  );
});

// Read: returns ciphertext and the wrapped DEK. The caller still needs the group key to open it. Logged as a fetch.
secrets.get("/secret", async (c) => {
  const path = c.req.query("path") ?? "";
  if (!validPath(path)) return c.json({ error: "bad path" }, 400);
  if (!(await check(c, path, "read"))) return c.json({ error: "denied" }, 403);
  // ADR 16: ciphertext is refused once the caller's time-boxed group key has lapsed.
  const who = c.get("who");
  if (await lapsedGrant(c.env.DB, who.id, prefixOf(path), now())) {
    await audit(c.env.DB, {
      who: who.name,
      actor: who,
      action: "secret.read",
      path,
      result: "denied",
      note: "access expired",
      ip: c.req.header("CF-Connecting-IP"),
    });
    return c.json({ error: "access has expired" }, 403);
  }
  // ADR 17: agent rules for this path (reason, approval for */prod, per-hour budget). Refusals are audited.
  const guard = await agentGuard(
    c.env.DB,
    who,
    path,
    c.req.header("X-Cfs-Reason"),
    c.req.header("CF-Connecting-IP"),
  );
  if (!guard.ok) {
    if (guard.retryAfter) c.header("Retry-After", String(guard.retryAfter));
    return c.json({ error: guard.error }, guard.status);
  }
  const want = c.req.query("version");
  const row = await repository.readSecret(c.env.DB, want ? Number(want) : null, path);
  if (!row) return c.json({ error: "not found" }, 404);
  await audit(c.env.DB, {
    who: who.name,
    actor: who,
    action: c.req.query("merge") === "1" ? "secret.merge_read" : "secret.read",
    path,
    version: row.version,
    result: "ok",
    note: guard.note,
    ip: c.req.header("CF-Connecting-IP"),
  });
  const { meta, ...rest } = row;
  return c.json({
    ...rest,
    names: JSON.parse(row.names),
    meta: meta ? (JSON.parse(meta) as Meta) : {},
  });
});

// Write: the client sends an already-encrypted version. The server cannot read or validate the values.
secrets.put("/secret", async (c) => {
  const who = c.get("who");
  const b = await c.req.json<{
    path?: string;
    names?: string[];
    wrappedDek?: string;
    ciphertext?: string;
    keyringVersion?: number;
    version?: number;
    fps?: unknown;
    meta?: unknown;
  }>();
  const { path, names, wrappedDek, ciphertext, keyringVersion } = b;
  if (
    !path ||
    !validPath(path) ||
    !Array.isArray(names) ||
    !wrappedDek ||
    !ciphertext?.startsWith("v1.") ||
    !keyringVersion
  ) {
    return c.json({ error: "bad request" }, 400);
  }
  if (names.some((n) => typeof n !== "string" || !NAME_RE.test(n)))
    return c.json({ error: "bad name" }, 400);
  if (b.fps !== undefined && !validFps(b.fps, names))
    return c.json({ error: "bad fingerprints" }, 400);
  let metaPatch: MetaPatch | undefined;
  if (b.meta !== undefined) {
    const parsed = parseMetaPatch(b.meta);
    if ("error" in parsed) return c.json({ error: parsed.error }, 400);
    metaPatch = parsed.patch;
    if (typeof metaPatch.owner === "string" && !(await ownerExists(c.env.DB, metaPatch.owner)))
      return c.json({ error: "owner is not a known identity" }, 400);
  }
  const keyring = await loadGroup(c.env.DB, prefixOf(path));
  if (!keyring)
    return c.json({ error: "create the group first", code: ConflictCode.group_required }, 409);
  // ADR 14: no writes while the group is rotating.
  if (keyring.status === "rotating")
    return c.json(
      { error: "group is rotating, writes are paused", code: ConflictCode.group_rotating },
      409,
    );
  if (keyringVersion !== keyring.version)
    return c.json(
      { error: "group key changed, reload and retry", code: ConflictCode.group_key_changed },
      409,
    );

  const existing = await repository.findSecret(c.env.DB, path);
  if (!existing && isReservedSecretPath(path))
    return c.json({ error: "secret name is reserved for a web route" }, 400);
  const cap: Cap = existing ? "update" : "create";
  if (!(await check(c, path, cap))) return c.json({ error: "denied" }, 403);
  // ADR 22: a deleted secret comes back only through an admin restore, not by a new write.
  if (existing?.deletedAt)
    return c.json(
      { error: "secret is deleted, an admin can restore it", code: ConflictCode.secret_deleted },
      409,
    );

  const id = existing?.id ?? newId();
  const version = (existing?.current ?? 0) + 1;
  // ADR 10: the client sealed for this exact version, so it must be the next one.
  if (b.version !== version)
    return c.json(
      {
        error: "version changed, reload and retry",
        code: ConflictCode.version_conflict,
        current: existing?.current ?? 0,
      },
      409,
    );
  const metaJson = metaPatch
    ? JSON.stringify(
        applyMeta(existing?.meta ? (JSON.parse(existing.meta) as Meta) : {}, metaPatch),
      )
    : null;
  await repository.writeSecret(
    c.env.DB,
    !!existing,
    id,
    path,
    keyring.id,
    version,
    metaJson,
    keyringVersion,
    JSON.stringify(names),
    wrappedDek,
    ciphertext,
    who.id,
    b.fps === undefined ? null : JSON.stringify(b.fps),
    now,
  );
  await audit(c.env.DB, {
    who: who.name,
    actor: who,
    action: "secret.write",
    path,
    version,
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ path, version }, existing ? 200 : 201);
});

secrets.delete("/secret", async (c) => {
  const path = c.req.query("path") ?? "";
  if (!validPath(path)) return c.json({ error: "bad path" }, 400);
  if (!(await check(c, path, "delete"))) return c.json({ error: "denied" }, 403);
  // ADR 14: no writes while the group is rotating.
  const grp = await repository.secretGroup(c.env.DB, path);
  if (grp?.status === "rotating")
    return c.json(
      { error: "group is rotating, writes are paused", code: ConflictCode.group_rotating },
      409,
    );
  const res = await repository.deleteSecret(c.env.DB, now(), path);
  if (!res.meta.changes) return c.json({ error: "not found" }, 404);
  await audit(c.env.DB, {
    who: c.get("who").name,
    actor: c.get("who"),
    action: "secret.delete",
    path,
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ ok: true });
});

// Version list: metadata, fingerprints and who wrote each version. Never values.
secrets.get("/secret/versions", async (c) => {
  const path = c.req.query("path") ?? "";
  if (!validPath(path)) return c.json({ error: "bad path" }, 400);
  if (!(await check(c, path, "list"))) return c.json({ error: "denied" }, 403);
  const rows = await repository.secretVersions(c.env.DB, path);
  return c.json(
    rows.results.map((r) => ({
      ...r,
      names: JSON.parse(r.names),
      fps: r.fps ? JSON.parse(r.fps) : null,
    })),
  );
});
