import { Hono } from "hono";
import { audit } from "../audit.ts";
import { can, validPath } from "../policy.ts";
import type { AppEnv, Who } from "../types.ts";
import { now } from "../util.ts";
import { applyMeta, check, type Meta, ownerExists, parseMetaPatch, rulesFor } from "./secrets.ts";

// ADR 22. Routes for this feature live here; the router is already registered in src/index.ts.
export const versions = new Hono<AppEnv>();

/** ADR 22: a soft-deleted secret is restorable by an admin for 30 days, then purged. */
export const RESTORE_WINDOW = 30 * 86400;
/** Access history counts this many seconds back. */
export const HISTORY_WINDOW = 30 * 86400;

// Access history. Only ciphertext fetches count as "opened" (audit action secret.read, result ok).
// Denied attempts and writes are not opens.
versions.get("/secret/history", async (c) => {
  const path = c.req.query("path") ?? "";
  if (!validPath(path)) return c.json({ error: "bad path" }, 400);
  if (!(await check(c, path, "update"))) return c.json({ error: "denied" }, 403);
  const db = c.env.DB;
  const since = now() - HISTORY_WINDOW;
  const rows = await db
    .prepare(
      `SELECT at, json_extract(entry, '$.who') AS who, json_extract(entry, '$.version') AS version
       FROM audit
       WHERE json_extract(entry, '$.action') = 'secret.read'
         AND json_extract(entry, '$.path') = ?
         AND json_extract(entry, '$.result') = 'ok'
         AND at >= ?
       ORDER BY at DESC, seq DESC`,
    )
    .bind(path, since)
    .all<{ at: number; who: string; version: number }>();

  const byName = new Map<string, { opens: number; lastOpened: number; lastVersion: number }>();
  for (const r of rows.results) {
    const agg = byName.get(r.who);
    if (agg) agg.opens++;
    else byName.set(r.who, { opens: 1, lastOpened: r.at, lastVersion: r.version });
  }

  const people = [];
  for (const [name, agg] of byName) {
    people.push({ name, ...agg, hasAccess: await stillHasAccess(db, name, path) });
  }
  people.sort((a, b) => b.lastOpened - a.lastOpened);
  const last = rows.results[0];
  return c.json({
    path,
    windowDays: HISTORY_WINDOW / 86400,
    opens: rows.results.length,
    readers: people.length,
    lastReader: last ? { who: last.who, at: last.at, version: last.version } : null,
    lostAccess: people.filter((p) => !p.hasAccess).length,
    people,
  });
});

/** A person keeps access only with a read policy AND the current group key (ADR 2: two gates). */
async function stillHasAccess(db: D1Database, name: string, path: string): Promise<boolean> {
  const ident = await db
    .prepare(
      "SELECT id, kind, name, role, status FROM identity WHERE name = ? ORDER BY kind LIMIT 1",
    )
    .bind(name)
    .first<Who & { status: string }>();
  if (ident?.status !== "active") return false;
  if (!can(await rulesFor(db, ident), path, "read")) return false;
  const member = await db
    .prepare(
      `SELECT 1 AS ok FROM keyring k JOIN keyring_member km ON km.keyring_id = k.id
       WHERE k.prefix = ? AND km.identity_id = ? AND km.version = k.version`,
    )
    .bind(path.split("/")[0] ?? "", ident.id)
    .first();
  return member !== null;
}

// Metadata: cleartext, changed without a new version. Partial: absent fields stay, null clears.
versions.put("/secret/meta", async (c) => {
  const b = await c.req.json<{ path?: string; meta?: unknown }>();
  const path = b.path ?? "";
  if (!validPath(path)) return c.json({ error: "bad path" }, 400);
  const parsed = parseMetaPatch(b.meta);
  if ("error" in parsed) return c.json({ error: parsed.error }, 400);
  if (typeof parsed.patch.owner === "string" && !(await ownerExists(c.env.DB, parsed.patch.owner)))
    return c.json({ error: "owner is not a known identity" }, 400);
  if (!(await check(c, path, "update"))) return c.json({ error: "denied" }, 403);
  const row = await c.env.DB.prepare(
    "SELECT id, meta FROM secret WHERE path = ? AND deleted_at IS NULL",
  )
    .bind(path)
    .first<{ id: string; meta: string | null }>();
  if (!row) return c.json({ error: "not found" }, 404);
  const next: Meta = applyMeta(row.meta ? (JSON.parse(row.meta) as Meta) : {}, parsed.patch);
  await c.env.DB.prepare("UPDATE secret SET meta = ? WHERE id = ?")
    .bind(JSON.stringify(next), row.id)
    .run();
  await audit(c.env.DB, {
    who: c.get("who").name,
    action: "secret.meta",
    path,
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ path, meta: next });
});

// Undo a soft delete. Admins only, and only within the restore window.
versions.post("/secret/restore-delete", async (c) => {
  const who = c.get("who");
  const path = c.req.query("path") ?? "";
  if (!validPath(path)) return c.json({ error: "bad path" }, 400);
  if (who.role !== "admin") {
    await audit(c.env.DB, {
      who: who.name,
      action: "secret.restore",
      path,
      result: "denied",
      ip: c.req.header("CF-Connecting-IP"),
    });
    return c.json({ error: "denied" }, 403);
  }
  const row = await c.env.DB.prepare(
    "SELECT id, deleted_at AS deletedAt FROM secret WHERE path = ?",
  )
    .bind(path)
    .first<{ id: string; deletedAt: number | null }>();
  if (!row?.deletedAt) return c.json({ error: "not found" }, 404);
  if (now() - row.deletedAt > RESTORE_WINDOW) return c.json({ error: "too old to restore" }, 410);
  await c.env.DB.prepare("UPDATE secret SET deleted_at = NULL WHERE id = ?").bind(row.id).run();
  await audit(c.env.DB, {
    who: who.name,
    action: "secret.restore",
    path,
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ ok: true, path });
});

/**
 * ADR 22: deletes soft-deleted secrets older than the restore window, with their versions.
 * Called by the cron job (ADR 19). Returns the number of secrets purged.
 */
export async function purgeDeletedSecrets(db: D1Database, at: number = now()): Promise<number> {
  const old = await db
    .prepare("SELECT id, path FROM secret WHERE deleted_at IS NOT NULL AND deleted_at < ?")
    .bind(at - RESTORE_WINDOW)
    .all<{ id: string; path: string }>();
  for (const s of old.results) {
    await db.batch([
      db.prepare("DELETE FROM secret_version WHERE secret_id = ?").bind(s.id),
      db.prepare("DELETE FROM secret WHERE id = ?").bind(s.id),
    ]);
    await audit(db, { who: "system", action: "secret.purge", path: s.path, result: "ok" });
  }
  return old.results.length;
}
