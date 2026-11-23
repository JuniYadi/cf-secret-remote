import { Hono } from "hono";
import { audit } from "../audit.ts";
import { can, validPath } from "../policy.ts";
import {
  deleteSecretVersions,
  findDeletedSecret,
  findSecretMeta,
  historyIdentity,
  historyMembership,
  historyRows,
  listExpiredSecrets,
  restoreDeletedSecret,
  updateSecretMeta,
} from "../repository/versions.ts";
import type { AppEnv } from "../types.ts";
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
  const rows = await historyRows(db, path, since);

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
  const ident = await historyIdentity(db, name);
  if (ident?.status !== "active") return false;
  if (!can(await rulesFor(db, ident), path, "read")) return false;
  const member = await historyMembership(db, path.split("/")[0] ?? "", ident.id);
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
  const row = await findSecretMeta(c.env.DB, path);
  if (!row) return c.json({ error: "not found" }, 404);
  const next: Meta = applyMeta(row.meta ? (JSON.parse(row.meta) as Meta) : {}, parsed.patch);
  await updateSecretMeta(c.env.DB, JSON.stringify(next), row.id);
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
  const row = await findDeletedSecret(c.env.DB, path);
  if (!row?.deletedAt) return c.json({ error: "not found" }, 404);
  if (now() - row.deletedAt > RESTORE_WINDOW) return c.json({ error: "too old to restore" }, 410);
  await restoreDeletedSecret(c.env.DB, row.id);
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
  const old = await listExpiredSecrets(db, at - RESTORE_WINDOW);
  for (const s of old.results) {
    await deleteSecretVersions(db, s.id);
    await audit(db, { who: "system", action: "secret.purge", path: s.path, result: "ok" });
  }
  return old.results.length;
}
