import { Hono } from "hono";
import { audit } from "../audit.ts";
import type { AppEnv } from "../types.ts";
import { now } from "../util.ts";

// ADR 27: people see their own signed-in devices and can end them. The id is the first 16 chars of the token hash.
export const sessions = new Hono<AppEnv>();

sessions.get("/sessions", async (c) => {
  const rows = await c.env.DB.prepare(
    "SELECT substr(token_hash, 1, 16) AS id, kind, device, created_at AS createdAt, last_used_at AS lastUsedAt, expires_at AS expiresAt FROM session WHERE identity_id = ? AND expires_at > ? ORDER BY created_at DESC",
  )
    .bind(c.get("who").id, now())
    .all();
  return c.json(rows.results);
});

sessions.delete("/sessions/:id", async (c) => {
  const who = c.get("who");
  const res = await c.env.DB.prepare(
    "DELETE FROM session WHERE identity_id = ? AND substr(token_hash, 1, 16) = ?",
  )
    .bind(who.id, c.req.param("id"))
    .run();
  if (!res.meta.changes) return c.json({ error: "not found" }, 404);
  await audit(c.env.DB, {
    who: who.name,
    action: "session.revoke",
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ ok: true });
});

// Ends every session of the caller, including the one that made this call when it is a CLI token.
sessions.delete("/sessions", async (c) => {
  const who = c.get("who");
  const res = await c.env.DB.prepare("DELETE FROM session WHERE identity_id = ?")
    .bind(who.id)
    .run();
  await audit(c.env.DB, {
    who: who.name,
    action: "session.revoke",
    note: `all, ${res.meta.changes} sessions`,
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ ok: true, ended: res.meta.changes });
});
