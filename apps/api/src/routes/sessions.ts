import { Hono } from "hono";
import { audit } from "../audit.ts";
import { deleteSession, deleteSessions, listSessions } from "../repository/account.ts";
import type { AppEnv } from "../types.ts";
import { now } from "../util.ts";

// ADR 27: people see their own signed-in devices and can end them. The id is the first 16 chars of the token hash.
export const sessions = new Hono<AppEnv>();

sessions.get("/sessions", async (c) => {
  const rows = await listSessions(c.env.DB, c.get("who").id, now());
  return c.json(rows.results);
});

sessions.delete("/sessions/:id", async (c) => {
  const who = c.get("who");
  const res = await deleteSession(c.env.DB, who.id, c.req.param("id"));
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
  const res = await deleteSessions(c.env.DB, who.id);
  await audit(c.env.DB, {
    who: who.name,
    action: "session.revoke",
    note: `all, ${res.meta.changes} sessions`,
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ ok: true, ended: res.meta.changes });
});
