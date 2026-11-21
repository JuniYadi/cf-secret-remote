import { Hono } from "hono";
import { audit } from "../audit.ts";
import { requireAdmin } from "../auth.ts";
import { validPath } from "../policy.ts";
import type { AppEnv } from "../types.ts";
import { newId, now } from "../util.ts";

export const keyrings = new Hono<AppEnv>();

keyrings.get("/keyrings", async (c) => {
  const who = c.get("who");
  const rows = await c.env.DB.prepare(
    `SELECT k.prefix, k.version FROM keyring k
     WHERE ?1 = 'admin' OR EXISTS (SELECT 1 FROM keyring_member m WHERE m.keyring_id = k.id AND m.identity_id = ?2)
     ORDER BY k.prefix`,
  )
    .bind(who.role, who.id)
    .all();
  return c.json(rows.results);
});

// The creator generates the keyring key in the browser and wraps it to each member's public key.
keyrings.post("/keyrings", requireAdmin, async (c) => {
  const who = c.get("who");
  const b = await c.req.json<{
    prefix?: string;
    members?: { identityId: string; wrappedKey: string }[];
  }>();
  if (!b.prefix || !validPath(b.prefix) || b.prefix.includes("/") || !b.members?.length)
    return c.json({ error: "bad request" }, 400);
  const id = newId();
  try {
    await c.env.DB.batch([
      c.env.DB.prepare("INSERT INTO keyring (id, prefix, created_at) VALUES (?, ?, ?)").bind(
        id,
        b.prefix,
        now(),
      ),
      ...b.members.map((m) =>
        c.env.DB.prepare(
          "INSERT INTO keyring_member (keyring_id, identity_id, version, wrapped_key) VALUES (?, ?, 1, ?)",
        ).bind(id, m.identityId, m.wrappedKey),
      ),
    ]);
  } catch {
    return c.json({ error: "group already exists or a member is unknown" }, 409);
  }
  await audit(c.env.DB, { who: who.name, action: "group.create", path: b.prefix, result: "ok" });
  return c.json({ id, prefix: b.prefix }, 201);
});

// The caller's wrapped copy of a group key. Whoever lacks one cannot decrypt, whatever the policies say.
// ADR 16: a time-boxed key (from an approved request) is refused once its expires_at has passed.
keyrings.get("/keyrings/:prefix/key", async (c) => {
  const who = c.get("who");
  const prefix = c.req.param("prefix");
  const row = await c.env.DB.prepare(
    `SELECT m.wrapped_key, m.version, m.expires_at AS expiresAt FROM keyring_member m JOIN keyring k ON k.id = m.keyring_id
     WHERE k.prefix = ? AND m.identity_id = ? ORDER BY m.version DESC LIMIT 1`,
  )
    .bind(prefix, who.id)
    .first<{ wrapped_key: string; version: number; expiresAt: number | null }>();
  if (!row) return c.json({ error: "no key for you in this group" }, 404);
  if (row.expiresAt !== null && row.expiresAt <= now()) {
    await audit(c.env.DB, {
      who: who.name,
      action: "group.key",
      path: prefix,
      version: row.version,
      result: "denied",
      note: "access expired",
      ip: c.req.header("CF-Connecting-IP"),
    });
    return c.json({ error: "access has expired" }, 403);
  }
  return c.json({ wrappedKey: row.wrapped_key, version: row.version });
});

keyrings.get("/identities", requireAdmin, async (c) => {
  const rows = await c.env.DB.prepare(
    "SELECT id, kind, name, role, public_key AS publicKey, status, (recovery_locked_key IS NOT NULL) AS recoverySet FROM identity ORDER BY name",
  ).all();
  return c.json(rows.results);
});

keyrings.post("/invites", requireAdmin, async (c) => {
  const who = c.get("who");
  const b = await c.req.json<{ email?: string; role?: "admin" | "member" }>();
  const email = b.email?.trim().toLowerCase();
  if (!email || !/^[^@\s]+@[^@\s]+$/.test(email)) return c.json({ error: "bad email" }, 400);
  try {
    await c.env.DB.prepare(
      "INSERT INTO identity (id, kind, name, role, created_at) VALUES (?, 'user', ?, ?, ?)",
    )
      .bind(newId(), email, b.role === "admin" ? "admin" : "member", now())
      .run();
  } catch {
    return c.json({ error: "already invited" }, 409);
  }
  await audit(c.env.DB, { who: who.name, action: "user.invite", note: email, result: "ok" });
  return c.json({ ok: true }, 201);
});
