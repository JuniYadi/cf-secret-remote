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
    `SELECT k.id, k.prefix, k.version FROM keyring k
     WHERE k.personal_owner IS NULL AND (?1 = 'admin' OR EXISTS (SELECT 1 FROM keyring_member m WHERE m.keyring_id = k.id AND m.identity_id = ?2))
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
     WHERE k.prefix = ? AND k.personal_owner IS NULL AND m.identity_id = ? ORDER BY m.version DESC LIMIT 1`,
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
    "SELECT id, kind, name, role, public_key AS publicKey, status, (recovery_locked_key IS NOT NULL) AS recoverySet, last_unlocked_at FROM identity ORDER BY name",
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

// A unique owner and database guards make creation safe across concurrent unlocks and prevent sharing.
keyrings.get("/me/personal-keyring", async (c) => {
  const row = await c.env.DB.prepare(
    `SELECT k.id, k.prefix, k.version, m.wrapped_key AS wrappedKey FROM keyring k
     JOIN keyring_member m ON m.keyring_id = k.id AND m.identity_id = k.personal_owner AND m.version = k.version
     WHERE k.personal_owner = ?`,
  )
    .bind(c.get("who").id)
    .first();
  return c.json(row ?? null);
});

keyrings.post("/me/personal-keyring", async (c) => {
  const who = c.get("who");
  if (who.kind !== "user") return c.json({ error: "users only" }, 403);
  const b = await c.req
    .json<{ prefix?: unknown; wrappedKey?: unknown }>()
    .catch(() => ({}) as { prefix?: unknown; wrappedKey?: unknown });
  if (
    typeof b.prefix !== "string" ||
    !/^personal-[a-z0-9-]{1,100}$/.test(b.prefix) ||
    typeof b.wrappedKey !== "string" ||
    !b.wrappedKey ||
    b.wrappedKey.length > 8192
  )
    return c.json({ error: "bad request" }, 400);
  const identity = await c.env.DB.prepare("SELECT public_key FROM identity WHERE id = ?")
    .bind(who.id)
    .first<{ public_key: string | null }>();
  if (!identity?.public_key) return c.json({ error: "set up your vault first" }, 409);
  const id = newId();
  try {
    await c.env.DB.batch([
      c.env.DB.prepare(
        "INSERT INTO keyring (id, prefix, created_at, personal_owner) VALUES (?, ?, ?, ?)",
      ).bind(id, b.prefix, now(), who.id),
      c.env.DB.prepare(
        "INSERT INTO keyring_member (keyring_id, identity_id, version, wrapped_key) VALUES (?, ?, 1, ?)",
      ).bind(id, who.id, b.wrappedKey),
    ]);
  } catch {
    const existing = await c.env.DB.prepare(
      "SELECT id, prefix, version FROM keyring WHERE personal_owner = ?",
    )
      .bind(who.id)
      .first();
    if (existing) return c.json(existing);
    return c.json({ error: "group already exists" }, 409);
  }
  return c.json({ id, prefix: b.prefix, version: 1 }, 201);
});
