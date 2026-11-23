import { Hono } from "hono";
import { audit } from "../audit.ts";
import { requireAdmin } from "../auth.ts";
import { validPath } from "../policy.ts";
import {
  createKeyring,
  createPersonalKeyring,
  findKeyringKey,
  findPersonalKeyring,
  findPersonalKeyringOwner,
  findPublicKey,
  inviteIdentity,
  listIdentities,
  listKeyrings,
} from "../repository/keyrings.ts";
import type { AppEnv } from "../types.ts";
import { newId, now } from "../util.ts";

export const keyrings = new Hono<AppEnv>();

keyrings.get("/keyrings", async (c) => {
  const who = c.get("who");
  const rows = await listKeyrings(c.env.DB, who.role, who.id);
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
    await createKeyring(c.env.DB, id, b.prefix, now(), b.members);
  } catch {
    return c.json({ error: "group already exists or a member is unknown" }, 409);
  }
  await audit(c.env.DB, {
    who: who.name,
    actor: who,
    action: "group.create",
    path: b.prefix,
    result: "ok",
  });
  return c.json({ id, prefix: b.prefix }, 201);
});

// The caller's wrapped copy of a group key. Whoever lacks one cannot decrypt, whatever the policies say.
// ADR 16: a time-boxed key (from an approved request) is refused once its expires_at has passed.
// ?version=N returns an older key the caller still holds, to read versions written before a rotation.
keyrings.get("/keyrings/:prefix/key", async (c) => {
  const who = c.get("who");
  const prefix = c.req.param("prefix");
  const want = c.req.query("version");
  if (want !== undefined && !/^[1-9][0-9]{0,8}$/.test(want))
    return c.json({ error: "bad version" }, 400);
  const row = await findKeyringKey(
    c.env.DB,
    prefix,
    who.id,
    want === undefined ? null : Number(want),
  );
  if (!row) return c.json({ error: "no key for you in this group" }, 404);
  if (row.expiresAt !== null && row.expiresAt <= now()) {
    await audit(c.env.DB, {
      who: who.name,
      actor: who,
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
  const rows = await listIdentities(c.env.DB);
  return c.json(rows.results);
});

keyrings.post("/invites", requireAdmin, async (c) => {
  const who = c.get("who");
  const b = await c.req.json<{ email?: string; role?: "admin" | "member" }>();
  const email = b.email?.trim().toLowerCase();
  if (!email || !/^[^@\s]+@[^@\s]+$/.test(email)) return c.json({ error: "bad email" }, 400);
  try {
    await inviteIdentity(c.env.DB, newId(), email, b.role === "admin" ? "admin" : "member", now());
  } catch {
    return c.json({ error: "already invited" }, 409);
  }
  await audit(c.env.DB, {
    who: who.name,
    actor: who,
    action: "user.invite",
    note: email,
    result: "ok",
  });
  return c.json({ ok: true }, 201);
});

// A unique owner and database guards make creation safe across concurrent unlocks and prevent sharing.
keyrings.get("/me/personal-keyring", async (c) => {
  const row = await findPersonalKeyring(c.env.DB, c.get("who").id);
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
  const identity = await findPublicKey(c.env.DB, who.id);
  if (!identity?.public_key) return c.json({ error: "set up your vault first" }, 409);
  const id = newId();
  try {
    await createPersonalKeyring(c.env.DB, id, b.prefix, now(), who.id, b.wrappedKey);
  } catch {
    const existing = await findPersonalKeyringOwner(c.env.DB, who.id);
    if (existing) return c.json(existing);
    return c.json({ error: "group already exists" }, 409);
  }
  return c.json({ id, prefix: b.prefix, version: 1 }, 201);
});
