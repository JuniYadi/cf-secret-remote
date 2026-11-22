import { isPrivateKeyLock, isRecoveryLockedKey } from "@cfs/core";
import { Hono } from "hono";
import { audit } from "../audit.ts";
import { LAST_USED_EVERY } from "../auth.ts";
import type { AppEnv } from "../types.ts";
import { now } from "../util.ts";

export const me = new Hono<AppEnv>();

me.get("/whoami", async (c) => {
  const who = c.get("who");
  const row = await c.env.DB.prepare("SELECT public_key, locked_key FROM identity WHERE id = ?")
    .bind(who.id)
    .first<{ public_key: string | null; locked_key: string | null }>();
  return c.json({
    ...who,
    vaultReady: !!row?.public_key,
    publicKey: row?.public_key ?? null,
    lockedKey: row?.locked_key ?? null,
  });
});

// Best effort: a missed stamp must not prevent the user from unlocking their vault.
me.post("/me/unlocked", async (c) => {
  const t = now();
  try {
    await c.env.DB.prepare(
      "UPDATE identity SET last_unlocked_at = ? WHERE id = ? AND (last_unlocked_at IS NULL OR last_unlocked_at <= ?)",
    )
      .bind(t, c.get("who").id, t - LAST_USED_EVERY)
      .run();
  } catch {
    // Writes can fail when D1 is over quota.
  }
  return c.json({ ok: true });
});

// First-time vault setup: the browser generates the key pair, locks the private key with the vault password, sends both.
me.post("/vault", async (c) => {
  const who = c.get("who");
  const b = await c.req.json<{ publicKey?: string; lockedKey?: string }>();
  if (!b.publicKey || !isPrivateKeyLock(b.lockedKey)) return c.json({ error: "bad request" }, 400);
  const res = await c.env.DB.prepare(
    "UPDATE identity SET public_key = ?, locked_key = ? WHERE id = ? AND public_key IS NULL",
  )
    .bind(b.publicKey, b.lockedKey, who.id)
    .run();
  if (!res.meta.changes) return c.json({ error: "vault already set up" }, 409);
  return c.json({ ok: true });
});

// ADR 20: change the vault password. The browser or CLI unlocks the private key with the old password and
// locks the same key with the new one. The server cannot check the old password or the key inside, so it
// checks the shape only. Group access is unchanged because the public key does not change.
me.put("/me/vault", async (c) => {
  const who = c.get("who");
  const b = await c.req
    .json<{ lockedKey?: unknown }>()
    .catch(() => ({}) as { lockedKey?: unknown });
  if (!isPrivateKeyLock(b.lockedKey)) return c.json({ error: "bad request" }, 400);
  const res = await c.env.DB.prepare(
    "UPDATE identity SET locked_key = ? WHERE id = ? AND public_key IS NOT NULL",
  )
    .bind(b.lockedKey, who.id)
    .run();
  if (!res.meta.changes) return c.json({ error: "set up your vault first" }, 409);
  await audit(c.env.DB, {
    who: who.name,
    action: "vault.password",
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ ok: true });
});

// ADR 20: the optional recovery key. Only the lock is stored; the 24 words stay with the person.
me.get("/me/recovery", async (c) => {
  const row = await c.env.DB.prepare(
    "SELECT recovery_locked_key AS lockedKey FROM identity WHERE id = ?",
  )
    .bind(c.get("who").id)
    .first<{ lockedKey: string | null }>();
  return c.json({ set: !!row?.lockedKey, lockedKey: row?.lockedKey ?? null });
});

me.put("/me/recovery", async (c) => {
  const who = c.get("who");
  const b = await c.req
    .json<{ lockedKey?: unknown }>()
    .catch(() => ({}) as { lockedKey?: unknown });
  if (!isRecoveryLockedKey(b.lockedKey)) return c.json({ error: "bad request" }, 400);
  const res = await c.env.DB.prepare(
    "UPDATE identity SET recovery_locked_key = ? WHERE id = ? AND public_key IS NOT NULL",
  )
    .bind(b.lockedKey, who.id)
    .run();
  if (!res.meta.changes) return c.json({ error: "set up your vault first" }, 409);
  await audit(c.env.DB, {
    who: who.name,
    action: "vault.recovery.set",
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ ok: true });
});
