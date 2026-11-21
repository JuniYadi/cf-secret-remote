import { Hono } from "hono";
import type { AppEnv } from "../types.ts";

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

// First-time vault setup: the browser generates the key pair, locks the private key with the vault password, sends both.
me.post("/vault", async (c) => {
  const who = c.get("who");
  const b = await c.req.json<{ publicKey?: string; lockedKey?: string }>();
  if (!b.publicKey || !b.lockedKey || !b.lockedKey.startsWith("p1."))
    return c.json({ error: "bad request" }, 400);
  const res = await c.env.DB.prepare(
    "UPDATE identity SET public_key = ?, locked_key = ? WHERE id = ? AND public_key IS NULL",
  )
    .bind(b.publicKey, b.lockedKey, who.id)
    .run();
  if (!res.meta.changes) return c.json({ error: "vault already set up" }, 409);
  return c.json({ ok: true });
});
