import { Hono } from "hono";
import { audit } from "../audit.ts";
import type { Env } from "../types.ts";
import { newToken, now, sha256Hex } from "../util.ts";

// Public route (no auth middleware): an app proves itself with role_id + secret_id and gets a short-lived token.
export const approle = new Hono<{ Bindings: Env }>();

approle.post("/auth/approle/login", async (c) => {
  const b = await c.req
    .json<{ roleId?: string; secretId?: string }>()
    .catch(() => ({}) as { roleId?: string; secretId?: string });
  const ip = c.req.header("CF-Connecting-IP");
  const deny = async (note: string) => {
    await audit(c.env.DB, {
      who: `app:${b.roleId ?? "?"}`,
      action: "login.denied",
      note,
      result: "denied",
      ip,
    });
    return c.json({ error: "invalid credentials" }, 401);
  };
  if (!b.roleId || !b.secretId) return deny("missing");

  const r = await c.env.DB.prepare(
    `SELECT a.identity_id, a.secret_hash, a.token_ttl, a.max_uses, a.uses, a.cidr, a.expires_at, i.name, i.status
     FROM app_role a JOIN identity i ON i.id = a.identity_id WHERE a.role_id = ?`,
  )
    .bind(b.roleId)
    .first<{
      identity_id: string;
      secret_hash: string;
      token_ttl: number;
      max_uses: number | null;
      uses: number;
      cidr: string | null;
      expires_at: number | null;
      name: string;
      status: string;
    }>();

  if (!r || r.status !== "active" || r.secret_hash !== (await sha256Hex(b.secretId)))
    return deny("bad secret");
  if (r.expires_at && r.expires_at < now()) return deny("expired");
  if (r.max_uses !== null && r.uses >= r.max_uses) return deny("uses exhausted");
  // CIDR support is exact-IP for now. Ranges come later.
  if (
    r.cidr &&
    !r.cidr
      .split(",")
      .map((s) => s.trim())
      .includes(ip ?? "")
  )
    return deny("network not allowed");

  const token = newToken("cfs");
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE app_role SET uses = uses + 1 WHERE identity_id = ?").bind(
      r.identity_id,
    ),
    c.env.DB.prepare(
      "INSERT INTO session (token_hash, identity_id, kind, created_at, expires_at) VALUES (?, ?, 'app', ?, ?)",
    ).bind(await sha256Hex(token), r.identity_id, now(), now() + r.token_ttl),
  ]);
  await audit(c.env.DB, { who: r.name, action: "login.ok", result: "ok", ip });
  return c.json({ token, expiresIn: r.token_ttl });
});
