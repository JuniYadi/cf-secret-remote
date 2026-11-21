import { Hono } from "hono";
import { audit } from "../audit.ts";
import { ipInRanges } from "../cidr.ts";
import { hit, safeEqual, spent } from "../throttle.ts";
import type { Env } from "../types.ts";
import { newToken, now, sha256Hex } from "../util.ts";

// ADR 15: at most 10 failed logins per role_id per 10 minutes, then 429 until the window ends.
const LOGIN_LIMIT = 10;
const LOGIN_WINDOW = 600;

// Public route (no auth middleware): an app proves itself with role_id + secret_id and gets a short-lived token.
export const approle = new Hono<{ Bindings: Env }>();

approle.post("/auth/approle/login", async (c) => {
  const b = await c.req
    .json<{ roleId?: string; secretId?: string }>()
    .catch(() => ({}) as { roleId?: string; secretId?: string });
  const ip = c.req.header("CF-Connecting-IP");
  const throttleKey = `approle:${b.roleId ?? ""}`;

  if (b.roleId && (await spent(c.env.DB, throttleKey, LOGIN_LIMIT, LOGIN_WINDOW)))
    return c.json({ error: "too many attempts" }, 429);

  // Every refusal counts toward the throttle and is audited with a reason. The response never says which check failed.
  const deny = async (note: string) => {
    if (b.roleId) await hit(c.env.DB, throttleKey, LOGIN_LIMIT, LOGIN_WINDOW);
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
    `SELECT a.identity_id, a.secret_hash, a.token_ttl, a.max_uses, a.cidr, a.expires_at, i.name, i.status
     FROM app_role a JOIN identity i ON i.id = a.identity_id WHERE a.role_id = ?`,
  )
    .bind(b.roleId)
    .first<{
      identity_id: string;
      secret_hash: string;
      token_ttl: number;
      max_uses: number | null;
      cidr: string | null;
      expires_at: number | null;
      name: string;
      status: string;
    }>();

  if (!r || !safeEqual(r.secret_hash, await sha256Hex(b.secretId))) return deny("bad secret");
  if (r.status !== "active") return deny("disabled");
  if (r.expires_at && r.expires_at < now()) return deny("expired");
  // Default deny: with an allowlist set, a missing or unlisted address is refused.
  if (r.cidr && !ipInRanges(ip, r.cidr.split(","))) return deny("network not allowed");

  // max_uses is enforced in the UPDATE itself, so two concurrent logins cannot both pass the check.
  const claimed = await c.env.DB.prepare(
    "UPDATE app_role SET uses = uses + 1 WHERE identity_id = ? AND (max_uses IS NULL OR uses < max_uses)",
  )
    .bind(r.identity_id)
    .run();
  if (!claimed.meta.changes) return deny("uses exhausted");

  const token = newToken("cfs");
  const at = now();
  await c.env.DB.batch([
    // first_login_at is set once; the UI shows "Waiting for first sign-in" until then.
    c.env.DB.prepare(
      "UPDATE app_role SET first_login_at = COALESCE(first_login_at, ?), last_login_at = ?, last_ip = ? WHERE identity_id = ?",
    ).bind(at, at, ip ?? null, r.identity_id),
    c.env.DB.prepare(
      "INSERT INTO session (token_hash, identity_id, kind, created_at, expires_at) VALUES (?, ?, 'app', ?, ?)",
    ).bind(await sha256Hex(token), r.identity_id, at, at + r.token_ttl),
  ]);
  await audit(c.env.DB, { who: r.name, action: "login.ok", result: "ok", ip });
  return c.json({ token, expiresIn: r.token_ttl });
});
