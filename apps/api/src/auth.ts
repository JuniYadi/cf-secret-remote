import type { MiddlewareHandler } from "hono";
import { accessJwtFrom, sameOrigin, verifyAccessJwt } from "./access.ts";
import { audit } from "./audit.ts";
import type { AppEnv, Who } from "./types.ts";
import { newId, now, sha256Hex } from "./util.ts";

/** Seconds between two last-used stamps on one session. */
export const LAST_USED_EVERY = 600;

const ip = (c: { req: { header: (n: string) => string | undefined } }) =>
  c.req.header("CF-Connecting-IP");

/** Bearer `cfs_…` tokens (CLI, apps) are checked first; otherwise a Cloudflare Access JWT (browser). */
export const authenticate: MiddlewareHandler<AppEnv> = async (c, next) => {
  const db = c.env.DB;
  const bearer = c.req.header("Authorization")?.match(/^Bearer (cfs_\S+)$/)?.[1];
  let who: Who | null = null;

  if (bearer) {
    const tokenHash = await sha256Hex(bearer);
    const found = await db
      .prepare(
        `SELECT i.id, i.kind, i.name, i.role, s.last_used_at AS lastUsedAt
         FROM session s JOIN identity i ON i.id = s.identity_id
         WHERE s.token_hash = ? AND s.expires_at > ? AND i.status = 'active'`,
      )
      .bind(tokenHash, now())
      .first<Who & { lastUsedAt: number | null }>();
    if (found) {
      const { lastUsedAt, ...rest } = found;
      who = rest;
      // Stamped at most once per LAST_USED_EVERY seconds, so a busy CLI does not write on every call.
      const t = now();
      if (lastUsedAt === null || t - lastUsedAt >= LAST_USED_EVERY) {
        await db
          .prepare("UPDATE session SET last_used_at = ? WHERE token_hash = ?")
          .bind(t, tokenHash)
          .run()
          .catch(() => {}); // a missed stamp must never fail the request (e.g. over the write quota)
      }
    }
  } else {
    const found = accessJwtFrom(c.req);
    // A cookie can be sent by another site's page, so cookie logins may only change data from our own origin.
    const safe =
      !found ||
      found.via === "header" ||
      ["GET", "HEAD"].includes(c.req.method) ||
      sameOrigin({ header: (n) => c.req.header(n), url: c.req.url });
    if (found && !safe) {
      await audit(db, {
        who: "anonymous",
        action: "auth.denied",
        note: "cross-site cookie request",
        result: "denied",
        ip: ip(c),
      });
      return c.json({ error: "forbidden" }, 403);
    }
    const email = await verifyAccessJwt(c.env, found?.jwt);
    if (email) who = await upsertUser(c.env.DB, email, c.env.BOOTSTRAP_ADMIN_EMAIL);
  }

  if (!who) {
    await audit(db, { who: "anonymous", action: "auth.denied", result: "denied", ip: ip(c) });
    return c.json({ error: "unauthorized" }, 401);
  }
  c.set("who", who);
  await next();
};

async function upsertUser(db: D1Database, email: string, bootstrap: string): Promise<Who | null> {
  const found = await db
    .prepare("SELECT id, kind, name, role, status FROM identity WHERE kind = 'user' AND name = ?")
    .bind(email)
    .first<Who & { status: string }>();
  if (found) return found.status === "active" ? found : null;
  // Only the bootstrap admin may appear on first sight. Everyone else must be invited first.
  if (!bootstrap || email !== bootstrap.toLowerCase()) return null;
  const who: Who = { id: newId(), kind: "user", name: email, role: "admin" };
  await db
    .prepare(
      "INSERT INTO identity (id, kind, name, role, created_at) VALUES (?, 'user', ?, 'admin', ?)",
    )
    .bind(who.id, email, now())
    .run();
  return who;
}

export const requireAdmin: MiddlewareHandler<AppEnv> = async (c, next) => {
  if (c.get("who").role !== "admin") return c.json({ error: "admin only" }, 403);
  await next();
};
