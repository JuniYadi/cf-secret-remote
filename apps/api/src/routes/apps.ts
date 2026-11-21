import { Hono } from "hono";
import { audit } from "../audit.ts";
import { requireAdmin } from "../auth.ts";
import { normalizeAllowlist } from "../cidr.ts";
import type { AppEnv } from "../types.ts";
import { newId, newToken, now, sha256Hex } from "../util.ts";

// ADR 15: apps and bots. Only admins manage them. The browser or CLI makes the key pair and keeps the
// private key in the kit; only the public key reaches the server. secret_id is returned once, stored as a hash.
export const apps = new Hono<AppEnv>();
apps.use("/apps", requireAdmin);
apps.use("/apps/*", requireAdmin);

const DEFAULT_TTL = 3600; // token TTL, seconds
const MIN_TTL = 60;
const MAX_TTL = 24 * 3600;
const MAX_USES = 1_000_000_000;
const NAME_MAX = 80;
const SHOWN_ACTIVITY = 20;

interface AppRow {
  id: string;
  name: string;
  status: string;
  createdAt: number;
  owner: string | null;
  roleId: string;
  tokenTtl: number;
  maxUses: number | null;
  uses: number;
  cidr: string | null;
  expiresAt: number | null;
  firstLoginAt: number | null;
  lastLoginAt: number | null;
  lastIp: string | null;
}

const APP_SELECT = `SELECT i.id, i.name, i.status, i.created_at AS createdAt, o.name AS owner,
  a.role_id AS roleId, a.token_ttl AS tokenTtl, a.max_uses AS maxUses, a.uses, a.cidr,
  a.expires_at AS expiresAt, a.first_login_at AS firstLoginAt, a.last_login_at AS lastLoginAt,
  a.last_ip AS lastIp
  FROM identity i JOIN app_role a ON a.identity_id = i.id LEFT JOIN identity o ON o.id = i.owner_id
  WHERE i.kind = 'app'`;

// The public view. Never includes secret_id or its hash.
const view = (r: AppRow) => ({
  ...r,
  cidr: r.cidr ? r.cidr.split(",") : null,
  waiting: r.firstLoginAt === null,
});

const findApp = (db: D1Database, id: string) =>
  db.prepare(`${APP_SELECT} AND i.id = ?`).bind(id).first<AppRow>();

const isInt = (v: unknown, min: number, max: number): v is number =>
  typeof v === "number" && Number.isInteger(v) && v >= min && v <= max;

apps.post("/apps", async (c) => {
  const who = c.get("who");
  const b = await c.req
    .json<{
      name?: unknown;
      publicKey?: unknown;
      tokenTtl?: unknown;
      maxUses?: unknown;
      expiresAt?: unknown;
      cidr?: unknown;
    }>()
    .catch(() => null);
  if (!b) return c.json({ error: "bad request" }, 400);
  const name = typeof b.name === "string" ? b.name.trim() : "";
  const publicKey = typeof b.publicKey === "string" ? b.publicKey : "";
  if (!name || name.length > NAME_MAX || !/^[A-Za-z0-9_-]{20,200}$/.test(publicKey))
    return c.json({ error: "bad request" }, 400);

  const tokenTtl = b.tokenTtl === undefined ? DEFAULT_TTL : b.tokenTtl;
  if (!isInt(tokenTtl, MIN_TTL, MAX_TTL)) return c.json({ error: "bad token ttl" }, 400);
  const maxUses = b.maxUses === undefined || b.maxUses === null ? null : b.maxUses;
  if (maxUses !== null && !isInt(maxUses, 1, MAX_USES))
    return c.json({ error: "bad max uses" }, 400);
  const expiresAt = b.expiresAt === undefined || b.expiresAt === null ? null : b.expiresAt;
  if (expiresAt !== null && !isInt(expiresAt, now() + 1, Number.MAX_SAFE_INTEGER))
    return c.json({ error: "expiry must be in the future" }, 400);
  let cidr: string | null = null;
  if (b.cidr !== undefined && b.cidr !== null) {
    cidr = typeof b.cidr === "string" ? normalizeAllowlist(b.cidr) : null;
    if (!cidr) return c.json({ error: "bad network allowlist" }, 400);
  }

  const id = newId();
  const roleId = newId();
  const secretId = newToken("cfssid");
  try {
    await c.env.DB.batch([
      c.env.DB.prepare(
        "INSERT INTO identity (id, kind, name, role, public_key, owner_id, created_at) VALUES (?, 'app', ?, 'member', ?, ?, ?)",
      ).bind(id, name, publicKey, who.id, now()),
      c.env.DB.prepare(
        "INSERT INTO app_role (identity_id, role_id, secret_hash, token_ttl, max_uses, expires_at, cidr) VALUES (?, ?, ?, ?, ?, ?, ?)",
      ).bind(id, roleId, await sha256Hex(secretId), tokenTtl, maxUses, expiresAt, cidr),
    ]);
  } catch {
    return c.json({ error: "name already used" }, 409);
  }
  await audit(c.env.DB, { who: who.name, action: "app.create", note: name, result: "ok" });
  return c.json({ id, roleId, secretId }, 201);
});

apps.get("/apps", async (c) => {
  const rows = await c.env.DB.prepare(`${APP_SELECT} ORDER BY i.name`).all<AppRow>();
  return c.json(rows.results.map(view));
});

apps.get("/apps/:id", async (c) => {
  const db = c.env.DB;
  const row = await findApp(db, c.req.param("id"));
  if (!row) return c.json({ error: "not found" }, 404);
  const sessions = await db
    .prepare(
      "SELECT substr(token_hash, 1, 16) AS id, created_at AS createdAt, expires_at AS expiresAt FROM session WHERE identity_id = ? AND expires_at > ? ORDER BY created_at DESC",
    )
    .bind(row.id, now())
    .all();
  // Activity is the audit trail of this app: its own events, and refused logins under its role_id.
  const activity = await db
    .prepare(
      "SELECT entry FROM audit WHERE json_extract(entry, '$.who') IN (?, ?) ORDER BY seq DESC LIMIT ?",
    )
    .bind(row.name, `app:${row.roleId}`, SHOWN_ACTIVITY)
    .all<{ entry: string }>();
  return c.json({
    ...view(row),
    sessions: sessions.results,
    activity: activity.results.map(({ entry }) => {
      const e = JSON.parse(entry) as {
        at: number;
        action: string;
        result: string;
        ip?: string;
        note?: string;
      };
      return {
        at: e.at,
        action: e.action,
        result: e.result,
        ip: e.ip ?? null,
        note: e.note ?? null,
      };
    }),
  });
});

// Rotate secret_id: the new one is returned once. The old one stops working at once. The key pair is unchanged.
apps.post("/apps/:id/rotate", async (c) => {
  const who = c.get("who");
  const row = await findApp(c.env.DB, c.req.param("id"));
  if (!row) return c.json({ error: "not found" }, 404);
  const secretId = newToken("cfssid");
  await c.env.DB.prepare("UPDATE app_role SET secret_hash = ? WHERE identity_id = ?")
    .bind(await sha256Hex(secretId), row.id)
    .run();
  await audit(c.env.DB, { who: who.name, action: "app.rotate", note: row.name, result: "ok" });
  return c.json({ roleId: row.roleId, secretId });
});

// Disable: the identity can no longer log in, and its sessions end now.
apps.post("/apps/:id/disable", async (c) => {
  const who = c.get("who");
  const row = await findApp(c.env.DB, c.req.param("id"));
  if (!row) return c.json({ error: "not found" }, 404);
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE identity SET status = 'disabled' WHERE id = ?").bind(row.id),
    c.env.DB.prepare("DELETE FROM session WHERE identity_id = ?").bind(row.id),
  ]);
  await audit(c.env.DB, { who: who.name, action: "app.disable", note: row.name, result: "ok" });
  return c.json({ ok: true });
});
