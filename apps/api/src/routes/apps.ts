import { Hono } from "hono";
import { audit } from "../audit.ts";
import { requireAdmin } from "../auth.ts";
import { normalizeAllowlist } from "../cidr.ts";
import {
  type AppRow,
  appActivity,
  appSessions,
  createApp,
  disableApp,
  findApp,
  listApps,
  rotateApp,
} from "../repository/apps.ts";
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

// The public view. Never includes secret_id or its hash.
const view = (r: AppRow) => ({
  ...r,
  cidr: r.cidr ? r.cidr.split(",") : null,
  waiting: r.firstLoginAt === null,
});

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
    await createApp(c.env.DB, {
      id,
      name,
      publicKey,
      owner: who.id,
      at: now(),
      roleId,
      secretHash: await sha256Hex(secretId),
      tokenTtl,
      maxUses,
      expiresAt,
      cidr,
    });
  } catch {
    return c.json({ error: "name already used" }, 409);
  }
  await audit(c.env.DB, {
    who: who.name,
    actor: who,
    action: "app.create",
    note: name,
    result: "ok",
  });
  return c.json({ id, roleId, secretId }, 201);
});

apps.get("/apps", async (c) => {
  const rows = await listApps(c.env.DB);
  return c.json(rows.map(view));
});

apps.get("/apps/:id", async (c) => {
  const db = c.env.DB;
  const row = await findApp(db, c.req.param("id"));
  if (!row) return c.json({ error: "not found" }, 404);
  const sessions = await appSessions(db, row.id, now());
  // Activity is the audit trail of this app: its own events, and refused logins under its role_id.
  const activity = await appActivity(db, row.id, row.name, row.roleId, SHOWN_ACTIVITY);
  return c.json({
    ...view(row),
    sessions,
    activity: activity.map(({ entry }) => {
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
  await rotateApp(c.env.DB, await sha256Hex(secretId), row.id);
  await audit(c.env.DB, {
    who: who.name,
    actor: who,
    action: "app.rotate",
    note: row.name,
    result: "ok",
  });
  return c.json({ roleId: row.roleId, secretId });
});

// Disable: the identity can no longer log in, and its sessions end now.
apps.post("/apps/:id/disable", async (c) => {
  const who = c.get("who");
  const row = await findApp(c.env.DB, c.req.param("id"));
  if (!row) return c.json({ error: "not found" }, 404);
  await disableApp(c.env.DB, row.id);
  await audit(c.env.DB, {
    who: who.name,
    actor: who,
    action: "app.disable",
    note: row.name,
    result: "ok",
  });
  return c.json({ ok: true });
});
