import { Hono } from "hono";
import { audit } from "../audit.ts";
import { hit } from "../throttle.ts";
import type { AppEnv, Env } from "../types.ts";
import { newToken, now, sha256Hex } from "../util.ts";

const TOKEN_TTL = 8 * 3600;
const CODE_TTL = 600;
const ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"; // no look-alike characters

function userCode(): string {
  const r = crypto.getRandomValues(new Uint8Array(8));
  const s = Array.from(r, (b) => ALPHABET[b % ALPHABET.length]).join("");
  return `${s.slice(0, 4)}-${s.slice(4)}`;
}

// Public: the CLI starts a login and polls for the result.
export const cliPublic = new Hono<{ Bindings: Env }>();

cliPublic.post("/cli/start", async (c) => {
  const b = await c.req.json<{ device?: string }>().catch(() => ({}) as { device?: string });
  const deviceCode = newToken("cfsdev");
  const code = userCode();
  await c.env.DB.prepare(
    "INSERT INTO cli_login (device_hash, user_code, device, expires_at) VALUES (?, ?, ?, ?)",
  )
    .bind(await sha256Hex(deviceCode), code, (b.device ?? "").slice(0, 80), now() + CODE_TTL)
    .run();
  return c.json({ deviceCode, userCode: code, expiresIn: CODE_TTL, interval: 2 });
});

cliPublic.post("/cli/poll", async (c) => {
  const b = await c.req
    .json<{ deviceCode?: string }>()
    .catch(() => ({}) as { deviceCode?: string });
  if (!b.deviceCode) return c.json({ error: "bad request" }, 400);
  const hash = await sha256Hex(b.deviceCode);
  // ADR 27: about one poll per 2 seconds, with some slack
  if (!(await hit(c.env.DB, `cli-poll:${hash}`, 40, 60)))
    return c.json({ error: "slow down" }, 429);
  const row = await c.env.DB.prepare(
    "SELECT l.status, l.identity_id, l.device, l.expires_at, i.name FROM cli_login l LEFT JOIN identity i ON i.id = l.identity_id WHERE l.device_hash = ?",
  )
    .bind(hash)
    .first<{
      status: string;
      identity_id: string | null;
      device: string;
      expires_at: number;
      name: string | null;
    }>();
  if (!row || row.expires_at < now() || row.status === "used")
    return c.json({ error: "expired" }, 410);
  if (row.status === "pending" || !row.identity_id) return c.json({ status: "pending" }, 202);

  // Mark used first, so a replayed poll cannot mint a second token.
  const claimed = await c.env.DB.prepare(
    "UPDATE cli_login SET status = 'used' WHERE device_hash = ? AND status = 'approved'",
  )
    .bind(hash)
    .run();
  if (!claimed.meta.changes) return c.json({ error: "expired" }, 410);
  const token = newToken("cfs");
  await c.env.DB.prepare(
    "INSERT INTO session (token_hash, identity_id, kind, device, created_at, expires_at) VALUES (?, ?, 'cli', ?, ?, ?)",
  )
    .bind(await sha256Hex(token), row.identity_id, row.device, now(), now() + TOKEN_TTL)
    .run();
  await audit(c.env.DB, {
    who: row.name ?? row.identity_id,
    action: "login.ok",
    note: `cli ${row.device}`,
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ token, expiresIn: TOKEN_TTL });
});

// Authenticated (Access in the browser): the person approves the code shown in their terminal.
export const cliApprove = new Hono<AppEnv>();

cliApprove.post("/cli/approve", async (c) => {
  const who = c.get("who");
  if (who.kind !== "user") return c.json({ error: "people only" }, 403);
  const b = await c.req.json<{ userCode?: string }>().catch(() => ({}) as { userCode?: string });
  // ADR 27: 5 wrong codes per person per 10 minutes
  if (!(await hit(c.env.DB, `cli-approve:${who.id}`, 5, 600)))
    return c.json({ error: "too many attempts" }, 429);
  const res = await c.env.DB.prepare(
    "UPDATE cli_login SET status = 'approved', identity_id = ? WHERE user_code = ? AND status = 'pending' AND expires_at > ?",
  )
    .bind(who.id, (b.userCode ?? "").trim().toUpperCase(), now())
    .run();
  if (!res.meta.changes) return c.json({ error: "code not found or expired" }, 404);
  await audit(c.env.DB, {
    who: who.name,
    action: "cli.approve",
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ ok: true });
});
