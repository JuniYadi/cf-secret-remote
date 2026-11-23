import { Hono } from "hono";
import { audit } from "../audit.ts";
import {
  approveCliLogin,
  claimCliLogin,
  createCliSession,
  findCliLogin,
  findPendingCliLogin,
  startCliLogin,
} from "../repository/identity.ts";
import { attemptsLeft, hit, spent } from "../throttle.ts";
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
  const b = await c.req
    .json<{ device?: string; device_type?: string }>()
    .catch(() => ({}) as { device?: string; device_type?: string });
  if (b.device_type !== undefined && b.device_type !== "cli" && b.device_type !== "extension")
    return c.json({ error: "bad request" }, 400);
  const deviceCode = newToken("cfsdev");
  const code = userCode();
  await startCliLogin(
    c.env.DB,
    await sha256Hex(deviceCode),
    code,
    (b.device ?? "").slice(0, 80),
    now() + CODE_TTL,
    b.device_type ?? "cli",
  );
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
  const row = await findCliLogin(c.env.DB, hash);
  if (!row || row.expires_at < now() || row.status === "used")
    return c.json({ error: "expired" }, 410);
  if (row.status === "pending" || !row.identity_id) return c.json({ status: "pending" }, 202);

  // Mark used first, so a replayed poll cannot mint a second token.
  const claimed = await claimCliLogin(c.env.DB, hash);
  if (!claimed) return c.json({ error: "expired" }, 410);
  const token = newToken("cfs");
  await createCliSession(
    c.env.DB,
    await sha256Hex(token),
    row.identity_id,
    row.device,
    now(),
    now() + TOKEN_TTL,
  );
  await audit(c.env.DB, {
    who: row.name ?? row.identity_id,
    actor: { id: row.identity_id, kind: "user" },
    action: "login.ok",
    note: `cli ${row.device}`,
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ token, expiresIn: TOKEN_TTL });
});

// Authenticated (Access in the browser): the person approves the code shown in their terminal.
export const cliApprove = new Hono<AppEnv>();

// ADR 27: 5 wrong codes per person per 10 minutes. Every approve call counts, and a 404 says how many are left.
const CODE_LIMIT = 5;
const CODE_WINDOW = 600;

/** The code as typed or shown: upper case, hyphen after four characters. Other inputs are only upper-cased. */
export function normalizeUserCode(raw: string): string {
  const s = raw.toUpperCase().replace(/[^A-Z0-9]/g, "");
  return s.length === 8 ? `${s.slice(0, 4)}-${s.slice(4)}` : raw.trim().toUpperCase();
}

// Shows the browser the device name before the person approves. A miss counts toward the same limit.
cliApprove.get("/cli/login", async (c) => {
  const who = c.get("who");
  if (who.kind !== "user") return c.json({ error: "people only" }, 403);
  const key = `cli-approve:${who.id}`;
  if (await spent(c.env.DB, key, CODE_LIMIT, CODE_WINDOW))
    return c.json({ error: "too many attempts" }, 429);
  const code = normalizeUserCode(c.req.query("code") ?? "");
  const row = await findPendingCliLogin(c.env.DB, code, now());
  if (!row) {
    const left = await attemptsLeft(c.env.DB, key, CODE_LIMIT, CODE_WINDOW);
    return c.json({ error: "code not found or expired", attemptsLeft: Math.max(0, left) }, 404);
  }
  return c.json({
    userCode: code,
    device: row.device,
    deviceType: row.deviceType,
    expiresAt: row.expiresAt,
  });
});

cliApprove.post("/cli/approve", async (c) => {
  const who = c.get("who");
  if (who.kind !== "user") return c.json({ error: "people only" }, 403);
  const b = await c.req.json<{ userCode?: string }>().catch(() => ({}) as { userCode?: string });
  const left = await attemptsLeft(c.env.DB, `cli-approve:${who.id}`, CODE_LIMIT, CODE_WINDOW);
  if (left < 0) return c.json({ error: "too many attempts" }, 429);
  const res = await approveCliLogin(c.env.DB, who.id, normalizeUserCode(b.userCode ?? ""), now());
  if (!res) return c.json({ error: "code not found or expired", attemptsLeft: left }, 404);
  await audit(c.env.DB, {
    who: who.name,
    actor: who,
    action: "cli.approve",
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  await audit(c.env.DB, {
    who: who.name,
    actor: who,
    action: "login.ok",
    note: "cli approval",
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ ok: true });
});
