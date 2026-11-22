import { type Context, Hono } from "hono";
import { audit } from "../audit.ts";
import { requireAdmin } from "../auth.ts";
import { prefixOf, validPath } from "../policy.ts";
import { notifyAccessRequest } from "../requests-notify.ts";
import { REQUEST_TTL } from "../requests-sweep.ts";
import type { AppEnv } from "../types.ts";
import { newId, now } from "../util.ts";

// ADR 16. Access requests with approval. The server stores the requester's wrapped group key and the
// time-boxed grant; it never sees a group key or a value in clear. Every state change is audited.

/** Longest grant, in seconds (24 h). The admin setting from ADR 16 is not built yet, so this is fixed. */
export const MAX_DURATION = 86400;
const MAX_REASON = 500;
const LIST_LIMIT = 200;
const STATUSES = ["pending", "approved", "denied", "cancelled", "expired"] as const;
type Status = (typeof STATUSES)[number];

/** The caller can read the request: an admin, or the requester. */
const RequestCols = `SELECT r.id, r.requester_id AS requesterId, q.name AS requester,
  r.path_glob AS path, r.group_prefix AS groupPrefix, r.reason, r.duration,
  r.rekey_after AS rekeyAfter, r.status, a.name AS approver, r.created_at AS createdAt,
  r.decided_at AS decidedAt, r.expires_at AS expiresAt
  FROM access_request r JOIN identity q ON q.id = r.requester_id
  LEFT JOIN identity a ON a.id = r.approver_id`;

interface RequestRow {
  id: string;
  requesterId: string;
  requester: string;
  path: string;
  groupPrefix: string;
  reason: string;
  duration: number;
  rekeyAfter: number;
  status: Status;
  approver: string | null;
  createdAt: number;
  decidedAt: number | null;
  expiresAt: number | null;
}

const loadRequest = (db: D1Database, id: string) =>
  db.prepare(`${RequestCols} WHERE r.id = ?`).bind(id).first<RequestRow>();

/** The view sent to clients. `rekeyAfter` is a flag for the client; the server does not rotate. */
const view = (r: RequestRow) => ({ ...r, rekeyAfter: r.rekeyAfter === 1 });

/** A pending request past its 24 h window is no longer decidable. The sweep records it as expired. */
const overdue = (r: RequestRow, t: number) =>
  r.status === "pending" && r.createdAt <= t - REQUEST_TTL;

const isStr = (v: unknown): v is string => typeof v === "string" && v.length > 0;

/** Glob paths are allowed in a request (for example `payments/*`), but the group (first segment) must be literal. */
function validRequestPath(path: string): boolean {
  return validPath(path.replace(/\*/g, "x")) && !prefixOf(path).includes("*");
}

export const requests = new Hono<AppEnv>();

// Create. Any active identity may ask for access to a path in an existing group.
requests.post("/requests", async (c) => {
  const db = c.env.DB;
  const who = c.get("who");
  const b = await c.req.json<{
    path?: unknown;
    reason?: unknown;
    duration?: unknown;
    rekeyAfter?: unknown;
  }>();
  if (!isStr(b.path) || !validRequestPath(b.path)) return c.json({ error: "bad path" }, 400);
  if (!isStr(b.reason) || b.reason.trim().length === 0 || b.reason.length > MAX_REASON)
    return c.json({ error: `reason is required, up to ${MAX_REASON} characters` }, 400);
  if (
    typeof b.duration !== "number" ||
    !Number.isInteger(b.duration) ||
    b.duration < 1 ||
    b.duration > MAX_DURATION
  )
    return c.json({ error: "duration must be between 1 second and 24 hours" }, 400);
  if (b.rekeyAfter !== undefined && typeof b.rekeyAfter !== "boolean")
    return c.json({ error: "rekeyAfter must be true or false" }, 400);

  const prefix = prefixOf(b.path);
  const group = await db
    .prepare("SELECT id FROM keyring WHERE prefix = ? AND personal_owner IS NULL")
    .bind(prefix)
    .first<{ id: string }>();
  if (!group) return c.json({ error: "no such group" }, 404);

  const id = newId();
  await db
    .prepare(
      `INSERT INTO access_request (id, requester_id, path_glob, group_prefix, reason, duration,
         rekey_after, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)`,
    )
    .bind(id, who.id, b.path, prefix, b.reason, b.duration, b.rekeyAfter === true ? 1 : 0, now())
    .run();
  await audit(db, {
    who: who.name,
    action: "request.create",
    path: b.path,
    note: `request ${id}`,
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  const row = await loadRequest(db, id);
  if (row)
    await notifyAccessRequest(c.env, {
      id,
      requester: who.name,
      path: b.path,
      reason: b.reason,
      duration: b.duration,
    });
  return c.json(row ? view(row) : { id }, 201);
});

// List. Admins see every request, anyone else sees their own. `?status=pending` filters.
requests.get("/requests", async (c) => {
  const who = c.get("who");
  const status = c.req.query("status");
  if (status !== undefined && !(STATUSES as readonly string[]).includes(status))
    return c.json({ error: "bad status" }, 400);
  const where: string[] = [];
  const binds: unknown[] = [];
  if (who.role !== "admin") {
    where.push("r.requester_id = ?");
    binds.push(who.id);
  }
  if (status) {
    where.push("r.status = ?");
    binds.push(status);
  }
  const sql = `${RequestCols}${where.length ? ` WHERE ${where.join(" AND ")}` : ""}
    ORDER BY r.created_at DESC LIMIT ${LIST_LIMIT}`;
  const rows = await c.env.DB.prepare(sql)
    .bind(...binds)
    .all<RequestRow>();
  return c.json(rows.results.map(view));
});

// One request. Admins and the requester only; anyone else gets 404 so existence is not revealed.
requests.get("/requests/:id", async (c) => {
  const who = c.get("who");
  const row = await loadRequest(c.env.DB, c.req.param("id") ?? "");
  if (!row || (who.role !== "admin" && row.requesterId !== who.id))
    return c.json({ error: "not found" }, 404);
  return c.json(view(row));
});

/** Loads the request named in the path, or returns the response to send. */
async function loadForAction(c: Context<AppEnv>): Promise<{ row: RequestRow } | { res: Response }> {
  const row = await loadRequest(c.env.DB, c.req.param("id") ?? "");
  if (!row) return { res: c.json({ error: "not found" }, 404) };
  return { row };
}

// Cancel. Only the requester, and only while pending.
requests.post("/requests/:id/cancel", async (c) => {
  const db = c.env.DB;
  const who = c.get("who");
  const found = await loadForAction(c);
  if ("res" in found) return found.res;
  const { row } = found;
  if (row.requesterId !== who.id) {
    await audit(db, {
      who: who.name,
      action: "request.cancel",
      path: row.path,
      note: `request ${row.id}`,
      result: "denied",
      ip: c.req.header("CF-Connecting-IP"),
    });
    return c.json({ error: "only the requester can cancel" }, 403);
  }
  if (row.status !== "pending") return c.json({ error: `already ${row.status}` }, 409);
  if (overdue(row, now())) return c.json({ error: "request has expired" }, 409);
  const done = await db
    .prepare(
      "UPDATE access_request SET status = 'cancelled', decided_at = ? WHERE id = ? AND status = 'pending'",
    )
    .bind(now(), row.id)
    .run();
  if (done.meta.changes !== 1) return c.json({ error: "already decided, reload" }, 409);
  await audit(db, {
    who: who.name,
    action: "request.cancel",
    path: row.path,
    note: `request ${row.id}`,
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json(view((await loadRequest(db, row.id)) as RequestRow));
});

// Deny. Admins only. Requesters withdraw with cancel, not deny.
requests.post("/requests/:id/deny", requireAdmin, async (c) => {
  const db = c.env.DB;
  const who = c.get("who");
  const found = await loadForAction(c);
  if ("res" in found) return found.res;
  const { row } = found;
  if (row.requesterId === who.id)
    return c.json({ error: "use cancel to withdraw your own request" }, 403);
  if (row.status !== "pending") return c.json({ error: `already ${row.status}` }, 409);
  if (overdue(row, now())) return c.json({ error: "request has expired" }, 409);
  const t = now();
  const done = await db
    .prepare(
      "UPDATE access_request SET status = 'denied', approver_id = ?, decided_at = ? WHERE id = ? AND status = 'pending'",
    )
    .bind(who.id, t, row.id)
    .run();
  if (done.meta.changes !== 1) return c.json({ error: "already decided, reload" }, 409);
  await audit(db, {
    who: who.name,
    action: "request.deny",
    path: row.path,
    note: `request ${row.id} by ${row.requester}`,
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json(view((await loadRequest(db, row.id)) as RequestRow));
});

// Approve. An admin who holds the group key approves. The client wraps the group key to the requester's
// public key and sends it here; the server stores it with the grant's expiry and never unwraps it.
requests.post("/requests/:id/approve", requireAdmin, async (c) => {
  const db = c.env.DB;
  const who = c.get("who");
  const ip = c.req.header("CF-Connecting-IP");
  const b = await c.req.json<{ wrappedKey?: unknown; version?: unknown }>();
  if (!isStr(b.wrappedKey) || !Number.isInteger(b.version))
    return c.json({ error: "bad request" }, 400);
  const wrappedKey = b.wrappedKey;

  const found = await loadForAction(c);
  if ("res" in found) return found.res;
  const { row } = found;

  if (row.requesterId === who.id) {
    await audit(db, {
      who: who.name,
      action: "request.approve",
      path: row.path,
      note: `request ${row.id}: self-approval refused`,
      result: "denied",
      ip,
    });
    return c.json({ error: "you cannot approve your own request" }, 403);
  }
  if (row.status !== "pending") return c.json({ error: `already ${row.status}` }, 409);
  const t = now();
  if (overdue(row, t)) return c.json({ error: "request has expired" }, 409);

  const group = await db
    .prepare("SELECT id, version, status FROM keyring WHERE prefix = ? AND personal_owner IS NULL")
    .bind(row.groupPrefix)
    .first<{ id: string; version: number; status: string }>();
  if (!group) return c.json({ error: "no such group" }, 404);
  if (group.status !== "active")
    return c.json({ error: "group is rotating, try again later" }, 409);

  // The approver must hold the group key at the current version, and that grant must not have lapsed.
  const mine = await db
    .prepare(
      `SELECT 1 AS ok FROM keyring_member WHERE keyring_id = ? AND identity_id = ? AND version = ?
       AND (expires_at IS NULL OR expires_at > ?)`,
    )
    .bind(group.id, who.id, group.version, t)
    .first();
  if (!mine) {
    await audit(db, {
      who: who.name,
      action: "request.approve",
      path: row.path,
      note: `request ${row.id}: approver is not in the group`,
      result: "denied",
      ip,
    });
    return c.json({ error: "you are not in this group" }, 403);
  }
  if (b.version !== group.version)
    return c.json({ error: "group key changed, reload and retry" }, 409);

  const requester = await db
    .prepare("SELECT status FROM identity WHERE id = ?")
    .bind(row.requesterId)
    .first<{ status: string }>();
  if (requester?.status !== "active") return c.json({ error: "requester is disabled" }, 409);

  const expiresAt = t + row.duration;
  const policyId = newId();
  // Every statement after the first is guarded by the request now being approved by this approver.
  // The batch is one transaction, so a grant is never written without the approval, or the reverse.
  const guard = `EXISTS (SELECT 1 FROM access_request WHERE id = ? AND status = 'approved' AND approver_id = ? AND decided_at = ?)`;
  const guardBinds = [row.id, who.id, t];
  const rules = JSON.stringify([{ path: row.path, caps: ["read", "list"] }]);
  const results = await db.batch([
    db
      .prepare(
        `UPDATE access_request SET status = 'approved', approver_id = ?, decided_at = ?, expires_at = ?
         WHERE id = ? AND status = 'pending'
         AND EXISTS (SELECT 1 FROM keyring WHERE id = ? AND version = ? AND status = 'active')`,
      )
      .bind(who.id, t, expiresAt, row.id, group.id, group.version),
    db
      .prepare(`INSERT INTO policy (id, name, rules) SELECT ?, ?, ? WHERE ${guard}`)
      .bind(policyId, `request:${row.id}`, rules, ...guardBinds),
    db
      .prepare(
        `INSERT INTO identity_policy (identity_id, policy_id, expires_at) SELECT ?, ?, ? WHERE ${guard}`,
      )
      .bind(row.requesterId, policyId, expiresAt, ...guardBinds),
    // A permanent membership is left alone. A lapsed or missing one is replaced by the time-boxed key.
    db
      .prepare(
        `INSERT OR IGNORE INTO keyring_member (keyring_id, identity_id, version, wrapped_key, expires_at)
         SELECT ?, ?, ?, ?, ? WHERE ${guard}`,
      )
      .bind(group.id, row.requesterId, group.version, wrappedKey, expiresAt, ...guardBinds),
    db
      .prepare(
        `UPDATE keyring_member SET wrapped_key = ?, expires_at = ?
         WHERE keyring_id = ? AND identity_id = ? AND version = ? AND expires_at IS NOT NULL AND ${guard}`,
      )
      .bind(wrappedKey, expiresAt, group.id, row.requesterId, group.version, ...guardBinds),
  ]);
  const applied = results[0]?.meta.changes === 1;
  const after = await loadRequest(db, row.id);
  if (!applied || after?.status !== "approved" || after.approver !== who.name)
    return c.json({ error: "already decided, reload" }, 409);

  await audit(db, {
    who: who.name,
    action: "request.approve",
    path: row.path,
    version: group.version,
    note: `request ${row.id} for ${row.requester}, until ${new Date(expiresAt * 1000).toISOString()}`,
    result: "ok",
    ip,
  });
  return c.json(view(after));
});
