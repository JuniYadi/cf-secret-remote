import { type Context, Hono } from "hono";
import { audit } from "../audit.ts";
import { requireAdmin } from "../auth.ts";
import { prefixOf, validPath } from "../policy.ts";
import {
  approveRequest,
  cancelRequest,
  createRequest,
  denyRequest,
  findApprovalGroup,
  findApprovalMembership,
  findRequester,
  findRequestGroup,
  listRequests,
  loadRequest,
  type RequestRow,
} from "../repository/requests.ts";
import { notifyAccessRequest } from "../requests-notify.ts";
import { REQUEST_TTL } from "../requests-sweep.ts";
import type { AppEnv } from "../types.ts";
import { newId, now } from "../util.ts";

// ADR 16. Access requests with approval. The server stores the requester's wrapped group key and the
// time-boxed grant; it never sees a group key or a value in clear. Every state change is audited.

/** Longest grant, in seconds (24 h). The admin setting from ADR 16 is not built yet, so this is fixed. */
export const MAX_DURATION = 86400;
const MAX_REASON = 500;
const STATUSES = ["pending", "approved", "denied", "cancelled", "expired"] as const;

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
  const group = await findRequestGroup(db, prefix);
  if (!group) return c.json({ error: "no such group" }, 404);

  const id = newId();
  await createRequest(
    db,
    id,
    who.id,
    b.path,
    prefix,
    b.reason,
    b.duration,
    b.rekeyAfter === true ? 1 : 0,
    now(),
  );
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
  const rows = await listRequests(c.env.DB, who.role, who.id, status);
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
  const done = await cancelRequest(db, now(), row.id);
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
  const done = await denyRequest(db, who.id, t, row.id);
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

  const group = await findApprovalGroup(db, row.groupPrefix);
  if (!group) return c.json({ error: "no such group" }, 404);
  if (group.status !== "active")
    return c.json({ error: "group is rotating, try again later" }, 409);

  // The approver must hold the group key at the current version, and that grant must not have lapsed.
  const mine = await findApprovalMembership(db, group.id, who.id, group.version, t);
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

  const requester = await findRequester(db, row.requesterId);
  if (requester?.status !== "active") return c.json({ error: "requester is disabled" }, 409);

  const expiresAt = t + row.duration;
  const policyId = newId();
  // Every statement after the first is guarded by the request now being approved by this approver.
  // The batch is one transaction, so a grant is never written without the approval, or the reverse.
  const results = await approveRequest(db, row, who.id, t, expiresAt, policyId, group, wrappedKey);
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
