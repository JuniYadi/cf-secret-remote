import { unwrapGroupKey, wrapGroupKey } from "@cfs/core";
import { flag } from "../args.ts";
import { CliError, type Client, connect } from "../client.ts";
import type { Commands } from "./types.ts";

// ADR 16: access requests. `request` asks, `requests` lists, `approve` wraps the group key to the requester,
// `deny` refuses. The approver must hold the group key and be an admin; the server enforces both.

/** Longest grant the server accepts, in seconds (24 h). */
export const MAX_SECONDS = 86400;

const UNIT_SECONDS: Record<string, number> = { s: 1, m: 60, h: 3600 };

/** `2h`, `30m`, `90s` or a plain number of seconds. Returns null when it is not 1 s to 24 h. */
export function parseDuration(text: string): number | null {
  const m = text.match(/^(\d+)([smh]?)$/);
  if (!m) return null;
  const secs = Number(m[1]) * (UNIT_SECONDS[m[2] || "s"] ?? 1);
  return secs >= 1 && secs <= MAX_SECONDS ? secs : null;
}

interface AccessRequest {
  id: string;
  requesterId: string;
  requester: string;
  path: string;
  groupPrefix: string;
  reason: string;
  duration: number;
  rekeyAfter: boolean;
  status: string;
  approver: string | null;
  createdAt: number;
  decidedAt: number | null;
  expiresAt: number | null;
}

const errorOf = (body: unknown, status: number) =>
  (body as { error?: string })?.error ?? `status ${status}`;

/** Removes a bare switch such as --rekey from the arguments. */
function takeSwitch(args: string[], name: string): boolean {
  const i = args.indexOf(name);
  if (i < 0) return false;
  args.splice(i, 1);
  return true;
}

const USAGE_REQUEST =
  "Usage: cfs request <path> --reason <text> --for <duration> [--rekey]   (duration: 30m, 2h, max 24h)";

async function requestCmd(args: string[], hostFlag?: string) {
  const reason = flag(args, "--reason");
  const forText = flag(args, "--for");
  const rekey = takeSwitch(args, "--rekey");
  const path = args[0];
  if (!path || !reason?.trim() || !forText) throw new CliError(USAGE_REQUEST);
  const duration = parseDuration(forText);
  if (duration === null)
    throw new CliError("--for takes a duration from 1s to 24h, for example 30m or 2h.");

  const c = await connect(hostFlag);
  const r = await c.call<AccessRequest>("POST", "/requests", {
    path,
    reason,
    duration,
    rekeyAfter: rekey,
  });
  if (r.status !== 201)
    throw new CliError(`Could not send the request: ${errorOf(r.body, r.status)}`);
  console.log(
    `Request ${r.body.id} sent for ${path}, ${forText}. It stays pending until an admin in the group approves it.`,
  );
}

async function requestsCmd(hostFlag?: string) {
  const c = await connect(hostFlag);
  const r = await c.call<AccessRequest[]>("GET", "/requests");
  if (r.status !== 200) throw new CliError(`Could not list requests: ${errorOf(r.body, r.status)}`);
  if (r.body.length === 0) console.log("No requests.");
  for (const q of r.body)
    console.log(
      [
        q.id,
        q.status,
        q.requester,
        q.path,
        `${q.duration}s`,
        q.rekeyAfter ? "rekey-after" : "",
        q.reason,
      ].join("\t"),
    );
}

/** Loads a request by id, or throws a readable error. */
async function loadRequest(c: Client, id: string): Promise<AccessRequest> {
  const r = await c.call<AccessRequest>("GET", `/requests/${encodeURIComponent(id)}`);
  if (r.status === 404) throw new CliError(`No request ${id} that you can see.`);
  if (r.status !== 200) throw new CliError(`Could not load request: ${errorOf(r.body, r.status)}`);
  return r.body;
}

/**
 * Unwraps the approver's group key, wraps it to the requester's public key, and sends it with the approval.
 * The plaintext key stays in this process; the server receives only the wrapped copy.
 */
async function approveCmd(args: string[], hostFlag?: string) {
  const id = args[0];
  if (!id) throw new CliError("Usage: cfs approve <request-id>");
  const c = await connect(hostFlag);
  if (!c.privateKey) throw new CliError("Your vault is locked. Run: cfs unlock");

  const req = await loadRequest(c, id);
  if (req.status !== "pending") throw new CliError(`This request is already ${req.status}.`);

  const [me, people, mine] = await Promise.all([
    c.call<{ publicKey: string | null }>("GET", "/whoami"),
    c.call<{ id: string; publicKey: string | null }[]>("GET", "/identities"),
    c.call<{ wrappedKey: string; version: number }>(
      "GET",
      `/keyrings/${encodeURIComponent(req.groupPrefix)}/key`,
    ),
  ]);
  if (people.status === 403) throw new CliError("Only admins can approve requests.");
  if (mine.status === 404)
    throw new CliError(
      `You are not in the "${req.groupPrefix}" group, so you cannot approve this.`,
    );
  if (mine.status !== 200 || !me.body.publicKey)
    throw new CliError(
      `Could not load the "${req.groupPrefix}" key: ${errorOf(mine.body, mine.status)}`,
    );
  const requester = people.body.find((p) => p.id === req.requesterId);
  if (!requester?.publicKey) throw new CliError(`${req.requester} has not set up a vault yet.`);

  const groupKey = await unwrapGroupKey(
    mine.body.wrappedKey,
    c.privateKey,
    me.body.publicKey,
    req.groupPrefix,
    mine.body.version,
  );
  const wrappedKey = await wrapGroupKey(
    groupKey,
    requester.publicKey,
    req.groupPrefix,
    mine.body.version,
  );
  const r = await c.call<AccessRequest>("POST", `/requests/${encodeURIComponent(id)}/approve`, {
    wrappedKey,
    version: mine.body.version,
  });
  if (r.status !== 200) throw new CliError(`Could not approve: ${errorOf(r.body, r.status)}`);
  console.log(
    `Approved ${req.requester} for ${req.path} until ${new Date((r.body.expiresAt ?? 0) * 1000).toISOString()}.`,
  );
}

async function denyCmd(args: string[], hostFlag?: string) {
  const id = args[0];
  if (!id) throw new CliError("Usage: cfs deny <request-id>");
  const c = await connect(hostFlag);
  const r = await c.call<AccessRequest>("POST", `/requests/${encodeURIComponent(id)}/deny`);
  if (r.status !== 200) throw new CliError(`Could not deny: ${errorOf(r.body, r.status)}`);
  console.log(`Denied ${r.body.requester} for ${r.body.path}.`);
}

export const request: Commands = {
  request: {
    help: "cfs request <path> --reason <text> --for <duration> [--rekey]",
    run: (a, h) => requestCmd(a, h),
  },
  requests: {
    help: "cfs requests",
    run: (_a, h) => requestsCmd(h),
  },
  approve: {
    help: "cfs approve <request-id>",
    run: (a, h) => approveCmd(a, h),
  },
  deny: {
    help: "cfs deny <request-id>",
    run: (a, h) => denyCmd(a, h),
  },
};
