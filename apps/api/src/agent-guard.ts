import { audit } from "./audit.ts";
import { globMatch } from "./policy.ts";
import { hit } from "./throttle.ts";
import type { Who } from "./types.ts";
import { now } from "./util.ts";

// ADR 17. Server side of the agent proxy. Every secret read by an identity that has agent rules for that
// path goes through agentGuard: reason, approval for */prod, and the per-hour read budget. Refusals are audited.
// The proxy never gets to skip these checks, because the proxy only ever reads through GET /secret.

/** The budget window. Reads are counted per alias in fixed one-hour windows. */
export const BUDGET_WINDOW = 3600;
/** Paths matching this glob need an approved access request for an app with require_approval (ADR 16, 17). */
export const PROD_GLOB = "*/prod";
const MAX_REASON_NOTE = 200;

/** A rule as read from agent_rule, with SQL aliases in camelCase. Column list shared by the routes. */
export const RULE_COLS = `alias, secret_path AS secretPath, name, upstream, inject,
  max_reads_per_hour AS maxReadsPerHour, require_reason AS requireReason,
  require_approval AS requireApproval`;

export interface StoredRule {
  alias: string;
  secretPath: string;
  name: string;
  upstream: string;
  inject: string;
  maxReadsPerHour: number;
  requireReason: number;
  requireApproval: number;
}

/** True when this rule asks for approval on this path. The default is on for paths under PROD_GLOB (ADR 17). */
export const needsApproval = (rule: { requireApproval: number }, path: string): boolean =>
  rule.requireApproval === 1 && globMatch(PROD_GLOB, path);

export type GuardResult =
  | { ok: true; note?: string }
  | { ok: false; status: 403 | 429; error: string; retryAfter?: number };

/** Drops control characters and caps the length, so a reason is one short line in the audit note. */
export function cleanReason(raw: string | undefined): string {
  const plain = Array.from(raw ?? "", (ch) => {
    const code = ch.charCodeAt(0);
    return code < 32 || code === 127 ? " " : ch;
  }).join("");
  return plain.trim().slice(0, MAX_REASON_NOTE);
}

/** Id of an approved, unexpired access request of this identity that covers `path`, if any (ADR 16). */
async function approvedRequestFor(
  db: D1Database,
  identityId: string,
  path: string,
): Promise<string | null> {
  const rows = await db
    .prepare(
      `SELECT id, path_glob AS glob FROM access_request
       WHERE requester_id = ? AND status = 'approved' AND expires_at > ?`,
    )
    .bind(identityId, now())
    .all<{ id: string; glob: string }>();
  return rows.results.find((r) => globMatch(r.glob, path))?.id ?? null;
}

async function refuse(
  db: D1Database,
  who: Who,
  path: string,
  ip: string | undefined,
  status: 403 | 429,
  error: string,
  note: string,
  retryAfter?: number,
): Promise<GuardResult> {
  await audit(db, {
    who: who.name,
    action: "secret.read",
    path,
    result: "denied",
    note,
    ip,
  });
  return { ok: false, status, error, retryAfter };
}

/**
 * Checks the agent rules that cover `path` for this identity. Identities without such a rule pass unchanged.
 * Order: reason, then approval, then budget. A read refused for a reason or approval does not use up budget.
 * Returns the audit note to attach to the successful read.
 */
export async function agentGuard(
  db: D1Database,
  who: Who,
  path: string,
  reasonHeader: string | undefined,
  ip: string | undefined,
): Promise<GuardResult> {
  const found = await db
    .prepare(
      `SELECT ${RULE_COLS} FROM agent_rule WHERE identity_id = ? AND secret_path = ? ORDER BY alias`,
    )
    .bind(who.id, path)
    .all<StoredRule>();
  const rules = found.results;
  if (rules.length === 0) return { ok: true };

  const reason = cleanReason(reasonHeader);
  const notes: string[] = [];

  // ADR 17: a rule that requires a reason refuses the read without one. The reason goes into the audit note.
  for (const rule of rules) {
    if (rule.requireReason === 1 && reason === "")
      return refuse(
        db,
        who,
        path,
        ip,
        403,
        `alias ${rule.alias} needs a reason: send the X-Cfs-Reason header`,
        `agent ${rule.alias}: reason missing`,
      );
  }
  if (rules.some((r) => r.requireReason === 1)) notes.push(`reason: ${reason}`);

  // ADR 17 and 16: a */prod read by an agent needs an approved, unexpired access request for that path.
  if (rules.some((r) => needsApproval(r, path))) {
    const requestId = await approvedRequestFor(db, who.id, path);
    if (!requestId)
      return refuse(
        db,
        who,
        path,
        ip,
        403,
        "production access needs an approved request: ask an admin to approve cfs request for this path",
        "agent: no approved request for production path",
      );
    notes.push(`approved request ${requestId}`);
  }

  // ADR 17: each fetch counts toward the alias's per-hour budget. The 429 is audited.
  for (const rule of rules) {
    const within = await hit(
      db,
      `agent:${who.id}:${rule.alias}`,
      rule.maxReadsPerHour,
      BUDGET_WINDOW,
    );
    if (!within) {
      const t = now();
      return refuse(
        db,
        who,
        path,
        ip,
        429,
        "the read budget for this alias is used up for this hour",
        `agent ${rule.alias}: budget exceeded, ${rule.maxReadsPerHour} reads per hour`,
        BUDGET_WINDOW - (t % BUDGET_WINDOW),
      );
    }
  }

  return { ok: true, note: notes.length ? notes.join("; ") : undefined };
}
