import { ConflictCode } from "@cfs/core";
import { Hono } from "hono";
import { PROD_GLOB, type StoredRule } from "../agent-guard.ts";
import { audit } from "../audit.ts";
import { requireAdmin } from "../auth.ts";
import { NAME_RE } from "../limits.ts";
import { globMatch, validPath } from "../policy.ts";
import {
  deleteRule,
  findRule,
  insertRule,
  isApp,
  listRules,
  type RuleInput,
  updateRule,
} from "../repository/agent.ts";
import type { AppEnv, Who } from "../types.ts";

// ADR 17. Agent rules: which secret an app's alias reads, where the value goes, and the limits on it.
// Admins manage rules per app. An app reads only its own rules through GET /agent/rules.
// Rules hold no values. The reads themselves are checked in agent-guard.ts when GET /secret runs.

const ALIAS_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;
const HEADER_NAME_RE = /^[A-Za-z0-9-]{1,64}$/;
const QUERY_NAME_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const MAX_READS = 100000;
const DEFAULT_READS = 60;
const MAX_UPSTREAM = 300;
const MAX_INJECT = 300;

interface RuleView {
  alias: string;
  secretPath: string;
  name: string;
  upstream: string;
  inject: string;
  maxReadsPerHour: number;
  requireReason: boolean;
  requireApproval: boolean;
}

const view = (r: StoredRule): RuleView => ({
  alias: r.alias,
  secretPath: r.secretPath,
  name: r.name,
  upstream: r.upstream,
  inject: r.inject,
  maxReadsPerHour: r.maxReadsPerHour,
  requireReason: r.requireReason === 1,
  requireApproval: r.requireApproval === 1,
});

type Check<T> = { value: T } | { error: string };

/** https only, no credentials, no query or fragment. The origin and path are kept. This is the host allowlist. */
export function parseUpstream(raw: unknown): Check<string> {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > MAX_UPSTREAM)
    return { error: "upstream must be an https URL" };
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return { error: "upstream must be an https URL" };
  }
  if (u.protocol !== "https:") return { error: "upstream must be https" };
  if (u.username || u.password) return { error: "upstream must not contain credentials" };
  if (u.search || u.hash) return { error: "upstream must not have a query or fragment" };
  return { value: `${u.origin}${u.pathname.replace(/\/+$/, "")}` };
}

/** `header:Name:Template` with {value} once in the template, or `query:name`. */
export function parseInject(raw: unknown): Check<string> {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > MAX_INJECT)
    return { error: "inject must be header:Name:Template or query:name" };
  if (raw.startsWith("query:")) {
    const name = raw.slice("query:".length);
    return QUERY_NAME_RE.test(name) ? { value: raw } : { error: "inject query name is not valid" };
  }
  const m = raw.match(/^header:([^:]+):(.*)$/);
  if (!m) return { error: "inject must be header:Name:Template or query:name" };
  const [, header = "", template = ""] = m;
  if (!HEADER_NAME_RE.test(header)) return { error: "inject header name is not valid" };
  if (!/^[\x20-\x7e]+$/.test(template) || template.split("{value}").length !== 2)
    return { error: "inject template must be printable and contain {value} once" };
  return { value: raw };
}

function checkSecretPath(raw: unknown): Check<string> {
  return typeof raw === "string" && validPath(raw) && !raw.includes("*")
    ? { value: raw }
    : { error: "secretPath is not a valid secret path" };
}

function checkName(raw: unknown): Check<string> {
  return typeof raw === "string" && NAME_RE.test(raw)
    ? { value: raw }
    : { error: "name must be the value name inside the secret" };
}

function checkReads(raw: unknown): Check<number> {
  return Number.isInteger(raw) && (raw as number) >= 1 && (raw as number) <= MAX_READS
    ? { value: raw as number }
    : { error: `maxReadsPerHour must be a whole number from 1 to ${MAX_READS}` };
}

function checkBool(raw: unknown, field: string): Check<boolean> {
  return typeof raw === "boolean" ? { value: raw } : { error: `${field} must be true or false` };
}

// Approval is on for prod paths unless the admin says otherwise (ADR 17).
const defaultApproval = (secretPath: string) => globMatch(PROD_GLOB, secretPath);

export const agent_rules = new Hono<AppEnv>();

// Rules of one app. Admins only; the app itself reads its own rules through /agent/rules.
agent_rules.get("/apps/:id/rules", requireAdmin, async (c) => {
  const app = await isApp(c.env.DB, c.req.param("id") ?? "");
  if (!app) return c.json({ error: "not found" }, 404);
  const rows = await listRules(c.env.DB, app.id);
  return c.json(rows.results.map(view));
});

agent_rules.post("/apps/:id/rules", requireAdmin, async (c) => {
  const db = c.env.DB;
  const who = c.get("who");
  const ip = c.req.header("CF-Connecting-IP");
  const app = await isApp(db, c.req.param("id") ?? "");
  if (!app) return c.json({ error: "not found" }, 404);
  const b = await c.req.json<Record<string, unknown>>().catch(() => null);
  if (!b || typeof b !== "object") return c.json({ error: "bad request" }, 400);

  if (typeof b.alias !== "string" || !ALIAS_RE.test(b.alias))
    return c.json({ error: "alias must be lowercase letters, digits and dashes" }, 400);
  const alias = b.alias;
  const checked = checkRuleBody(b);
  if ("error" in checked) return c.json({ error: checked.error }, 400);
  const input = checked.value;

  if (await findRule(db, app.id, alias))
    return c.json(
      { error: "alias already used for this app", code: ConflictCode.alias_exists },
      409,
    );
  await insertRule(db, app.id, alias, input);
  await audit(db, {
    who: who.name,
    actor: who,
    action: "agent_rule.create",
    path: input.secretPath,
    note: `app ${app.name}, alias ${alias}`,
    result: "ok",
    ip,
  });
  const row = await findRule(db, app.id, alias);
  return c.json(row ? view(row) : { alias }, 201);
});

agent_rules.put("/apps/:id/rules/:alias", requireAdmin, async (c) => {
  const db = c.env.DB;
  const who = c.get("who");
  const ip = c.req.header("CF-Connecting-IP");
  const app = await isApp(db, c.req.param("id") ?? "");
  if (!app) return c.json({ error: "not found" }, 404);
  const alias = c.req.param("alias") ?? "";
  const current = await findRule(db, app.id, alias);
  if (!current) return c.json({ error: "not found" }, 404);
  const b = await c.req.json<Record<string, unknown>>().catch(() => null);
  if (!b || typeof b !== "object") return c.json({ error: "bad request" }, 400);
  if (b.alias !== undefined && b.alias !== alias)
    return c.json({ error: "alias cannot change, delete the rule and create another" }, 400);

  const patch = pick(b);
  // A new secret path re-applies the */prod default unless the body sets requireApproval itself.
  const requireApproval =
    b.requireApproval !== undefined
      ? b.requireApproval
      : b.secretPath !== undefined
        ? defaultApproval(String(b.secretPath))
        : current.requireApproval === 1;
  const checked = checkRuleBody({
    secretPath: patch.secretPath ?? current.secretPath,
    name: patch.name ?? current.name,
    upstream: patch.upstream ?? current.upstream,
    inject: patch.inject ?? current.inject,
    maxReadsPerHour: patch.maxReadsPerHour ?? current.maxReadsPerHour,
    requireReason: patch.requireReason ?? current.requireReason === 1,
    requireApproval,
  });
  if ("error" in checked) return c.json({ error: checked.error }, 400);
  const input = checked.value;

  await updateRule(db, app.id, alias, input);
  await audit(db, {
    who: who.name,
    actor: who,
    action: "agent_rule.update",
    path: input.secretPath,
    note: `app ${app.name}, alias ${alias}`,
    result: "ok",
    ip,
  });
  const row = await findRule(db, app.id, alias);
  return c.json(row ? view(row) : { alias });
});

agent_rules.delete("/apps/:id/rules/:alias", requireAdmin, async (c) => {
  const db = c.env.DB;
  const who = c.get("who");
  const ip = c.req.header("CF-Connecting-IP");
  const app = await isApp(db, c.req.param("id") ?? "");
  if (!app) return c.json({ error: "not found" }, 404);
  const alias = c.req.param("alias") ?? "";
  const current = await findRule(db, app.id, alias);
  if (!current) return c.json({ error: "not found" }, 404);
  await deleteRule(db, app.id, alias);
  await audit(db, {
    who: who.name,
    actor: who,
    action: "agent_rule.delete",
    path: current.secretPath,
    note: `app ${app.name}, alias ${alias}`,
    result: "ok",
    ip,
  });
  return c.json({ ok: true });
});

// The caller's own rules. Any identity may call it; it only ever lists rows where identity_id is the caller.
agent_rules.get("/agent/rules", async (c) => {
  const who: Who = c.get("who");
  const rows = await listRules(c.env.DB, who.id);
  return c.json(rows.results.map(view));
});

/** The body fields a rule takes, from a request or from the stored row. Unknown fields are ignored. */
function pick(b: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (b.secretPath !== undefined) out.secretPath = b.secretPath;
  if (b.name !== undefined) out.name = b.name;
  if (b.upstream !== undefined) out.upstream = b.upstream;
  if (b.inject !== undefined) out.inject = b.inject;
  if (b.maxReadsPerHour !== undefined) out.maxReadsPerHour = b.maxReadsPerHour;
  if (b.requireReason !== undefined) out.requireReason = b.requireReason;
  if (b.requireApproval !== undefined) out.requireApproval = b.requireApproval;
  return out;
}

/**
 * Validates a rule. `b` carries camelCase fields. maxReadsPerHour defaults to DEFAULT_READS when absent, and
 * requireApproval follows the prod-path default when absent.
 */
function checkRuleBody(b: Record<string, unknown>): Check<RuleInput> {
  const secretPath = checkSecretPath(b.secretPath);
  if ("error" in secretPath) return secretPath;
  const name = checkName(b.name);
  if ("error" in name) return name;
  const upstream = parseUpstream(b.upstream);
  if ("error" in upstream) return upstream;
  const inject = parseInject(b.inject);
  if ("error" in inject) return inject;
  const reads = checkReads(b.maxReadsPerHour ?? DEFAULT_READS);
  if ("error" in reads) return reads;
  const requireReason: Check<boolean> =
    b.requireReason === undefined ? { value: false } : checkBool(b.requireReason, "requireReason");
  if ("error" in requireReason) return requireReason;
  const requireApproval: Check<boolean> =
    b.requireApproval === undefined
      ? { value: defaultApproval(secretPath.value) }
      : checkBool(b.requireApproval, "requireApproval");
  if ("error" in requireApproval) return requireApproval;
  return {
    value: {
      secretPath: secretPath.value,
      name: name.value,
      upstream: upstream.value,
      inject: inject.value,
      maxReadsPerHour: reads.value,
      requireReason: requireReason.value,
      requireApproval: requireApproval.value,
    },
  };
}
