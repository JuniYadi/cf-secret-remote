// Agent rule form checks (ADR 17). These mirror the Worker's checks so the person sees problems before sending.
// The Worker stays the authority: a rule it refuses is shown with its message.

import type { AgentRuleInput } from "./api.ts";

export const ALIAS_PATTERN = /^[a-z0-9][a-z0-9-]{0,39}$/;
export const NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
export const MAX_READS = 100000;
export const DEFAULT_READS = 60;
export const DEFAULT_INJECT = "header:Authorization:Bearer {value}";
const MAX_UPSTREAM = 300;
const MAX_INJECT = 300;
const HEADER_PATTERN = /^[A-Za-z0-9-]{1,64}$/;
const QUERY_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/;

/** The prod default (ADR 17): a secret whose path ends in /prod waits for an approver unless the rule says otherwise. */
export const isProdPath = (secretPath: string): boolean => /\/prod$/.test(secretPath.trim());

/** https only, no credentials, query or fragment. Returns the origin and path, as the Worker stores them. */
export function checkUpstream(raw: string): string | null {
  const v = raw.trim();
  if (v === "" || v.length > MAX_UPSTREAM) return null;
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    return null;
  }
  if (u.protocol !== "https:" || u.username || u.password || u.search || u.hash) return null;
  return `${u.origin}${u.pathname.replace(/\/+$/, "")}`;
}

/** `header:Name:Template` with {value} once in the template, or `query:name`. */
export function checkInject(raw: string): boolean {
  const v = raw.trim();
  if (v === "" || v.length > MAX_INJECT) return false;
  if (v.startsWith("query:")) return QUERY_PATTERN.test(v.slice("query:".length));
  const m = v.match(/^header:([^:]+):(.*)$/);
  if (!m) return false;
  const [, header = "", template = ""] = m;
  return (
    HEADER_PATTERN.test(header) &&
    /^[\x20-\x7e]+$/.test(template) &&
    template.split("{value}").length === 2
  );
}

export interface RuleDraft {
  alias: string;
  secretPath: string;
  name: string;
  upstream: string;
  inject: string;
  maxReadsPerHour: string;
  requireReason: boolean;
  requireApproval: boolean;
}

export type RuleField = "alias" | "secretPath" | "name" | "upstream" | "inject" | "maxReadsPerHour";

export type RuleErrors = Partial<Record<RuleField, true>>;

/** Field errors for the rule form. Empty means it can be sent. `editing` skips the alias check (it cannot change). */
export function checkRule(draft: RuleDraft, editing: boolean): RuleErrors {
  const errors: RuleErrors = {};
  if (!editing && !ALIAS_PATTERN.test(draft.alias.trim())) errors.alias = true;
  const path = draft.secretPath.trim();
  if (path === "" || path.includes("*") || path.startsWith("/") || path.endsWith("/"))
    errors.secretPath = true;
  if (!NAME_PATTERN.test(draft.name.trim())) errors.name = true;
  if (checkUpstream(draft.upstream) === null) errors.upstream = true;
  if (!checkInject(draft.inject)) errors.inject = true;
  const reads = Number(draft.maxReadsPerHour);
  if (
    draft.maxReadsPerHour.trim() === "" ||
    !Number.isInteger(reads) ||
    reads < 1 ||
    reads > MAX_READS
  )
    errors.maxReadsPerHour = true;
  return errors;
}

/** The body for POST or PUT. Call only after checkRule passes. */
export function ruleInput(draft: RuleDraft): AgentRuleInput & { alias: string } {
  return {
    alias: draft.alias.trim(),
    secretPath: draft.secretPath.trim(),
    name: draft.name.trim(),
    upstream: checkUpstream(draft.upstream) ?? draft.upstream.trim(),
    inject: draft.inject.trim(),
    maxReadsPerHour: Number(draft.maxReadsPerHour),
    requireReason: draft.requireReason,
    requireApproval: draft.requireApproval,
  };
}
