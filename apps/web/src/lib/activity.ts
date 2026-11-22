// Pure helpers for the Activity screens: the log query, the free-tier meter and the chain status (ADR 6, 19).
// No DOM, no network. Unit tested in activity.test.ts.

import type { AuditResult, Usage, Verify } from "./api.ts";

export const PAGE_SIZE = 50;

/** Share of the daily write quota at which the meter warns (ADR 19: 80%). */
export const METER_WARN_RATIO = 0.8;

export type DateRange = "24h" | "7d" | "30d" | "all";

export const DATE_RANGE_SECONDS: Record<Exclude<DateRange, "all">, number> = {
  "24h": 24 * 3600,
  "7d": 7 * 24 * 3600,
  "30d": 30 * 24 * 3600,
};

export interface AuditFilters {
  /** Exact name of the person or app. Empty means everyone. */
  who: string;
  /** Exact action name, such as secret.read. Empty means all. */
  action: string;
  /** An exact path, or a prefix when it ends with *, such as backend/*. Empty means any. */
  path: string;
  result: "" | AuditResult;
  /** A person or an app. Empty means both. */
  kind: "" | "user" | "app";
  range: DateRange;
}

export const NO_FILTERS: AuditFilters = {
  who: "",
  action: "",
  path: "",
  result: "",
  kind: "",
  range: "24h",
};

/** Action names the Worker writes (apps/api/src). The filter lists them so the person need not type them. */
export const ACTION_NAMES: readonly string[] = [
  "secret.read",
  "secret.write",
  "secret.delete",
  "secret.rotate",
  "login.ok",
  "login.denied",
  "auth.denied",
  "request.create",
  "request.approve",
  "request.deny",
  "request.cancel",
  "group.create",
  "group.key",
  "group.member.add",
  "agent_rule.create",
  "agent_rule.update",
  "agent_rule.delete",
  "alerts.update",
  "cli.approve",
  "session.revoke",
  "policy.create",
  "policy.assign",
  "backup.export",
  "audit.export",
  "audit.gap",
];

export interface AuditQuery {
  who?: string;
  action?: string;
  path?: string;
  result?: AuditResult;
  kind?: "user" | "app";
  from?: number;
  before?: number;
  limit: number;
}

const trimmed = (value: string): string | undefined => {
  const v = value.trim();
  return v === "" ? undefined : v;
};

/**
 * The query for GET /audit. `nowSec` is unix seconds. `before` is the seq of the last row on the page before,
 * so the next page holds older rows only.
 */
export function auditQuery(filters: AuditFilters, nowSec: number, before?: number): AuditQuery {
  const query: AuditQuery = { limit: PAGE_SIZE };
  const who = trimmed(filters.who);
  const action = trimmed(filters.action);
  const path = trimmed(filters.path);
  if (who !== undefined) query.who = who;
  if (action !== undefined) query.action = action;
  if (path !== undefined) query.path = path;
  if (filters.result !== "") query.result = filters.result;
  if (filters.kind !== "") query.kind = filters.kind;
  if (filters.range !== "all") query.from = nowSec - DATE_RANGE_SECONDS[filters.range];
  if (before !== undefined) query.before = before;
  return query;
}

/** Whether a path filter is a valid exact path or prefix. Only the shape is checked here; the Worker decides the rest. */
export function validPathFilter(path: string): boolean {
  const v = path.trim();
  if (v === "") return true;
  // A single trailing * is the only wildcard allowed, so the part before it holds no * at all.
  const body = v.endsWith("*") ? v.slice(0, -1) : v;
  return v.length <= 200 && !body.includes("*") && !/\s/.test(v);
}

export interface MeterState {
  /** Whole percent used, from 0 to 100. */
  percent: number;
  /** At or above 80% of the daily quota. */
  warn: boolean;
  /** At or above the whole quota. */
  over: boolean;
}

/** Thresholds for the free-tier meter. A zero or missing limit reads as 0%, never as a division error. */
export function meterState(writes: number, limit: number): MeterState {
  if (!(limit > 0) || writes < 0) return { percent: 0, warn: false, over: false };
  const ratio = writes / limit;
  return {
    percent: Math.min(100, Math.floor(ratio * 100)),
    warn: ratio >= METER_WARN_RATIO,
    over: writes >= limit,
  };
}

export type ChainState = "verified" | "broken" | "unchecked";

/** The panel's state. A failed check is "broken"; no check yet is "unchecked". */
export function chainState(verify: Verify | null): ChainState {
  if (verify === null) return "unchecked";
  return verify.ok ? "verified" : "broken";
}

/** The number in the usage line, with thousands separators: 62400 becomes "62,400". */
export function formatCount(n: number, lang: "en" | "id"): string {
  return new Intl.NumberFormat(lang === "id" ? "id-ID" : "en-US").format(n);
}

/** Usage for the line under the meter, e.g. "62,400 of 100,000 writes". */
export function usageLine(usage: Usage, lang: "en" | "id"): string {
  return `${formatCount(usage.writes, lang)} / ${formatCount(usage.limit, lang)}`;
}

/** Local date and time for a unix-second timestamp. */
export function formatTime(sec: number, lang: "en" | "id"): string {
  return new Date(sec * 1000).toLocaleString(lang === "id" ? "id-ID" : "en-GB", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** Clock time only, for the time column of the log. */
export function formatClock(sec: number, lang: "en" | "id"): string {
  return new Date(sec * 1000).toLocaleTimeString(lang === "id" ? "id-ID" : "en-GB", {
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** The query for the CSV export: the applied filters, without paging. */
export function exportQuery(filters: AuditFilters, nowSec: number): Omit<AuditQuery, "limit"> {
  const { limit: _limit, before: _before, ...rest } = auditQuery(filters, nowSec);
  return rest;
}
