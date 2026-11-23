import { retentionDays } from "./cron.ts";
import { readLimits } from "./repository/settings.ts";
import type { Env } from "./types.ts";

export interface Limits {
  maxRequestDuration: number;
  defaultApprovalDuration: number;
  auditRetentionDays: number;
}
export const MAX_REQUEST_DURATION = 30 * 86400;
export const MAX_RETENTION_DAYS = 36500;
export function validLimits(v: Limits): boolean {
  return (
    Number.isInteger(v.maxRequestDuration) &&
    v.maxRequestDuration >= 1 &&
    v.maxRequestDuration <= MAX_REQUEST_DURATION &&
    Number.isInteger(v.defaultApprovalDuration) &&
    v.defaultApprovalDuration >= 1 &&
    v.defaultApprovalDuration <= v.maxRequestDuration &&
    Number.isInteger(v.auditRetentionDays) &&
    v.auditRetentionDays >= 90 &&
    v.auditRetentionDays <= MAX_RETENTION_DAYS
  );
}
export async function loadLimits(env: Env): Promise<Limits> {
  const fallback = {
    maxRequestDuration: 86400,
    defaultApprovalDuration: 3600,
    auditRetentionDays: retentionDays(env),
  };
  const raw = await readLimits(env.DB);
  if (raw === null) return fallback;
  try {
    const value = JSON.parse(raw) as Limits;
    return validLimits(value) ? value : fallback;
  } catch {
    return fallback;
  }
}
