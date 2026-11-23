import { globMatch } from "../policy.ts";

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

/** Fields a rule holds, after validation. Used by create (all present) and update (merged over the old row). */
export interface RuleInput {
  secretPath: string;
  name: string;
  upstream: string;
  inject: string;
  maxReadsPerHour: number;
  requireReason: boolean;
  requireApproval: boolean;
}

export const isApp = (db: D1Database, id: string) =>
  db
    .prepare("SELECT id, name FROM identity WHERE id = ? AND kind = 'app'")
    .bind(id)
    .first<{ id: string; name: string }>();

export const findRule = (db: D1Database, appId: string, alias: string) =>
  db
    .prepare(`SELECT ${RULE_COLS} FROM agent_rule WHERE identity_id = ? AND alias = ?`)
    .bind(appId, alias)
    .first<StoredRule>();

export function listRules(db: D1Database, id: string) {
  return db
    .prepare(`SELECT ${RULE_COLS} FROM agent_rule WHERE identity_id = ? ORDER BY alias`)
    .bind(id)
    .all<StoredRule>();
}

export async function insertRule(db: D1Database, appId: string, alias: string, input: RuleInput) {
  await db
    .prepare(
      `INSERT INTO agent_rule (identity_id, alias, secret_path, name, upstream, inject,
         max_reads_per_hour, require_reason, require_approval) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      appId,
      alias,
      input.secretPath,
      input.name,
      input.upstream,
      input.inject,
      input.maxReadsPerHour,
      input.requireReason ? 1 : 0,
      input.requireApproval ? 1 : 0,
    )
    .run();
}

export async function updateRule(db: D1Database, appId: string, alias: string, input: RuleInput) {
  await db
    .prepare(
      `UPDATE agent_rule SET secret_path = ?, name = ?, upstream = ?, inject = ?,
         max_reads_per_hour = ?, require_reason = ?, require_approval = ?
       WHERE identity_id = ? AND alias = ?`,
    )
    .bind(
      input.secretPath,
      input.name,
      input.upstream,
      input.inject,
      input.maxReadsPerHour,
      input.requireReason ? 1 : 0,
      input.requireApproval ? 1 : 0,
      appId,
      alias,
    )
    .run();
}

export async function deleteRule(db: D1Database, appId: string, alias: string) {
  await db
    .prepare("DELETE FROM agent_rule WHERE identity_id = ? AND alias = ?")
    .bind(appId, alias)
    .run();
}

export function approvedRequests(db: D1Database, identityId: string, at: number) {
  return db
    .prepare(
      `SELECT id, path_glob AS glob FROM access_request
       WHERE requester_id = ? AND status = 'approved' AND expires_at > ?`,
    )
    .bind(identityId, at)
    .all<{ id: string; glob: string }>();
}

export async function rulesForPath(db: D1Database, identityId: string, path: string) {
  const rows = await listRules(db, identityId);
  return rows.results.filter((rule) => globMatch(rule.secretPath, path));
}
