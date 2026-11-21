// View model for the Restore check (ADR 23): turns the server's POST /restore/check answer into what the
// screen shows. Pure, so the rules are unit tested (restore-view.test.ts).

import type { RestoreCheck } from "./api.ts";
import { gapParts } from "./backup.ts";

export interface RestoreView {
  /** The backup's time, UTC, as "YYYY-MM-DD HH:MM UTC". */
  madeAt: string;
  gap: { days: number; hours: number; minutes: number };
  people: number;
  secrets: number;
  logEntries: number;
  /** Rows the restore would drop from the current vault: work done since the backup. */
  currentSecrets: number;
  currentLogEntries: number;
  /** The audit chain inside the file checks out, and so does every checkpoint in it. */
  chainOk: boolean;
  checkpointsOk: boolean;
  /** Only the counts, never values. */
  hasMismatchedCheckpoints: boolean;
}

export function restoreView(check: RestoreCheck): RestoreView {
  const made = new Date(check.createdAt * 1000);
  const iso = made.toISOString();
  const file = check.counts.file;
  const current = check.counts.current;
  const mismatched = check.audit.checkpoints.mismatched.length > 0;
  return {
    madeAt: `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`,
    gap: gapParts(check.gapSeconds),
    people: file.identity ?? 0,
    secrets: file.secret ?? 0,
    logEntries: file.audit ?? 0,
    currentSecrets: current.secret ?? 0,
    currentLogEntries: current.audit ?? 0,
    chainOk: check.audit.ok,
    checkpointsOk: !mismatched,
    hasMismatchedCheckpoints: mismatched,
  };
}

/** Whether the server's check passed: the file verified and the audit chain is intact. */
export const checkPassed = (check: RestoreCheck): boolean => check.ok && check.audit.ok;
