// Backup and restore helpers (ADR 23). The server does the sealing and the checks. The browser only reads the
// file, shows what the check found, and decides when the restore button may be used.

import { isSealedBackup, MIN_BACKUP_PASSPHRASE } from "@cfs/core";
import type { RestoreCheck } from "./api.ts";

/** A passphrase is optional. When typed, it must reach the server's minimum length. */
export function passphraseProblem(passphrase: string): "too-short" | null {
  if (passphrase === "") return null;
  return passphrase.length < MIN_BACKUP_PASSPHRASE ? "too-short" : null;
}

/** The file name for a download, from the UTC day (matches the server's Content-Disposition). */
export function backupFileName(day: Date): string {
  const iso = day.toISOString().slice(0, 10);
  return `cfs-backup-${iso}.cfsbackup`;
}

/** Sealed files need the passphrase. A plain file (gzip) does not. Checked from the first bytes only. */
export const needsPassphrase = (bytes: Uint8Array): boolean => isSealedBackup(bytes);

/** The typed host must match the server's host name exactly, ignoring case and spaces. */
export function hostMatches(typed: string, host: string): boolean {
  return typed.trim().toLowerCase() === host.trim().toLowerCase();
}

/** The restore button is usable only when the host is typed correctly and the person has acknowledged the loss. */
export function canReplace(
  typedHost: string,
  check: Pick<RestoreCheck, "host">,
  acknowledged: boolean,
): boolean {
  return acknowledged && hostMatches(typedHost, check.host);
}

/** Splits a gap in seconds into whole days, hours and minutes, for the screen to label. */
export function gapParts(seconds: number): { days: number; hours: number; minutes: number } {
  const s = Math.max(0, Math.floor(seconds));
  return {
    days: Math.floor(s / 86400),
    hours: Math.floor((s % 86400) / 3600),
    minutes: Math.floor((s % 3600) / 60),
  };
}
