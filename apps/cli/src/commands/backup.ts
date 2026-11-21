import { readFileSync, writeFileSync } from "node:fs";
import { isSealedBackup, MIN_BACKUP_PASSPHRASE } from "@cfs/core";
import { flag } from "../args.ts";
import { CliError, type Client, connect } from "../client.ts";
import { ask } from "../prompt.ts";
import type { Commands } from "./types.ts";

// ADR 23. `cfs backup` downloads the admin's backup file. `cfs restore` checks it and, after the host name is typed, replaces the data.

/** The body of POST /restore/check (ADR 23). */
export interface CheckReport {
  ok: boolean;
  host: string;
  schema: number;
  createdAt: number;
  gapSeconds: number;
  lastAuditAt: number | null;
  audit: {
    rows: number;
    ok: boolean;
    checkpoints: { stored: number; verified: number; pruned: number; mismatched: string[] };
  };
  counts: { file: Record<string, number>; current: Record<string, number> };
  sha256: string;
}

const PASS_HEADER = "X-Backup-Passphrase";

/** Reads the passphrase from the named environment variable. Never from a flag value on the command line. */
export function passphraseFromEnv(varName: string | undefined): string | undefined {
  if (!varName) return undefined;
  const v = process.env[varName];
  if (!v)
    throw new CliError(`${varName} is empty or not set. Set it to the backup passphrase first.`);
  if (v.length < MIN_BACKUP_PASSPHRASE)
    throw new CliError(`The passphrase must be at least ${MIN_BACKUP_PASSPHRASE} characters.`);
  return v;
}

const headersFor = (pass?: string): Record<string, string> => (pass ? { [PASS_HEADER]: pass } : {});

/** Downloads a backup and writes it to `out` (mode 0600). Returns the path and size. */
export async function saveBackup(
  c: Client,
  opts: { out: string; passphrase?: string },
): Promise<{ file: string; bytes: number; sealed: boolean }> {
  const r = await c.download("/backup", headersFor(opts.passphrase));
  if (r.status === 403) throw new CliError("Only admins can make a backup.");
  if (r.status !== 200) throw new CliError(`Backup failed: ${r.error ?? `status ${r.status}`}`);
  writeFileSync(opts.out, r.bytes, { mode: 0o600 });
  return { file: opts.out, bytes: r.bytes.length, sealed: Boolean(opts.passphrase) };
}

const iso = (t: number) => new Date(t * 1000).toISOString();

/** Plain-text summary of a check. Shown before anything is restored. */
export function formatCheck(r: CheckReport): string[] {
  const lines = [
    `backup made ${iso(r.createdAt)} (schema ${r.schema}), ${formatGap(r.gapSeconds)} ago`,
    r.lastAuditAt
      ? `last audit entry in the file: ${iso(r.lastAuditAt)}`
      : "the file has no audit entries",
    `audit chain: ${r.audit.ok ? "ok" : "BROKEN"} (${r.audit.rows} rows, ${r.audit.checkpoints.verified} checkpoints verified)`,
    "tables (file / this server):",
  ];
  for (const [t, n] of Object.entries(r.counts.file))
    lines.push(`  ${t.padEnd(22)} ${n} / ${r.counts.current[t] ?? 0}`);
  lines.push(
    "Restoring replaces every table above. Sessions end, so everyone signs in again.",
    "The alert webhook is never in a backup. Set it again after a restore.",
  );
  return lines;
}

function formatGap(sec: number): string {
  if (sec < 3600) return `${Math.round(sec / 60)} min`;
  if (sec < 86400 * 2) return `${Math.round(sec / 3600)} h`;
  return `${Math.round(sec / 86400)} days`;
}

/** Checks a file without changing anything, and returns the report. */
export async function checkBackup(
  c: Client,
  bytes: Uint8Array,
  passphrase?: string,
): Promise<CheckReport> {
  const r = await c.send<CheckReport & { error?: string }>(
    "POST",
    "/restore/check",
    { file: toBase64(bytes) },
    headersFor(passphrase),
  );
  if (r.status === 403) throw new CliError("Only admins can restore a backup.");
  if (r.status !== 200) throw new CliError(`The backup was refused: ${r.body.error ?? r.status}`);
  return r.body;
}

/**
 * Restores a file. `confirm` asks for the host name; the typed text must equal the server's host name, or nothing changes.
 * Returns the server's answer.
 */
export async function restoreBackup(
  c: Client,
  bytes: Uint8Array,
  opts: { passphrase?: string; confirm: (check: CheckReport) => Promise<string> },
): Promise<{ restoredAt: number }> {
  const check = await checkBackup(c, bytes, opts.passphrase);
  const typed = await opts.confirm(check);
  if (typed !== check.host)
    throw new CliError("The host name does not match. Nothing was changed.");
  const r = await c.send<{ ok?: boolean; restoredAt?: number; error?: string }>(
    "POST",
    "/restore",
    { file: toBase64(bytes), confirmHost: typed },
    headersFor(opts.passphrase),
  );
  if (r.status !== 200)
    throw new CliError(`Restore failed: ${r.body.error ?? `status ${r.status}`}`);
  return { restoredAt: r.body.restoredAt ?? 0 };
}

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

const takeBool = (args: string[], name: string) => {
  const i = args.indexOf(name);
  if (i < 0) return false;
  args.splice(i, 1);
  return true;
};

const defaultName = () => `cfs-backup-${new Date().toISOString().slice(0, 10)}.cfsbackup`;

async function backupCmd(args: string[], hostFlag?: string): Promise<void> {
  const out = flag(args, "--out") ?? defaultName();
  const passphrase = passphraseFromEnv(flag(args, "--passphrase-env"));
  if (args.length) throw new CliError("Usage: cfs backup [--out file] [--passphrase-env VAR]");
  const c = await connect(hostFlag);
  const r = await saveBackup(c, { out, passphrase });
  console.log(
    `Wrote ${r.file} (${r.bytes} bytes, ${r.sealed ? "sealed with a passphrase" : "not sealed"}).`,
  );
  console.log("It holds names, emails and paths in clear, and encrypted values. Keep it private.");
}

async function restoreCmd(args: string[], hostFlag?: string): Promise<void> {
  const check = takeBool(args, "--check");
  const confirmHost = flag(args, "--confirm-host");
  const passphraseVar = flag(args, "--passphrase-env");
  const file = args.shift();
  if (!file || args.length)
    throw new CliError(
      "Usage: cfs restore <file> [--check] [--passphrase-env VAR] [--confirm-host NAME]",
    );
  const bytes = new Uint8Array(readFileSync(file));
  const passphrase = passphraseFromEnv(passphraseVar);
  if (isSealedBackup(bytes) && !passphrase)
    throw new CliError(
      "This backup is sealed. Pass --passphrase-env VAR with the passphrase in VAR.",
    );

  const c = await connect(hostFlag);
  if (check) {
    for (const line of formatCheck(await checkBackup(c, bytes, passphrase))) console.log(line);
    return;
  }
  const r = await restoreBackup(c, bytes, {
    passphrase,
    confirm: async (check) => {
      for (const line of formatCheck(check)) console.log(line);
      return (
        confirmHost ?? ask(`Type ${check.host} to confirm. This replaces the data on that server: `)
      );
    },
  });
  console.log(`Restored at ${iso(r.restoredAt)}. Everyone must sign in again.`);
}

export const backup: Commands = {
  backup: {
    help: "cfs backup [--out file] [--passphrase-env VAR]",
    run: backupCmd,
  },
  restore: {
    help: "cfs restore <file> [--check] [--passphrase-env VAR] [--confirm-host NAME]",
    run: restoreCmd,
  },
};
