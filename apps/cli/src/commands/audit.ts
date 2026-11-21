import { CliError, connect } from "../client.ts";
import type { Commands } from "./types.ts";

// ADR 19: the shape of GET /audit/verify.
export interface VerifyResult {
  ok: boolean;
  rows: number;
  firstBad: number | null;
  firstBadSeq: number | null;
  head: string;
  base: { seq: number; hash: string } | null;
  checkpoints: { stored: number; verified: number; pruned: number; mismatched: string[] };
}

/** Plain-text report. Lines for the first bad row and each mismatched checkpoint. */
export function formatVerify(r: VerifyResult): string[] {
  const cp = r.checkpoints;
  const lines: string[] = [];
  if (r.firstBad !== null)
    lines.push(`bad: row seq ${r.firstBadSeq} (position ${r.firstBad}) does not match its hash`);
  for (const day of cp.mismatched) lines.push(`bad: checkpoint ${day} does not match the chain`);
  const from = r.base ? `from pruned base seq ${r.base.seq}, ` : "";
  lines.push(
    `${r.ok ? "ok" : "FAILED"}: ${r.rows} rows checked, ${from}head ${r.head}`,
    `checkpoints: ${cp.verified} verified, ${cp.pruned} pruned, ${cp.stored} stored`,
  );
  return lines;
}

async function verify(): Promise<void> {
  const c = await connect();
  const r = await c.call<VerifyResult>("GET", "/audit/verify");
  if (r.status === 403) throw new CliError("Only admins can verify the audit log.");
  if (r.status !== 200) throw new CliError(`Could not verify the audit log (status ${r.status}).`);
  for (const line of formatVerify(r.body)) console.log(line);
  if (!r.body.ok) process.exitCode = 1;
}

export const audit: Commands = {
  audit: {
    help: "cfs audit verify",
    run: (a) => {
      if (a.shift() === "verify") return verify();
      throw new CliError("Usage: cfs audit verify");
    },
  },
};
