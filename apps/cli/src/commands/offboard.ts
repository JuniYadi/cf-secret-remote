import { writeFileSync } from "node:fs";
import { flag } from "../args.ts";
import { CliError, type Client, connect } from "../client.ts";
import { confirm } from "../prompt.ts";
import { removeMember } from "./group.ts";
import type { Commands } from "./types.ts";

// ADR 21. `cfs offboard <email>`: plan, confirm, then resumable steps. Every step is also an API call the
// server audits. Group removal reuses the client-driven rotation in group.ts (ADR 14).

const USAGE = "Usage: cfs offboard <email> [--reassign-to <email>] [--report <file>] [--yes]";

/** Printed last. Removal from the company login is done at the identity provider (ADR 21). */
export const REMINDER =
  "Reminder: remove the person from the company login at your identity provider. cfs cannot do that.";

/** What GET /offboard/:id/plan returns (see apps/api/src/routes/offboard.ts). Names only. */
export interface Plan {
  person: { id: string; name: string; role: string; status: string };
  groups: string[];
  apps: { id: string; name: string; status: string }[];
  sessions: {
    id: string;
    kind: string;
    device: string | null;
    createdAt: number;
    expiresAt: number;
  }[];
  opened: {
    windowDays: number;
    secrets: {
      path: string;
      versions: number[];
      names: string[];
      opens: number;
      lastOpened: number;
    }[];
  };
  blockers: { groups: string[]; apps: string[]; twoAdmins: boolean };
  canFinish: boolean;
}

export interface OffboardOptions {
  yes: boolean;
  reassignTo?: string;
}

export interface OffboardIO {
  confirm(question: string): Promise<boolean>;
  log(line: string): void;
}

const errorOf = (body: unknown, status: number) =>
  (body as { error?: string })?.error ?? `status ${status}`;

/** The plain-text lines of the "values this person could open" report: names and paths, never values. */
export function reportLines(plan: Plan): string[] {
  const lines = [
    `Values ${plan.person.name} could open (fetched in the last ${plan.opened.windowDays} days).`,
    "Names only. Change these values at their source; rotation protects only values written after it.",
    "",
  ];
  if (plan.opened.secrets.length === 0) lines.push("(none)");
  for (const s of plan.opened.secrets) {
    const names = s.names.length ? s.names.join(", ") : "(names no longer stored)";
    lines.push(`${s.path}\t${names}\tversions ${s.versions.join(", ")}`);
  }
  return lines;
}

/** The lines shown before the confirmation. */
export function planLines(plan: Plan): string[] {
  const lines = [`Offboarding ${plan.person.name} (${plan.person.status}).`];
  lines.push(
    plan.groups.length
      ? `Groups to remove them from (${plan.groups.length}): ${plan.groups.join(", ")}`
      : "Groups: none",
  );
  if (plan.apps.length) {
    lines.push("Apps they own:");
    for (const a of plan.apps) lines.push(`  ${a.name} (${a.status})`);
  } else lines.push("Apps they own: none");
  lines.push(`Open sessions: ${plan.sessions.length}`);
  lines.push(
    `Secrets they fetched in the last ${plan.opened.windowDays} days: ${plan.opened.secrets.length}`,
  );
  return lines;
}

/** Looks up a person by email in the admin directory. Apps are never offboarded this way. */
async function personByEmail(c: Client, email: string) {
  const r = await c.call<{ id: string; name: string; kind: string; status: string }[]>(
    "GET",
    "/identities",
  );
  if (r.status === 403) throw new CliError("Only admins can offboard people.");
  if (r.status !== 200) throw new CliError(`Could not load people: ${errorOf(r.body, r.status)}`);
  const found = r.body.find((i) => i.kind === "user" && i.name === email);
  if (!found) throw new CliError(`${email} is not a person on this server.`);
  return found;
}

/**
 * Runs the offboarding of `email`. Safe to re-run: groups already left and apps already handled drop out
 * of the plan, and finish is idempotent. Returns the report lines (names only).
 */
export async function runOffboard(
  c: Client,
  email: string,
  opts: OffboardOptions,
  io: OffboardIO,
): Promise<string[]> {
  const target = await personByEmail(c, email);
  const newOwner = opts.reassignTo ? await personByEmail(c, opts.reassignTo) : undefined;
  if (newOwner && newOwner.status !== "active")
    throw new CliError(`${newOwner.name} is disabled, so cannot own apps.`);

  const got = await c.call<Plan>("GET", `/offboard/${target.id}/plan`);
  if (got.status !== 200)
    throw new CliError(`Could not load the plan: ${errorOf(got.body, got.status)}`);
  const plan = got.body;
  for (const line of planLines(plan)) io.log(line);

  if (!opts.yes) {
    const ok = await io.confirm(`Offboard ${email}? [y/N] `);
    if (!ok) throw new CliError("Cancelled. Nothing was changed.");
  }

  const missing: string[] = [];
  for (const prefix of plan.groups) {
    const key = await c.call("GET", `/keyrings/${encodeURIComponent(prefix)}/key`);
    if (key.status === 404) {
      const members = await c.call<{ name: string; role: string; status: string }[]>(
        "GET",
        `/keyrings/${encodeURIComponent(prefix)}/members`,
      );
      if (members.status !== 200)
        throw new CliError(`Could not list "${prefix}": ${errorOf(members.body, members.status)}`);
      const admins = members.body
        .filter((m) => m.role === "admin" && m.status === "active" && m.name !== email)
        .map((m) => m.name);
      missing.push(`${prefix}: ${admins.join(", ") || "no other active admin found"}`);
    } else if (key.status !== 200)
      throw new CliError(`Could not check "${prefix}": ${errorOf(key.body, key.status)}`);
  }
  if (missing.length)
    throw new CliError(
      `You lack group keys. Ask another admin holding each key to offboard this person, then rerun:\n${missing.join("\n")}`,
    );

  for (const prefix of plan.groups) {
    await removeMember(c, prefix, email);
    io.log(`Removed ${email} from "${prefix}" (key rotated).`);
  }

  for (const app of plan.apps) {
    if (app.status !== "active") continue;
    if (newOwner) {
      const r = await c.call("POST", `/offboard/${target.id}/apps/${app.id}/reassign`, {
        ownerId: newOwner.id,
      });
      if (r.status !== 200)
        throw new CliError(`Could not reassign ${app.name}: ${errorOf(r.body, r.status)}`);
      io.log(`${app.name} reassigned to ${newOwner.name}.`);
    } else {
      const r = await c.call("POST", `/apps/${app.id}/disable`, {});
      if (r.status !== 200)
        throw new CliError(`Could not disable ${app.name}: ${errorOf(r.body, r.status)}`);
      io.log(`${app.name} disabled.`);
    }
  }

  const done = await c.call<{
    changed: { disabled: boolean; sessionsEnded: number; policiesRemoved: number };
  }>("POST", `/offboard/${target.id}/finish`, {});
  if (done.status !== 200) {
    const blockers = (done.body as { blockers?: Plan["blockers"] })?.blockers;
    const left = blockers
      ? ` Still in groups: ${blockers.groups.join(", ") || "none"}. Active apps: ${blockers.apps.join(", ") || "none"}.`
      : "";
    throw new CliError(`Offboarding is not finished: ${errorOf(done.body, done.status)}.${left}`);
  }
  io.log(
    `${email} disabled: ${done.body.changed.sessionsEnded} session(s) ended, ${done.body.changed.policiesRemoved} policy link(s) removed.`,
  );

  return reportLines(plan);
}

/** Pulls `--yes` out of the arguments; flags with values are read by the caller first. */
function takeSwitch(args: string[], name: string): boolean {
  const i = args.indexOf(name);
  if (i < 0) return false;
  args.splice(i, 1);
  return true;
}

export const offboard: Commands = {
  offboard: {
    help: "cfs offboard <email> [--reassign-to <email>] [--report <file>] [--yes]",
    run: async (a, hostFlag) => {
      const reassignTo = flag(a, "--reassign-to");
      const reportFile = flag(a, "--report");
      const yes = takeSwitch(a, "--yes");
      const email = a[0]?.toLowerCase();
      if (!email || a.length !== 1) throw new CliError(USAGE);
      if (!yes && !process.stdin.isTTY)
        throw new CliError("No terminal to confirm in. Pass --yes to offboard without asking.");

      const c = await connect(hostFlag);
      const lines = await runOffboard(
        c,
        email,
        { yes, reassignTo: reassignTo?.toLowerCase() },
        { confirm: (q) => confirm(q), log: (l) => console.log(l) },
      );
      if (reportFile) {
        writeFileSync(reportFile, `${lines.join("\n")}\n`, { mode: 0o600 });
        console.log(`Report written to ${reportFile}.`);
      } else {
        console.log("");
        for (const l of lines) console.log(l);
      }
      console.log(REMINDER);
    },
  },
};
