import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { decodeKit, encodeKit, generateKeyPair, type Kit } from "@cfs/core";
import { flag } from "../args.ts";
import { CliError, type Client, connect } from "../client.ts";
import type { Commands } from "./types.ts";

// ADR 15: app create|list|show|rotate|disable. The private key is made here and leaves this machine only inside the kit.

const USAGE = `Usage:
  cfs app create <name> [--ttl 1h] [--max-uses n] [--expires 90d] [--cidr list] [--out file]
  cfs app list
  cfs app show <name>
  cfs app rotate <name> --kit-file <file> [--out file]
  cfs app disable <name>`;

/** What the server returns for an app (see apps/api/src/routes/apps.ts). Never a secret_id. */
export interface AppView {
  id: string;
  name: string;
  status: string;
  createdAt: number;
  owner: string | null;
  roleId: string;
  tokenTtl: number;
  maxUses: number | null;
  uses: number;
  cidr: string[] | null;
  expiresAt: number | null;
  firstLoginAt: number | null;
  lastLoginAt: number | null;
  lastIp: string | null;
  waiting: boolean;
  sessions?: { id: string; createdAt: number; expiresAt: number }[];
  activity?: {
    at: number;
    action: string;
    result: string;
    ip: string | null;
    note: string | null;
  }[];
}

const UNIT: Record<string, number> = { "": 1, s: 1, m: 60, h: 3600, d: 86400 };

/** "90" is seconds; "30m", "1h", "90d" are minutes, hours, days. Returns seconds, or null if it does not parse. */
export function parseDuration(s: string): number | null {
  const m = /^(\d+)([smhd]?)$/.exec(s.trim());
  if (!m) return null;
  return Number(m[1]) * (UNIT[m[2] ?? ""] ?? 1);
}

const when = (t: number | null): string => (t === null ? "-" : new Date(t * 1000).toISOString());

/** One line of `cfs app list`. */
export function formatAppLine(a: AppView): string {
  const seen = a.waiting
    ? "waiting for first sign-in"
    : `last seen ${when(a.lastLoginAt)} from ${a.lastIp ?? "unknown"}`;
  return `${a.name.padEnd(24)} ${a.status.padEnd(9)} ${seen}`;
}

/** The lines of `cfs app show`. */
export function formatAppDetail(a: AppView): string[] {
  const lines = [
    `Name:             ${a.name}`,
    `Role ID:          ${a.roleId}`,
    `State:            ${a.status}`,
    `Owner:            ${a.owner ?? "-"}`,
    `Token TTL:        ${a.tokenTtl}s`,
    `Uses:             ${a.uses}${a.maxUses === null ? "" : ` of ${a.maxUses}`}`,
    `Expires:          ${a.expiresAt === null ? "never" : when(a.expiresAt)}`,
    `Networks:         ${a.cidr?.join(", ") ?? "any"}`,
    `First sign-in:    ${a.waiting ? "waiting for first sign-in" : when(a.firstLoginAt)}`,
    `Last sign-in:     ${when(a.lastLoginAt)}${a.lastIp ? ` from ${a.lastIp}` : ""}`,
    `Open sessions:    ${a.sessions?.length ?? 0}`,
  ];
  if (a.activity?.length) {
    lines.push("", "Recent activity:");
    for (const e of a.activity) {
      const note = e.note ? ` (${e.note})` : "";
      lines.push(`  ${when(e.at)}  ${e.action}  ${e.result}${note}${e.ip ? ` from ${e.ip}` : ""}`);
    }
  }
  return lines;
}

function refused(status: number, body: unknown, what: string): CliError {
  if (status === 401) return new CliError("Your session ended. Run: cfs login");
  if (status === 403) return new CliError("Only admins can manage apps and bots.");
  if (status === 404) return new CliError(`${what}: not found.`);
  const msg = (body as { error?: string } | null)?.error ?? `status ${status}`;
  return new CliError(`${what}: ${msg}`);
}

/** Writes the kit to a file (owner-only) or prints it. Either way it is shown once. */
function emitKit(kit: string, out: string | undefined): void {
  if (out) {
    writeFileSync(out, `${kit}\n`, { mode: 0o600, flag: "wx" });
    console.log(`Kit written to ${out}. It is shown only once, so keep that file safe.`);
    return;
  }
  console.log(`Access kit, shown once. Save it now and set it as CFS_KIT for the app:\n\n${kit}\n`);
}

function refuseExisting(out: string | undefined): void {
  if (out && existsSync(out)) throw new CliError(`${out} already exists. Choose another path.`);
}

async function listApps(c: Client): Promise<AppView[]> {
  const r = await c.call<AppView[]>("GET", "/apps");
  if (r.status !== 200) throw refused(r.status, r.body, "list apps");
  return r.body;
}

/** Finds an app by name or id. */
async function resolve(c: Client, ref: string): Promise<AppView> {
  const found = (await listApps(c)).find((a) => a.name === ref || a.id === ref);
  if (!found) throw new CliError(`No app or bot named "${ref}".`);
  return found;
}

async function create(args: string[], hostFlag?: string) {
  const ttlArg = flag(args, "--ttl");
  const maxArg = flag(args, "--max-uses");
  const expArg = flag(args, "--expires");
  const cidr = flag(args, "--cidr");
  const out = flag(args, "--out");
  const name = args[0];
  if (!name) throw new CliError(USAGE);

  const tokenTtl = ttlArg === undefined ? 3600 : parseDuration(ttlArg);
  if (tokenTtl === null) throw new CliError("--ttl must look like 90, 30m, 1h or 7d.");
  let maxUses: number | undefined;
  if (maxArg !== undefined) {
    maxUses = Number(maxArg);
    if (!Number.isInteger(maxUses) || maxUses < 1)
      throw new CliError("--max-uses must be a whole number, 1 or more.");
  }
  let expiresAt: number | undefined;
  if (expArg !== undefined) {
    const secs = parseDuration(expArg);
    if (secs === null) throw new CliError("--expires must look like 1h, 90d or 3600.");
    expiresAt = Math.floor(Date.now() / 1000) + secs;
  }
  refuseExisting(out);

  const c = await connect(hostFlag);
  // The key pair is made here. The server receives only the public key.
  const pair = await generateKeyPair();
  const r = await c.call<{ roleId: string; secretId: string }>("POST", "/apps", {
    name,
    publicKey: pair.publicKey,
    tokenTtl,
    maxUses,
    expiresAt,
    cidr,
  });
  if (r.status !== 201) throw refused(r.status, r.body, `create ${name}`);

  const kit = encodeKit({
    host: c.host,
    roleId: r.body.roleId,
    secretId: r.body.secretId,
    privateKey: pair.privateKey,
  });
  emitKit(kit, out);
  console.log(`Created "${name}". It cannot sign in until its kit is used.`);
}

async function list(hostFlag?: string) {
  const c = await connect(hostFlag);
  const apps = await listApps(c);
  if (!apps.length) {
    console.log("No apps or bots yet. Create one: cfs app create <name>");
    return;
  }
  for (const a of apps) console.log(formatAppLine(a));
}

async function show(args: string[], hostFlag?: string) {
  const ref = args[0];
  if (!ref) throw new CliError("Usage: cfs app show <name>");
  const c = await connect(hostFlag);
  const app = await resolve(c, ref);
  const r = await c.call<AppView>("GET", `/apps/${app.id}`);
  if (r.status !== 200) throw refused(r.status, r.body, `show ${ref}`);
  console.log(formatAppDetail(r.body).join("\n"));
}

// Rotating keeps the private key, so the new kit is built from the current one. The server does not hold the key.
async function rotate(args: string[], hostFlag?: string) {
  const kitFile = flag(args, "--kit-file");
  const out = flag(args, "--out");
  const ref = args[0];
  if (!ref) throw new CliError("Usage: cfs app rotate <name> --kit-file <file> [--out file]");
  if (!kitFile)
    throw new CliError(
      "Rotating needs the app's current kit (--kit-file), because the new kit keeps its private key.",
    );
  refuseExisting(out);

  let current: Kit;
  try {
    current = decodeKit(readFileSync(kitFile, "utf8").trim());
  } catch {
    throw new CliError("That file is not a valid access kit.");
  }
  const c = await connect(hostFlag);
  const app = await resolve(c, ref);
  if (current.roleId !== app.roleId)
    throw new CliError(`That kit belongs to another app, not ${app.name}.`);

  const r = await c.call<{ roleId: string; secretId: string }>("POST", `/apps/${app.id}/rotate`);
  if (r.status !== 200) throw refused(r.status, r.body, `rotate ${ref}`);
  emitKit(encodeKit({ ...current, secretId: r.body.secretId }), out);
  console.log("The old kit no longer works. Update the app's CFS_KIT now.");
}

async function disable(args: string[], hostFlag?: string) {
  const ref = args[0];
  if (!ref) throw new CliError("Usage: cfs app disable <name>");
  const c = await connect(hostFlag);
  const app = await resolve(c, ref);
  const r = await c.call("POST", `/apps/${app.id}/disable`);
  if (r.status !== 200) throw refused(r.status, r.body, `disable ${ref}`);
  console.log(`Disabled "${app.name}". It cannot sign in, and its sessions have ended.`);
}

export const app: Commands = {
  app: {
    help: "cfs app create|list|show|rotate|disable   apps and bots (admins)",
    run: (a, h) => {
      const sub = a.shift();
      if (sub === "create") return create(a, h);
      if (sub === "list") return list(h);
      if (sub === "show") return show(a, h);
      if (sub === "rotate") return rotate(a, h);
      if (sub === "disable") return disable(a, h);
      throw new CliError(USAGE);
    },
  },
};
