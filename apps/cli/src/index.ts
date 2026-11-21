#!/usr/bin/env bun
import { newGroupKey, PROTOCOL_VERSION, unlockPrivateKey, wrapGroupKey } from "@cfs/core";
import { anonymous, CliError, connect, readSecret, writeSecret } from "./client.ts";
import {
  clearSession,
  loadSession,
  projectFile,
  resolveHost,
  saveHost,
  saveSession,
} from "./config.ts";
import { askHidden } from "./prompt.ts";

const USAGE = `cfs: secrets for your team, locked before they leave your device

Usage:
  cfs login [--host <url>]            sign in with your browser
  cfs unlock                          unlock your vault on this device
  cfs lock                            forget the unlocked vault
  cfs whoami
  cfs list
  cfs get <secret> [<name>]
  cfs set <secret> NAME=value ...     reads a .env from stdin if no pairs are given
  cfs run [<secret>] [--env <name>] -- <command>
  cfs group create <name> [--member <email> ...]

Apps and agents set CFS_KIT instead of logging in.
Host: --host, CFS_HOST, .cfs.json, or ~/.config/cfs/config.json.`;

function flag(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  if (i < 0) return undefined;
  const v = args[i + 1];
  args.splice(i, v ? 2 : 1);
  return v;
}
function flagAll(args: string[], name: string): string[] {
  const out: string[] = [];
  for (let v = flag(args, name); v; v = flag(args, name)) out.push(v);
  return out;
}

function parseEnv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!m) continue;
    let v = m[2] as string;
    if (/^(".*"|'.*')$/.test(v)) v = v.slice(1, -1);
    out[m[1] as string] = v;
  }
  return out;
}

async function login(args: string[]) {
  const host = resolveHost(flag(args, "--host"));
  if (!host) throw new CliError("Which server? Run: cfs login --host https://secrets.example.com");
  const api = anonymous(host);
  const start = await api.call<{
    deviceCode: string;
    userCode: string;
    expiresIn: number;
    interval: number;
  }>("POST", "/cli/start", { device: process.env.HOSTNAME ?? "cli" });
  if (start.status !== 200) throw new CliError("The server did not start a login.");
  console.log(`Open ${host}/cli/authorize and enter this code:\n\n    ${start.body.userCode}\n`);
  const until = Date.now() + start.body.expiresIn * 1000;
  while (Date.now() < until) {
    await Bun.sleep(start.body.interval * 1000);
    const p = await api.call<{ token?: string; expiresIn?: number }>("POST", "/cli/poll", {
      deviceCode: start.body.deviceCode,
    });
    if (p.status === 200 && p.body.token) {
      saveHost(host);
      saveSession({
        host,
        token: p.body.token,
        expiresAt: Math.floor(Date.now() / 1000) + (p.body.expiresIn ?? 3600),
      });
      console.log("Signed in. Next: cfs unlock");
      return;
    }
    if (p.status === 410) break;
  }
  throw new CliError("The code expired. Run cfs login again.");
}

async function unlock() {
  const c = await connect();
  const me = await c.call<{ vaultReady: boolean; lockedKey: string | null }>("GET", "/whoami");
  if (!me.body.vaultReady || !me.body.lockedKey)
    throw new CliError(
      "Your vault is not set up yet. Open the web app and choose a vault password first.",
    );
  const pw = await askHidden("Vault password: ");
  let key: string;
  try {
    key = await unlockPrivateKey(me.body.lockedKey, pw);
  } catch {
    throw new CliError("That vault password did not work.");
  }
  const s = loadSession();
  if (!s) throw new CliError("Not signed in.");
  saveSession({ ...s, privateKey: key });
  console.log("Unlocked until your session ends.");
}

async function groupCreate(args: string[]) {
  const emails = flagAll(args, "--member").map((e) => e.toLowerCase());
  const prefix = args[0];
  if (!prefix) throw new CliError("Usage: cfs group create <name> [--member <email> ...]");
  const c = await connect();
  if (!c.privateKey) throw new CliError("Your vault is locked. Run: cfs unlock");
  const [me, ids] = await Promise.all([
    c.call<{ name: string }>("GET", "/whoami"),
    c.call<{ id: string; name: string; publicKey: string | null }[]>("GET", "/identities"),
  ]);
  if (ids.status !== 200) throw new CliError("Only admins can create groups.");
  const names = new Set([me.body.name, ...emails]);
  const members = [];
  const gk = await newGroupKey();
  for (const n of names) {
    const m = ids.body.find((i) => i.name === n);
    if (!m) throw new CliError(`${n} is not invited yet.`);
    if (!m.publicKey) throw new CliError(`${n} has not set up a vault yet.`);
    members.push({ identityId: m.id, wrappedKey: await wrapGroupKey(gk, m.publicKey, prefix, 1) });
  }
  const r = await c.call("POST", "/keyrings", { prefix, members });
  if (r.status !== 201)
    throw new CliError(
      `Could not create the group: ${(r.body as { error?: string }).error ?? r.status}`,
    );
  console.log(`Group "${prefix}" created with ${members.length} member(s).`);
}

async function main() {
  const args = process.argv.slice(2);
  const cmd = args.shift();
  if (!cmd || cmd === "--help" || cmd === "-h" || cmd === "help") return console.log(USAGE);
  if (cmd === "--version" || cmd === "-v")
    return console.log(`cfs 0.0.0 (protocol ${PROTOCOL_VERSION})`);

  const hostFlag = flag(args, "--host");
  switch (cmd) {
    case "login":
      return login(hostFlag ? ["--host", hostFlag, ...args] : args);
    case "unlock":
      return unlock();
    case "lock":
      clearSession();
      return console.log("Locked.");
    case "whoami": {
      const c = await connect(hostFlag);
      const w = await c.call<{ name: string; kind: string; role: string; vaultReady: boolean }>(
        "GET",
        "/whoami",
      );
      return console.log(
        `${w.body.name} (${w.body.kind}, ${w.body.role}) on ${c.host}${c.privateKey ? ", vault unlocked" : ", vault locked"}`,
      );
    }
    case "list": {
      const c = await connect(hostFlag);
      const r = await c.call<{ path: string; version: number; names: string[] }[]>(
        "GET",
        "/secrets",
      );
      if (r.status !== 200) throw new CliError("Could not list secrets.");
      for (const s of r.body) console.log(`${s.path}  v${s.version}  ${s.names.join(", ")}`);
      return;
    }
    case "get": {
      const [path, name] = args;
      if (!path) throw new CliError("Usage: cfs get <secret> [<name>]");
      const { values } = await readSecret(await connect(hostFlag), path);
      if (name) {
        if (!(name in values)) throw new CliError(`"${name}" is not in ${path}.`);
        return console.log(values[name]);
      }
      for (const [k, v] of Object.entries(values)) console.log(`${k}=${v}`);
      return;
    }
    case "set": {
      const path = args.shift();
      if (!path) throw new CliError("Usage: cfs set <secret> NAME=value ...");
      let change: Record<string, string> = {};
      if (args.length) {
        for (const a of args) {
          const i = a.indexOf("=");
          if (i < 1) throw new CliError(`"${a}" is not NAME=value.`);
          change[a.slice(0, i)] = a.slice(i + 1);
        }
      } else if (!process.stdin.isTTY) change = parseEnv(await Bun.stdin.text());
      if (!Object.keys(change).length)
        throw new CliError("Nothing to save. Give NAME=value pairs or pipe a .env file.");
      const v = await writeSecret(await connect(hostFlag), path, change);
      return console.log(
        `Saved ${path} as version ${v} (${Object.keys(change).length} value(s) changed).`,
      );
    }
    case "run": {
      const dd = args.indexOf("--");
      if (dd < 0 || dd === args.length - 1)
        throw new CliError("Usage: cfs run [<secret>] [--env <name>] -- <command>");
      const before = args.slice(0, dd);
      const command = args.slice(dd + 1);
      const env = flag(before, "--env") ?? "dev";
      let path = before[0];
      if (!path) {
        const project = projectFile().project;
        if (!project) throw new CliError("No secret given and no project in .cfs.json.");
        path = `${project}/${env}`;
      }
      const { values } = await readSecret(await connect(hostFlag), path);
      const child = Bun.spawn(command, {
        env: { ...process.env, ...values },
        stdio: ["inherit", "inherit", "inherit"],
      });
      process.exitCode = await child.exited;
      return;
    }
    case "group":
      if (args.shift() === "create") return groupCreate(args);
      throw new CliError("Usage: cfs group create <name> [--member <email> ...]");
    default:
      console.error(USAGE);
      process.exitCode = 1;
  }
}

main().catch((e) => {
  console.error(e instanceof CliError || e instanceof Error ? e.message : String(e));
  process.exitCode = 1;
});
