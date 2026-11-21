#!/usr/bin/env bun
import { PROTOCOL_VERSION } from "@cfs/core";
import { flag } from "./args.ts";
import { commands } from "./commands/index.ts";

const HEAD = `cfs: secrets for your team, locked before they leave your device

Usage:`;
const TAIL = `
Apps and agents set CFS_KIT instead of logging in.
Host: --host, CFS_HOST, .cfs.json, or ~/.config/cfs/config.json.`;

const usage = () =>
  `${HEAD}\n${Object.values(commands)
    .map((c) => `  ${c.help}`)
    .join("\n")}\n${TAIL}`;

async function main() {
  const args = process.argv.slice(2);
  const cmd = args.shift();
  if (!cmd || cmd === "--help" || cmd === "-h" || cmd === "help") return console.log(usage());
  if (cmd === "--version" || cmd === "-v")
    return console.log(`cfs 0.0.0 (protocol ${PROTOCOL_VERSION})`);
  const hostFlag = flag(args, "--host");
  const c = commands[cmd];
  if (!c) {
    console.error(usage());
    process.exitCode = 1;
    return;
  }
  await c.run(args, hostFlag);
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : String(e));
  process.exitCode = 1;
});
