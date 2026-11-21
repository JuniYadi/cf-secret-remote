#!/usr/bin/env bun
import { PROTOCOL_VERSION } from "@cfs/core";

const USAGE = `cfs: secrets for your team, locked before they leave your device

Usage:
  cfs login --host <url>
  cfs unlock
  cfs run [<secret>] [--env <name>] -- <command>
  cfs get <secret> [<key>]
  cfs set <secret>
  cfs list
  cfs whoami
  cfs init

Not implemented yet.`;

const args = process.argv.slice(2);

if (args.includes("--version") || args.includes("-v")) {
  console.log(`cfs 0.0.0 (protocol ${PROTOCOL_VERSION})`);
} else {
  console.log(USAGE);
  if (args.length > 0 && !args.includes("--help") && !args.includes("-h")) process.exitCode = 1;
}
