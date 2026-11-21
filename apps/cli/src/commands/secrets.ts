import { flag, parseEnv } from "../args.ts";
import { CliError, connect, readSecret, writeSecret } from "../client.ts";
import { projectFile } from "../config.ts";
import type { Commands } from "./types.ts";

export const secrets: Commands = {
  list: {
    help: "cfs list",
    run: async (_a, h) => {
      const c = await connect(h);
      const r = await c.call<{ path: string; version: number; names: string[] }[]>(
        "GET",
        "/secrets",
      );
      if (r.status !== 200) throw new CliError("Could not list secrets.");
      for (const s of r.body) console.log(`${s.path}  v${s.version}  ${s.names.join(", ")}`);
    },
  },
  get: {
    help: "cfs get <secret> [<name>]",
    run: async (a, h) => {
      const [path, name] = a;
      if (!path) throw new CliError("Usage: cfs get <secret> [<name>]");
      const { values } = await readSecret(await connect(h), path);
      if (name) {
        if (!(name in values)) throw new CliError(`"${name}" is not in ${path}.`);
        return console.log(values[name]);
      }
      for (const [k, v] of Object.entries(values)) console.log(`${k}=${v}`);
    },
  },
  set: {
    help: "cfs set <secret> NAME=value ...     reads a .env from stdin if no pairs are given",
    run: async (a, h) => {
      const path = a.shift();
      if (!path) throw new CliError("Usage: cfs set <secret> NAME=value ...");
      let change: Record<string, string> = {};
      if (a.length) {
        for (const x of a) {
          const i = x.indexOf("=");
          if (i < 1) throw new CliError(`"${x}" is not NAME=value.`);
          change[x.slice(0, i)] = x.slice(i + 1);
        }
      } else if (!process.stdin.isTTY) change = parseEnv(await Bun.stdin.text());
      if (!Object.keys(change).length)
        throw new CliError("Nothing to save. Give NAME=value pairs or pipe a .env file.");
      const v = await writeSecret(await connect(h), path, change);
      console.log(
        `Saved ${path} as version ${v} (${Object.keys(change).length} value(s) changed).`,
      );
    },
  },
  run: {
    help: "cfs run [<secret>] [--env <name>] -- <command>",
    run: async (a, h) => {
      const dd = a.indexOf("--");
      if (dd < 0 || dd === a.length - 1)
        throw new CliError("Usage: cfs run [<secret>] [--env <name>] -- <command>");
      const before = a.slice(0, dd);
      const command = a.slice(dd + 1);
      const env = flag(before, "--env") ?? "dev";
      let path = before[0];
      if (!path) {
        const project = projectFile().project;
        if (!project) throw new CliError("No secret given and no project in .cfs.json.");
        path = `${project}/${env}`;
      }
      const { values } = await readSecret(await connect(h), path);
      const child = Bun.spawn(command, {
        env: { ...process.env, ...values },
        stdio: ["inherit", "inherit", "inherit"],
      });
      process.exitCode = await child.exited;
    },
  },
};
