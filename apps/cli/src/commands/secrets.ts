import { totp } from "@cfs/core";
import { flag, flagAll, parseEnv } from "../args.ts";
import { CliError, connect, readSecret, writeSecret } from "../client.ts";
import { mergeSecrets, projectFile, runPaths } from "../config.ts";
import { accounts, findAccount, reveal } from "./account.ts";
import type { Commands } from "./types.ts";

export function accountPrefixes(specs: string[]): string[] {
  const names = specs.map((spec) =>
    (spec.split(":")[0] ?? "").toUpperCase().replace(/[^A-Z0-9_]/g, "_"),
  );
  if (names.some((name) => !name) || new Set(names).size !== names.length)
    throw new CliError("Account names must be nonempty and must not collide when normalised.");
  return names;
}

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
    help: "cfs run [<secret>] [--env <name>] [--account <name>[:env[:role]]] [--purpose <text>] -- <command>",
    run: async (a, h) => {
      const dd = a.indexOf("--");
      if (dd < 0 || dd === a.length - 1)
        throw new CliError("Usage: cfs run [<secret>] [--env <name>] -- <command>");
      const before = a.slice(0, dd);
      const command = a.slice(dd + 1);
      const env = flag(before, "--env");
      const accountNames = flagAll(before, "--account");
      const purpose = flag(before, "--purpose");
      const normalised = accountPrefixes(accountNames);
      const c = await connect(h);
      let values: Record<string, string>;
      if (before[0]) {
        values = (await readSecret(c, before[0])).values;
      } else {
        // ADR 25: explicit envs in .cfs.json, later secrets override earlier ones.
        const plan = runPaths(projectFile(), env);
        values = await mergeSecrets(
          plan.paths,
          async (p) => (await readSecret(c, p)).values,
          plan.env,
        );
      }
      if (accountNames.length) {
        const items = await accounts(c);
        for (const [i, spec] of accountNames.entries()) {
          const parts = spec.split(":");
          if (parts.length > 3 || !parts[0])
            throw new CliError(`Invalid account selector: ${spec}`);
          const item = findAccount(items, parts[0], parts[1] || undefined, parts[2] || undefined);
          await reveal(c, item, purpose);
          const prefix = `CFS_${normalised[i]}`;
          values[`${prefix}_USER`] = item.login.username;
          values[`${prefix}_PASS`] = item.login.password;
          values[`${prefix}_TOTP`] = item.login.totp ? await totp(item.login.totp) : "";
        }
      }
      const child = Bun.spawn(command, {
        env: { ...process.env, ...values },
        stdio: ["inherit", "inherit", "inherit"],
      });
      process.exitCode = await child.exited;
    },
  },
};
