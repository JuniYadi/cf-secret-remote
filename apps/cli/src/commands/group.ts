import { newGroupKey, wrapGroupKey } from "@cfs/core";
import { flagAll } from "../args.ts";
import { CliError, connect } from "../client.ts";
import type { Commands } from "./types.ts";

// ADR 14: group create, add-member, remove-member, list.
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

export const group: Commands = {
  group: {
    help: "cfs group create <name> [--member <email> ...]",
    run: (a) => {
      if (a.shift() === "create") return groupCreate(a);
      throw new CliError("Usage: cfs group create <name> [--member <email> ...]");
    },
  },
};
