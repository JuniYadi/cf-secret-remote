import { describe, expect, test } from "bun:test";
import { CliError } from "../client.ts";
import { CHUNK_SIZE, chunks, group, remainingMembers } from "./group.ts";

// ADR 14: the CLI's rotation helpers and argument checks. Network paths are covered by the API tests.

describe("group rotation helpers", () => {
  test("chunks hold at most 50 secrets and keep order", () => {
    expect(CHUNK_SIZE).toBe(50);
    const items = Array.from({ length: 120 }, (_, i) => i);
    const parts = chunks(items);
    expect(parts.map((p) => p.length)).toEqual([50, 50, 20]);
    expect(parts.flat()).toEqual(items);
    expect(chunks([])).toEqual([]);
  });

  test("the new key goes to everyone except the removed identity", () => {
    const members = [{ identityId: "a" }, { identityId: "b" }, { identityId: "c" }];
    expect(remainingMembers(members, "b")).toEqual([{ identityId: "a" }, { identityId: "c" }]);
    expect(remainingMembers(members, "zz")).toEqual(members);
  });
});

describe("group command arguments", () => {
  const run = (...args: string[]) => {
    if (!group.group) throw new Error("group command missing");
    return group.group.run([...args]);
  };

  test("unknown or incomplete subcommands show usage without calling the server", async () => {
    for (const args of [["nope"], [], ["add-member", "pay"], ["remove-member"]]) {
      await expect(run(...args)).rejects.toBeInstanceOf(CliError);
    }
    await expect(run("add-member", "pay")).rejects.toThrow("cfs group add-member");
  });
});
