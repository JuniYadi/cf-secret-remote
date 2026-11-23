import { expect, test } from "bun:test";
import { createPersonalKeyring, generateKeyPair, type Login, sealLogin } from "@cfs/core";
import type { Client } from "../client.ts";
import { accounts, findAccount, keptPassword, reveal } from "./account.ts";

test("decrypts the list, rejects ambiguous matches, and audits reveals", async () => {
  const pair = await generateKeyPair();
  const personal = await createPersonalKeyring(pair.publicKey, "personal-test");
  const login: Login = {
    v: 1,
    name: "site",
    url: "",
    environment: "dev",
    role: "admin",
    username: "alice",
    password: "secret",
    totp: "",
    notes: "",
  };
  const rows = await Promise.all(
    ["one", "two"].map(async (id) => ({
      id,
      keyringId: "ring",
      keyringVersion: 1,
      version: 1,
      ...(await sealLogin(personal.key, id, 1, login)),
    })),
  );
  const calls: { path: string; body: unknown }[] = [];
  const c = {
    privateKey: pair.privateKey,
    call: async (_method: string, path: string, body: unknown) => {
      calls.push({ path, body });
      return {
        status: 200,
        body:
          path === "/logins"
            ? rows
            : path === "/keyrings"
              ? []
              : path === "/whoami"
                ? { publicKey: pair.publicKey }
                : path === "/me/personal-keyring"
                  ? {
                      id: "ring",
                      prefix: "personal-test",
                      version: 1,
                      wrappedKey: personal.wrappedKey,
                    }
                  : { ok: true },
      };
    },
  } as unknown as Client;
  const result = await accounts(c);
  expect(result[0]?.login.password).toBe("secret");
  expect(() => findAccount(result, "site")).toThrow("Ambiguous");
  expect(() => findAccount(result, "missing")).toThrow("No account");
  await reveal(c, result[0]!, "job-1", "totp");
  expect(calls.at(-1)).toEqual({
    path: "/logins/one/reveal",
    body: { purpose: "job-1", field: "totp" },
  });
});

test("edit keeps the current password when none is typed", () => {
  expect(keptPassword("", "old")).toBe("old");
  expect(keptPassword("new", "old")).toBe("new");
});
