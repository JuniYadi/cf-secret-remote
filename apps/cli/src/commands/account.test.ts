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

test("imports with encrypted request bodies to a fake server", async () => {
  const { importAccounts } = await import("./account.ts");
  const pair = await generateKeyPair();
  const personal = await createPersonalKeyring(pair.publicKey, "personal-test");
  const raw = await Bun.file(
    new URL("../../../../packages/core/test-fixtures/import/chrome.csv", import.meta.url),
  ).text();
  const ring = { id: "ring", prefix: "personal-test", version: 1, wrappedKey: personal.wrappedKey };
  const calls: { method: string; path: string; body: unknown }[] = [];
  const server = Bun.serve({
    port: 0,
    async fetch(req) {
      const path = new URL(req.url).pathname;
      const body = req.method === "GET" ? undefined : await req.json();
      calls.push({ method: req.method, path, body });
      return Response.json(
        path === "/logins" && req.method === "GET"
          ? []
          : path === "/keyrings"
            ? []
            : path === "/whoami"
              ? { publicKey: pair.publicKey }
              : path === "/me/personal-keyring"
                ? ring
                : {},
        { status: req.method === "POST" ? 201 : 200 },
      );
    },
  });
  const c = {
    privateKey: pair.privateKey,
    call: async (method: string, path: string, body: unknown) => {
      const response = await fetch(new URL(path, server.url), {
        method,
        ...(body === undefined
          ? {}
          : { body: JSON.stringify(body), headers: { "content-type": "application/json" } }),
      });
      return { status: response.status, body: await response.json() };
    },
  } as unknown as Client;
  try {
    await importAccounts(c, raw, { mode: "skip", yes: true });
  } finally {
    server.stop();
  }
  const write = calls.find((call) => call.method === "POST" && call.path === "/logins")!;
  const sent = JSON.stringify(calls);
  expect(sent).not.toContain(raw);
  expect(sent).not.toContain("fake-password");
  expect(sent).not.toContain("alice");
  const body = write.body as { id: string; ciphertext: string; wrappedDek: string };
  const { openLogin } = await import("@cfs/core");
  expect(
    (await openLogin(personal.key, body.id, 1, body.wrappedDek, body.ciphertext)).password,
  ).toBe("fake-password");
});
