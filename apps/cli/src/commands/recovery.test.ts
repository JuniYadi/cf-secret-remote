import { describe, expect, test } from "bun:test";
import {
  fingerprintWords,
  generateKeyPair,
  lockPrivateKey,
  newGroupKey,
  recoveryEntropy,
  recoveryPhrase,
  unlockPrivateKey,
  unwrapGroupKey,
  wrapGroupKey,
} from "@cfs/core";
import vector from "../../../../packages/core/test-vectors/recovery.json";
import { CliError, type Client } from "../client.ts";
import { changePassword, grantRecovery, startRecovery } from "./recovery.ts";

// ADR 20 CLI checks with a fake server. The API tests cover the server rules.

type Reply = { status: number; body: unknown };
type Call = { method: string; path: string; body?: any; headers?: Record<string, string> };

/** A Client whose server answers from `routes` ("METHOD /path" -> reply), and records every call. */
function fakeClient(
  privateKey: string | undefined,
  routes: Record<string, Reply | ((c: Call) => Reply)>,
) {
  const calls: Call[] = [];
  const client: Client = {
    host: "https://cfs.test",
    privateKey,
    call: (async (
      method: string,
      path: string,
      body?: unknown,
      headers?: Record<string, string>,
    ) => {
      const call: Call = { method, path, body, headers };
      calls.push(call);
      const route =
        routes[`${method} ${path}`] ?? routes[`${method} ${path.replace(/\/[^/]+$/, "/:x")}`];
      const reply = typeof route === "function" ? route(call) : route;
      if (!reply) return { status: 404, body: { error: "not found" } };
      return reply;
    }) as Client["call"],
  };
  return { client, calls };
}

describe("shared recovery vectors (ADR 20)", () => {
  test("the phrase and the fingerprint words match the vector file", async () => {
    const hex = (h: string) =>
      Uint8Array.from(h.match(/../g)?.map((b) => Number.parseInt(b, 16)) ?? []);
    for (const c of vector.mnemonic) {
      expect(await recoveryPhrase(hex(c.entropyHex))).toBe(c.words);
      expect(await recoveryEntropy(c.words)).toEqual(hex(c.entropyHex));
    }
    for (const c of vector.fingerprint) {
      expect(await fingerprintWords(c.publicKey)).toBe(c.words);
    }
  });
});

describe("cfs recover (ADR 20)", () => {
  test("starting needs a fresh Access token and sends the new key only", async () => {
    const { client, calls } = fakeClient(undefined, {});
    await expect(startRecovery(client, undefined, "a long password")).rejects.toThrow(
      /CFS_ACCESS_TOKEN/,
    );
    expect(calls).toHaveLength(0);

    const { client: ok, calls: okCalls } = fakeClient(undefined, {
      "POST /recovery/request": (c) => ({
        status: 201,
        body: { id: "req1", words: "anchor velvet kiwi sixty", cancelToken: "should-not-print" },
      }),
    });
    const out = await startRecovery(ok, "jwt-token", "a long password");
    expect(out).toEqual({ id: "req1", words: "anchor velvet kiwi sixty" });
    const sent = okCalls[0];
    expect(sent?.headers).toEqual({ "Cf-Access-Jwt-Assertion": "jwt-token" });
    expect(sent?.body.publicKey).toBeTruthy();
    expect(sent?.body.lockedKey.startsWith("p1.")).toBe(true);
    // The words the person reads out are the fingerprint of the key that was sent.
    expect(await fingerprintWords(sent?.body.publicKey)).toMatch(/^\S+ \S+ \S+ \S+$/);
  });

  test("a short new password is refused before anything is sent", async () => {
    const { client, calls } = fakeClient(undefined, {});
    await expect(startRecovery(client, "jwt", "short")).rejects.toBeInstanceOf(CliError);
    expect(calls).toHaveLength(0);
  });
});

describe("cfs recover grant (ADR 20)", () => {
  test("re-wraps only the groups the admin holds, to the new key", async () => {
    const admin = await generateKeyPair();
    const fresh = await generateKeyPair();
    const gA = "cliA";
    const gB = "cliB";
    const gk = await newGroupKey();
    const wrappedForAdmin = await wrapGroupKey(gk, admin.publicKey, gA, 1);

    const { client, calls } = fakeClient(admin.privateKey, {
      "GET /recovery/req1": { status: 200, body: { publicKey: fresh.publicKey, groups: [gA, gB] } },
      "GET /whoami": { status: 200, body: { publicKey: admin.publicKey } },
      [`GET /keyrings/${gA}/key`]: {
        status: 200,
        body: { wrappedKey: wrappedForAdmin, version: 1 },
      },
      [`GET /keyrings/${gB}/key`]: { status: 404, body: { error: "not in group" } },
      "POST /recovery/req1/grant": { status: 200, body: { ok: true, groups: [gA] } },
    });
    const words = await fingerprintWords(fresh.publicKey);
    const out = await grantRecovery(client, "req1", `  ${words.toUpperCase()} `);
    expect(out).toEqual({ granted: [gA], notRewrapped: [gB] });

    const grant = calls.find((c) => c.method === "POST");
    expect(grant?.body.words).toBe(words);
    expect(grant?.body.keys.map((k: { prefix: string }) => k.prefix)).toEqual([gA]);
    const rewrapped = grant?.body.keys[0].wrappedKey as string;
    const opened = await unwrapGroupKey(rewrapped, fresh.privateKey, fresh.publicKey, gA, 1);
    expect(opened).toEqual(gk);
  });

  test("wrong words are sent for counting but nothing is re-wrapped", async () => {
    const admin = await generateKeyPair();
    const fresh = await generateKeyPair();
    const { client, calls } = fakeClient(admin.privateKey, {
      "GET /recovery/req2": { status: 200, body: { publicKey: fresh.publicKey, groups: ["cliA"] } },
      "POST /recovery/req2/grant": {
        status: 403,
        body: { error: "x", attemptsLeft: 4, locked: false },
      },
    });
    await expect(grantRecovery(client, "req2", "abandon abandon abandon abandon")).rejects.toThrow(
      "4 attempts left",
    );
    const grant = calls.find((c) => c.method === "POST");
    expect(grant?.body.keys).toEqual([]);
    expect(calls.some((c) => c.path.startsWith("/keyrings/"))).toBe(false);
  });

  test("a locked request is reported as locked", async () => {
    const admin = await generateKeyPair();
    const fresh = await generateKeyPair();
    const { client } = fakeClient(admin.privateKey, {
      "GET /recovery/req3": { status: 200, body: { publicKey: fresh.publicKey, groups: [] } },
      "POST /recovery/req3/grant": {
        status: 403,
        body: { error: "x", attemptsLeft: 0, locked: true },
      },
    });
    await expect(grantRecovery(client, "req3", "abandon abandon abandon abandon")).rejects.toThrow(
      /locked/,
    );
  });

  test("granting needs an unlocked vault", async () => {
    const { client } = fakeClient(undefined, {});
    await expect(grantRecovery(client, "req4", "a b c d")).rejects.toThrow(/Run: cfs unlock/);
  });
});

describe("cfs passwd (ADR 20)", () => {
  test("re-locks the same private key with the new password", async () => {
    const kp = await generateKeyPair();
    const oldLock = await lockPrivateKey(kp.privateKey, "old password here", 100_000);
    const { client, calls } = fakeClient(kp.privateKey, {
      "GET /whoami": { status: 200, body: { lockedKey: oldLock } },
      "PUT /me/vault": { status: 200, body: { ok: true } },
    });
    await changePassword(client, "old password here", "new password here");
    const put = calls.find((c) => c.method === "PUT");
    expect(put?.path).toBe("/me/vault");
    expect(await unlockPrivateKey(put?.body.lockedKey, "new password here")).toBe(kp.privateKey);
  });

  test("a wrong current password is refused and nothing is sent", async () => {
    const kp = await generateKeyPair();
    const oldLock = await lockPrivateKey(kp.privateKey, "old password here", 100_000);
    const { client, calls } = fakeClient(kp.privateKey, {
      "GET /whoami": { status: 200, body: { lockedKey: oldLock } },
    });
    await expect(changePassword(client, "not the password", "new password here")).rejects.toThrow(
      "did not work",
    );
    expect(calls.some((c) => c.method === "PUT")).toBe(false);
  });

  test("the new password must differ and be long enough", async () => {
    const { client } = fakeClient(undefined, {});
    await expect(changePassword(client, "same password", "same password")).rejects.toThrow(
      /different/,
    );
    await expect(changePassword(client, "old password", "short")).rejects.toThrow(/at least 8/);
  });
});
