import { generateKeyPair, newGroupKey, wrapGroupKey } from "@cfs/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "./api.ts";
import { setLang } from "./i18n.ts";
import { lock, unlock } from "./keystore.ts";
import {
  isConflict,
  isNoKey,
  loadSecret,
  saveValues,
  secretConflictMessage,
  VaultLockedError,
} from "./secret-store.ts";

// Crypto runs for real here (@cfs/core, WebCrypto). The API is a small fake that keeps what it is sent,
// so the tests can check what the server would see.

const json = (status: number, body: unknown) =>
  new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

interface Fake {
  puts: Record<string, unknown>[];
  stored: Record<string, unknown> | null;
  putStatus: number;
  keyStatus: number;
}

async function setup(prefix = "myapp") {
  const pair = await generateKeyPair();
  const groupKey = await newGroupKey();
  const wrappedKey = await wrapGroupKey(groupKey, pair.publicKey, prefix, 1);
  unlock({ publicKey: pair.publicKey, privateKey: pair.privateKey });
  const fake: Fake = { puts: [], stored: null, putStatus: 200, keyStatus: 200 };
  const fetchMock = vi.fn(async (input: string, init: RequestInit) => {
    const url = new URL(input, "https://cfs.test");
    const method = init.method ?? "GET";
    if (url.pathname === `/api/v1/keyrings/${prefix}/key`) {
      return fake.keyStatus === 200
        ? json(200, { wrappedKey, version: 1 })
        : json(fake.keyStatus, { error: "no key for you in this group" });
    }
    if (url.pathname === "/api/v1/secret" && method === "PUT") {
      const body = JSON.parse(String(init.body)) as Record<string, unknown>;
      fake.puts.push(body);
      if (fake.putStatus !== 200) return json(fake.putStatus, { error: "version changed" });
      fake.stored = {
        path: body.path,
        version: body.version,
        keyringVersion: body.keyringVersion,
        names: body.names,
        wrappedDek: body.wrappedDek,
        ciphertext: body.ciphertext,
        createdAt: 1,
      };
      return json(200, { path: body.path, version: body.version });
    }
    if (url.pathname === "/api/v1/secret" && method === "GET") {
      return fake.stored ? json(200, fake.stored) : json(404, { error: "not found" });
    }
    return json(500, {});
  });
  vi.stubGlobal("fetch", fetchMock);
  return { fake, groupKey, fetchMock };
}

beforeEach(() => {
  lock();
});

afterEach(() => {
  lock();
  vi.unstubAllGlobals();
});

describe("saving a version", () => {
  it("sends sealed envelopes only, never a value, and the next version number", async () => {
    const { fake, groupKey } = await setup();
    const secret = "sk_live_PLAINTEXT_MARKER_123";
    await saveValues({
      path: "myapp/dev",
      values: { API_KEY: secret, DEBUG_MODE: "true" },
      currentVersion: 6,
      groupKey,
      keyVersion: 1,
    });
    const body = fake.puts[0] as Record<string, unknown>;
    expect(JSON.stringify(fake.puts)).not.toContain(secret);
    expect(JSON.stringify(fake.puts)).not.toContain('"true"');
    expect(body.version).toBe(7);
    expect(body.keyringVersion).toBe(1);
    // Names are cleartext by design (ADR 10). Values are not.
    expect(body.names).toEqual(["API_KEY", "DEBUG_MODE"]);
    expect(String(body.ciphertext).startsWith("v1.")).toBe(true);
    expect(String(body.wrappedDek)).toContain(".");
    expect(Object.keys(body.fps as object)).toEqual(["API_KEY", "DEBUG_MODE"]);
    for (const fp of Object.values(body.fps as Record<string, string>)) {
      expect(fp).toMatch(/^[0-9a-f]{16}$/);
    }
  });

  it("writes a new secret as version 1", async () => {
    const { fake, groupKey } = await setup();
    await saveValues({
      path: "myapp/new",
      values: { A: "x" },
      currentVersion: 0,
      groupKey,
      keyVersion: 1,
    });
    expect((fake.puts[0] as Record<string, unknown>).version).toBe(1);
  });

  it("reads back what was saved, through the same keys", async () => {
    const { groupKey } = await setup();
    await saveValues({
      path: "myapp/dev",
      values: { API_KEY: "sk_live_1", MAX: "20" },
      currentVersion: 0,
      groupKey,
      keyVersion: 1,
    });
    const opened = await loadSecret("myapp/dev");
    expect(opened.version).toBe(1);
    expect(opened.values).toEqual({ API_KEY: "sk_live_1", MAX: "20" });
    expect(opened.keyVersion).toBe(1);
  });

  it("reports a version conflict (409) as a conflict, and writes nothing", async () => {
    const { fake, groupKey } = await setup();
    fake.putStatus = 409;
    const err = await saveValues({
      path: "myapp/dev",
      values: { A: "1" },
      currentVersion: 3,
      groupKey,
      keyVersion: 1,
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(isConflict(err)).toBe(true);
    expect(fake.stored).toBeNull();
  });
});

describe("reading", () => {
  it("says so when the person has no key for the group", async () => {
    const { fake } = await setup();
    fake.keyStatus = 404;
    fake.stored = {
      path: "myapp/prod",
      version: 1,
      keyringVersion: 1,
      names: ["A"],
      wrappedDek: "x.y",
      ciphertext: "v1.a.b",
      createdAt: 1,
    };
    const err = await loadSecret("myapp/prod").catch((e: unknown) => e);
    expect(isNoKey(err)).toBe(true);
  });

  it("refuses to open anything while the vault is locked", async () => {
    const { groupKey } = await setup();
    await saveValues({
      path: "myapp/dev",
      values: { A: "1" },
      currentVersion: 0,
      groupKey,
      keyVersion: 1,
    });
    lock();
    await expect(loadSecret("myapp/dev")).rejects.toBeInstanceOf(VaultLockedError);
  });
});

it("explains secret conflicts in both languages", () => {
  const err = new ApiError("conflict", 409, undefined, null, "group_rotating");
  setLang("en");
  expect(secretConflictMessage(err)).toContain("re-locked");
  setLang("id");
  expect(secretConflictMessage(err)).toContain("dikunci ulang");
  setLang("en");
  expect(
    secretConflictMessage(new ApiError("conflict", 409, undefined, null, "secret_deleted")),
  ).toContain("deleted");
  expect(
    secretConflictMessage(new ApiError("conflict", 409, undefined, null, "group_key_changed")),
  ).toContain("key changed");
  expect(
    secretConflictMessage(new ApiError("conflict", 409, undefined, null, "version_conflict")),
  ).toBeUndefined();
});
