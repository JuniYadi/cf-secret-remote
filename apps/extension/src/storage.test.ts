import { afterEach, expect, it, vi } from "vitest";
import { getSession, openLogins, sync } from "./client.ts";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});
it("persists only encrypted login data locally and expires the session key", async () => {
  const local: Record<string, unknown> = { host: "https://vault.example" };
  const session: Record<string, unknown> = {
    session: {
      token: "cfs_secret",
      tokenExpires: Date.now() + 10000,
      privateKey: "private",
      publicKey: "public",
      lockAt: Date.now() - 1,
    },
  };
  const area = (data: Record<string, unknown>) => ({
    get: async () => ({ ...data }),
    set: async (v: object) => Object.assign(data, v),
    remove: async (key: string) => {
      delete data[key];
    },
  });
  vi.stubGlobal("chrome", { storage: { local: area(local), session: area(session) } });
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify([{ id: "1", ciphertext: "encrypted", wrappedDek: "wrapped" }]),
          { headers: { ETag: '"v1"' } },
        ),
    ),
  );
  await sync("https://vault.example", "cfs_secret");
  const stored = JSON.stringify(local);
  expect(stored).not.toContain("cfs_secret");
  expect(stored).not.toContain("private");
  expect(stored).toContain("encrypted");
  expect((await getSession())?.privateKey).toBeUndefined();
  expect(JSON.stringify(session)).not.toContain("private");
});

it("wipes an expired key and refuses to use it", async () => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
  const stale = {
    token: "token",
    tokenExpires: Date.now() + 10000,
    privateKey: "private",
    publicKey: "public",
    lockAt: Date.now() + 1000,
  };
  const data: Record<string, unknown> = { session: { ...stale } };
  vi.stubGlobal("chrome", {
    storage: {
      session: {
        get: async () => structuredClone(data),
        set: async (value: object) => Object.assign(data, structuredClone(value)),
        remove: async (key: string) => {
          delete data[key];
        },
      },
    },
  });
  vi.advanceTimersByTime(1000);
  expect((await getSession())?.privateKey).toBeUndefined();
  expect(JSON.stringify(data)).not.toContain("private");
  await expect(openLogins("https://vault.example", stale)).rejects.toThrow("Locked");
});
