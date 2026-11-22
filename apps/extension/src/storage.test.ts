import { afterEach, expect, it, vi } from "vitest";
import { getSession, sync } from "./client.ts";

afterEach(() => vi.unstubAllGlobals());
it("persists only encrypted login data locally and expires the session key", async () => {
  const local: Record<string, unknown> = { host: "https://vault.example" };
  const session: Record<string, unknown> = {
    session: {
      token: "cfs_secret",
      tokenExpires: Date.now() + 10000,
      privateKey: "private",
      publicKey: "public",
      unlockExpires: Date.now() - 1,
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
