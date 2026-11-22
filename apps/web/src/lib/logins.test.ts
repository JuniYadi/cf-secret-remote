import { newGroupKey, sealLogin } from "@cfs/core";
import { describe, expect, it, vi } from "vitest";
import { createLoginClient, decryptLoginList, filterLogins, type LoginRecord } from "./logins.ts";

const login = {
  v: 1 as const,
  name: "Example",
  url: "https://example.com",
  environment: "prod",
  role: "admin",
  username: "alice",
  password: "secret",
  totp: "",
  notes: "private",
};
describe("login client", () => {
  it("uses the ETag and reuses the encrypted list on 304", async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify([{ id: "a" }]), { headers: { ETag: '"v1"' } }),
      )
      .mockResolvedValueOnce(new Response(null, { status: 304 }));
    const client = createLoginClient(fetcher);
    expect(await client.list()).toEqual([{ id: "a" }]);
    expect(await client.list()).toEqual([{ id: "a" }]);
    expect(fetcher.mock.calls[1]?.[1].headers).toMatchObject({ "If-None-Match": '"v1"' });
  });
  it("opens with the keyring and version on each record, then filters locally", async () => {
    const key = await newGroupKey();
    const envelope = await sealLogin(key, "a", 1, login);
    const row: LoginRecord = {
      id: "a",
      keyringId: "personal",
      keyringVersion: 2,
      version: 1,
      ...envelope,
      fps: {},
      createdAt: 1,
      updatedAt: 1,
      size: 1,
    };
    const keyFor = vi.fn(async () => key);
    const opened = await decryptLoginList([row], keyFor);
    expect(keyFor).toHaveBeenCalledWith("personal", 2);
    expect(opened[0]?.login).toEqual(login);
    expect(
      filterLogins(opened, {
        query: "EXAMPLE",
        environment: "prod",
        role: "admin",
        keyring: "personal",
      }),
    ).toHaveLength(1);
    expect(filterLogins(opened, { role: "member" })).toHaveLength(0);
    expect(filterLogins(opened, { query: "secret" })).toHaveLength(0);
  });
  it("sends the audit request as JSON", async () => {
    const fetcher = vi.fn(async (_url: string, _init: RequestInit) => new Response('{"ok":true}'));
    await createLoginClient(fetcher).reveal("a", { field: "password" });
    expect(fetcher.mock.calls[0]?.[0]).toBe("/api/v1/logins/a/reveal");
    expect(JSON.parse(String(fetcher.mock.calls[0]?.[1].body))).toEqual({ field: "password" });
  });
});
