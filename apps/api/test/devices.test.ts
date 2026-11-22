import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { LAST_USED_EVERY } from "../src/auth.ts";
import { sha256Hex } from "../src/util.ts";
import { api, makeIdentity } from "./helpers.ts";

// ADR 24 (Devices): "last used" on each session, and "Sign out everywhere".

const db = env.DB;

type Device = { id: string; device: string | null; lastUsedAt: number | null };

async function lastUsed(token: string): Promise<number | null> {
  const row = await db
    .prepare("SELECT last_used_at AS t FROM session WHERE token_hash = ?")
    .bind(await sha256Hex(token))
    .first<{ t: number | null }>();
  return row?.t ?? null;
}

describe("session last used", () => {
  it("stamps a session on first use and shows it in the list", async () => {
    const me = await makeIdentity({});
    expect(await lastUsed(me.token)).toBeNull();
    const list = await api<Device[]>("GET", "/sessions", me.token);
    expect(list.status).toBe(200);
    const stamped = await lastUsed(me.token);
    expect(stamped).not.toBeNull();
    // The listing was read after the stamp was written in the same request.
    expect(list.body[0]?.lastUsedAt).toBe(stamped);
  });

  it("does not write again within the window, and does after it", async () => {
    const me = await makeIdentity({});
    await api("GET", "/sessions", me.token);
    const first = await lastUsed(me.token);
    await api("GET", "/sessions", me.token);
    expect(await lastUsed(me.token)).toBe(first);

    const old = (first ?? 0) - LAST_USED_EVERY - 5;
    await db
      .prepare("UPDATE session SET last_used_at = ? WHERE token_hash = ?")
      .bind(old, await sha256Hex(me.token))
      .run();
    await api("GET", "/sessions", me.token);
    expect(await lastUsed(me.token)).toBeGreaterThan(old);
  });
});

describe("DELETE /sessions", () => {
  async function extraSession(identityId: string, token: string) {
    await db
      .prepare(
        "INSERT INTO session (token_hash, identity_id, kind, device, created_at, expires_at) VALUES (?, ?, 'cli', 'laptop', 1, 9999999999)",
      )
      .bind(await sha256Hex(token), identityId)
      .run();
  }

  it("ends every session of the caller and none of anyone else's, and logs the count", async () => {
    const me = await makeIdentity({});
    const other = await makeIdentity({});
    await extraSession(me.id, "cfs_extra_one");
    await extraSession(me.id, "cfs_extra_two");

    const res = await api<{ ok: boolean; ended: number }>("DELETE", "/sessions", me.token);
    expect(res.status).toBe(200);
    expect(res.body.ended).toBe(3);

    // The caller's own token is gone too, so the next call is refused.
    expect((await api("GET", "/sessions", me.token)).status).toBe(401);
    expect((await api("GET", "/sessions", "cfs_extra_one")).status).toBe(401);
    // Someone else's session is untouched.
    expect((await api("GET", "/sessions", other.token)).status).toBe(200);

    const log = await db
      .prepare("SELECT entry FROM audit WHERE who = ? ORDER BY seq DESC LIMIT 1")
      .bind(me.name)
      .first<{ entry: string }>();
    expect(JSON.parse(log?.entry ?? "{}")).toMatchObject({
      action: "session.revoke",
      note: "all, 3 sessions",
    });
  });
});
