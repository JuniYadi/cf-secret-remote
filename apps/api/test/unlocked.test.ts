import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { admin, api, makeIdentity } from "./helpers.ts";

async function stamp(id: string): Promise<number | null> {
  const row = await env.DB.prepare("SELECT last_unlocked_at FROM identity WHERE id = ?")
    .bind(id)
    .first<{ last_unlocked_at: number | null }>();
  if (!row) throw new Error(`Missing identity ${id}`);
  return row.last_unlocked_at;
}

describe("last unlocked", () => {
  it("stamps only the caller, throttles for ten minutes, and restricts the directory to admins", async () => {
    const a = await admin();
    const member = await makeIdentity();
    expect((await api("POST", "/me/unlocked", member.token, { id: a.id })).status).toBe(200);
    const first = await stamp(member.id);
    expect(first).toBeGreaterThan(0);
    expect(await stamp(a.id)).toBeNull();
    expect((await api("GET", "/identities", member.token)).status).toBe(403);
    const list = await api("GET", "/identities", a.token);
    expect(list.body.find((row: { id: string }) => row.id === member.id).last_unlocked_at).toBe(
      first,
    );
    const recent = Math.floor(Date.now() / 1000) - 500;
    await env.DB.prepare("UPDATE identity SET last_unlocked_at = ? WHERE id = ?")
      .bind(recent, member.id)
      .run();
    await api("POST", "/me/unlocked", member.token);
    expect(await stamp(member.id)).toBe(recent);
    const old = Math.floor(Date.now() / 1000) - 601;
    await env.DB.prepare("UPDATE identity SET last_unlocked_at = ? WHERE id = ?")
      .bind(old, member.id)
      .run();
    await api("POST", "/me/unlocked", member.token);
    expect(await stamp(member.id)).toBeGreaterThan(old);
  });

  it("succeeds if the stamp write fails", async () => {
    const member = await makeIdentity();
    await env.DB.exec(
      "CREATE TRIGGER fail_unlock BEFORE UPDATE OF last_unlocked_at ON identity BEGIN SELECT RAISE(ABORT, 'quota'); END;",
    );
    try {
      expect((await api("POST", "/me/unlocked", member.token)).status).toBe(200);
      expect(await stamp(member.id)).toBeNull();
    } finally {
      await env.DB.exec("DROP TRIGGER fail_unlock;");
    }
  });
});
