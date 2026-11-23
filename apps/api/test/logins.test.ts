import { env, SELF } from "cloudflare:test";
import { loginFingerprints, newGroupKey, openLogin, sealLogin } from "@cfs/core";
import { describe, expect, it } from "vitest";
import { api, makeIdentity } from "./helpers.ts";

const value = {
  v: 1 as const,
  name: "private name",
  url: "https://private.example",
  environment: "dev",
  role: "user",
  username: "u",
  password: "secret",
  totp: "",
  notes: "",
};
describe("Login API", () => {
  it("syncs, versions, restores, moves and deletes with membership checks", async () => {
    const user = await makeIdentity({ role: "admin" });
    const stranger = await makeIdentity();
    const id = crypto.randomUUID();
    const keyringId = crypto.randomUUID();
    const destination = crypto.randomUUID();
    const key = await newGroupKey();
    const nextKey = await newGroupKey();
    for (const group of [keyringId, destination]) {
      await env.DB.batch([
        env.DB.prepare("INSERT INTO keyring (id, prefix, created_at) VALUES (?, ?, 1)").bind(
          group,
          group,
        ),
        env.DB.prepare(
          "INSERT INTO keyring_member (keyring_id, identity_id, version, wrapped_key) VALUES (?, ?, 1, 'key')",
        ).bind(group, user.id),
      ]);
    }
    const payload = async (version: number, group = keyringId, groupKey = key) => ({
      id,
      keyringId: group,
      keyringVersion: 1,
      version,
      ...(await sealLogin(groupKey, id, version, value)),
      fps: await loginFingerprints(groupKey, id, value),
    });
    expect((await api("POST", "/logins", user.token, await payload(1))).status).toBe(201);

    expect((await api("GET", `/logins/${id}`, stranger.token)).status).toBe(404);
    expect((await api("PUT", `/logins/${id}`, stranger.token, await payload(2))).status).toBe(404);
    const list = await SELF.fetch("http://t.test/api/v1/logins", {
      headers: { authorization: `Bearer ${user.token}` },
    });
    expect(list.status).toBe(200);
    expect(((await list.json()) as { id: string }[]).some((l) => l.id === id)).toBe(true);
    const etag = list.headers.get("etag");
    expect(etag).toMatch(/^"[0-9a-f]+"$/);
    const cached = await SELF.fetch("http://t.test/api/v1/logins", {
      headers: { authorization: `Bearer ${user.token}`, "if-none-match": etag ?? "" },
    });
    expect(cached.status).toBe(304);
    expect((await api("GET", `/logins/${id}`, user.token)).body.version).toBe(1);
    expect((await api("PUT", `/logins/${id}`, user.token, await payload(2))).status).toBe(200);
    expect((await api("GET", `/logins/${id}/versions`, user.token)).body).toHaveLength(2);
    expect((await api("GET", `/logins/${id}/versions/1`, user.token)).body.version).toBe(1);
    expect(
      (await api("POST", `/logins/${id}/versions/1/restore`, user.token, await payload(3))).status,
    ).toBe(200);
    expect(
      (await api("POST", `/logins/${id}/move`, user.token, await payload(4, destination, nextKey)))
        .status,
    ).toBe(200);
    expect((await api("GET", `/logins/${id}`, user.token)).body.keyringId).toBe(destination);
    expect(
      (
        await api("POST", `/logins/${id}/reveal`, user.token, {
          field: "password",
          purpose: "test run",
        })
      ).status,
    ).toBe(200);
    expect((await api("POST", `/logins/${id}/fill`, user.token, {})).status).toBe(200);
    const entries = await env.DB.prepare(
      "SELECT entry FROM audit WHERE json_extract(entry, '$.path') = ? ORDER BY seq",
    )
      .bind(id)
      .all<{ entry: string }>();
    const events = entries.results.map(
      (row) => JSON.parse(row.entry) as { action: string; purpose?: string; version: number },
    );
    expect(events.map((e) => e.action)).toEqual([
      "login.create",
      "login.update",
      "login.restore",
      "login.move",
      "login.reveal",
      "login.fill",
    ]);
    expect(events[4]?.purpose).toBe("test run");
    expect(events.map((e) => e.version)).toEqual([1, 2, 3, 4, 4, 4]);
    expect(JSON.stringify(events)).not.toContain(value.name);
    expect(JSON.stringify(events)).not.toContain(value.url);

    expect((await api("DELETE", `/logins/${id}`, user.token)).status).toBe(200);
    const deleted = await env.DB.prepare(
      "SELECT entry FROM audit WHERE json_extract(entry, '$.path') = ? ORDER BY seq DESC LIMIT 1",
    )
      .bind(id)
      .first<{ entry: string }>();
    expect(JSON.parse(deleted?.entry ?? "{}").action).toBe("login.delete");

    expect((await api("GET", `/logins/${id}`, user.token)).status).toBe(404);
    expect((await api("POST", `/logins/${id}/undelete`, user.token)).status).toBe(200);
    const restoredAudit = await env.DB.prepare(
      "SELECT entry FROM audit WHERE json_extract(entry, '$.path') = ? ORDER BY seq DESC LIMIT 1",
    )
      .bind(id)
      .first<{ entry: string }>();
    const restoredEvent = JSON.parse(restoredAudit?.entry ?? "{}");
    expect(restoredEvent).toMatchObject({
      action: "login.undelete",
      path: id,
      version: 4,
      who: user.name,
    });
    expect(restoredAudit?.entry).not.toContain(value.name);
    expect(restoredAudit?.entry).not.toContain(value.url);
    await api("DELETE", `/logins/${id}`, user.token);
    await env.DB.prepare("UPDATE login SET deleted_at = ? WHERE id = ?")
      .bind(Math.floor(Date.now() / 1000) - 31 * 86400, id)
      .run();
    expect((await api("POST", `/logins/${id}/undelete`, user.token)).status).toBe(410);
  });
  it("rotates live and deleted logins, refuses incomplete commit and cleans abort", async () => {
    const admin = await makeIdentity({ role: "admin" });
    const removed = await makeIdentity();
    const group = crypto.randomUUID();
    const oldKey = await newGroupKey();
    const newKey = await newGroupKey();
    await env.DB.prepare("INSERT INTO keyring (id, prefix, created_at) VALUES (?, ?, 1)")
      .bind(group, group)
      .run();
    for (const user of [admin, removed])
      await env.DB.prepare(
        "INSERT INTO keyring_member (keyring_id, identity_id, version, wrapped_key) VALUES (?, ?, 1, 'key')",
      )
        .bind(group, user.id)
        .run();
    const ids = [crypto.randomUUID(), crypto.randomUUID()];
    for (const id of ids)
      expect(
        (
          await api("POST", "/logins", admin.token, {
            id,
            keyringId: group,
            keyringVersion: 1,
            version: 1,
            ...(await sealLogin(oldKey, id, 1, value)),
            fps: await loginFingerprints(oldKey, id, value),
          })
        ).status,
      ).toBe(201);
    await api("DELETE", `/logins/${ids[1]}`, admin.token);
    const start = () =>
      api("POST", `/keyrings/${group}/rotate/start`, admin.token, {
        removeIdentityId: removed.id,
        members: [{ identityId: admin.id, wrappedKey: "new" }],
      });
    const stage = async () => {
      const logins = await Promise.all(
        ids.map(async (id) => ({
          id,
          version: 2,
          ...(await sealLogin(newKey, id, 2, value)),
          fps: await loginFingerprints(newKey, id, value),
        })),
      );
      return api("POST", `/keyrings/${group}/rotate/chunk`, admin.token, {
        keyringVersion: 2,
        logins,
      });
    };
    expect((await start()).status).toBe(200);
    expect((await api("GET", `/keyrings/${group}/rotate/logins`, admin.token)).body).toHaveLength(
      2,
    );
    expect((await api("POST", `/keyrings/${group}/rotate/commit`, admin.token, {})).status).toBe(
      409,
    );
    expect((await stage()).status).toBe(200);
    expect((await api("POST", `/keyrings/${group}/rotate/abort`, admin.token, {})).status).toBe(
      200,
    );
    expect(
      (
        await env.DB.prepare(
          "SELECT COUNT(*) AS n FROM login_version WHERE keyring_id = ? AND keyring_version = 2",
        )
          .bind(group)
          .first<{ n: number }>()
      )?.n,
    ).toBe(0);
    expect((await start()).status).toBe(200);
    expect((await stage()).status).toBe(200);
    expect((await api("POST", `/keyrings/${group}/rotate/commit`, admin.token, {})).status).toBe(
      200,
    );
    expect((await api("GET", `/logins/${ids[0]}`, removed.token)).status).toBe(404);
    expect((await api("GET", "/logins", removed.token)).body).toEqual([]);
    const row = (await api("GET", `/logins/${ids[0]}`, admin.token)).body;
    expect(row.keyringVersion).toBe(2);
    expect(
      await openLogin(newKey, ids[0] as string, row.version, row.wrappedDek, row.ciphertext),
    ).toEqual(value);
    expect((await api("POST", `/logins/${ids[1]}/undelete`, admin.token)).status).toBe(200);
    const restored = (await api("GET", `/logins/${ids[1]}`, admin.token)).body;
    expect(
      await openLogin(
        newKey,
        ids[1] as string,
        restored.version,
        restored.wrappedDek,
        restored.ciphertext,
      ),
    ).toEqual(value);
  });
  it("rejects oversized ciphertext", async () => {
    const user = await makeIdentity();
    const fps = Object.fromEntries(
      Object.keys(value)
        .filter((k) => k !== "v")
        .map((k) => [k, "0000000000000000"]),
    );
    const res = await api("POST", "/logins", user.token, {
      id: "too-large",
      keyringId: "group",
      keyringVersion: 1,
      version: 1,
      wrappedDek: "wrapped",
      ciphertext: `v1.a.${"A".repeat(90000)}`,
      fps,
    });
    expect(res.status).toBe(413);
  });
});
