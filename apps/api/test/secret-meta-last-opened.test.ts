import { generateKeyPair, newGroupKey, wrapGroupKey } from "@cfs/core";
import { describe, expect, it } from "vitest";
import { admin, api, makeIdentity } from "./helpers.ts";

type Row = {
  path: string;
  lastOpenedBy: string | null;
  lastOpenedAt: number | null;
};

describe("GET /secret meta and last opened in GET /secrets", () => {
  it("returns meta on read and the last non-merge reader on the list", async () => {
    const kp = await generateKeyPair();
    const adm = await admin(kp.publicKey);
    const bot = await makeIdentity({ kind: "app" });
    const gk = await newGroupKey();
    await api("POST", "/keyrings", adm.token, {
      prefix: "lo",
      members: [{ identityId: adm.id, wrappedKey: await wrapGroupKey(gk, kp.publicKey, "lo", 1) }],
    });
    for (const p of ["lo/a", "lo/b"]) {
      const put = await api("PUT", "/secret", adm.token, {
        path: p,
        names: ["K"],
        wrappedDek: "d",
        ciphertext: "v1.a.b",
        keyringVersion: 1,
        version: 1,
        ...(p === "lo/a" ? { meta: { description: "demo", owner: adm.name } } : {}),
      });
      expect(put.status).toBe(201);
    }
    const pol = await api("POST", "/policies", adm.token, {
      name: "lo-read",
      rules: [{ path: "lo/*", caps: ["read"] }],
    });
    await api("POST", `/policies/${pol.body.id}/assign`, adm.token, { identityId: bot.id });

    const find = async (p: string) =>
      (await api<Row[]>("GET", "/secrets", adm.token)).body.find((s) => s.path === p) as Row;

    // never opened
    expect(await find("lo/a")).toMatchObject({ lastOpenedBy: null, lastOpenedAt: null });

    // meta comes back on the read, {} when unset
    const a = await api("GET", "/secret?path=lo/a", adm.token);
    expect(a.body.meta).toEqual({ description: "demo", owner: adm.name });
    expect((await api("GET", "/secret?path=lo/b", adm.token)).body.meta).toEqual({});
    expect(await find("lo/a")).toMatchObject({ lastOpenedBy: adm.name });
    expect((await find("lo/a")).lastOpenedAt).toBeTypeOf("number");

    // a later reader replaces the earlier one; a merge read does not count
    expect((await api("GET", "/secret?path=lo/a", bot.token)).status).toBe(200);
    expect((await find("lo/a")).lastOpenedBy).toBe(bot.name);
    await api("GET", "/secret?path=lo/a&merge=1", adm.token);
    expect((await find("lo/a")).lastOpenedBy).toBe(bot.name);

    // a denied read does not count
    const denied = await makeIdentity({ kind: "app" });
    expect((await api("GET", "/secret?path=lo/b", denied.token)).status).toBe(403);
    expect((await find("lo/b")).lastOpenedBy).toBe(adm.name);
  });
});
