import { describe, expect, it } from "vitest";
import { admin, api, makeIdentity } from "./helpers.ts";

describe("ADR 27", () => {
  it("throttles app login after 10 attempts per role", async () => {
    let last = 0;
    for (let i = 0; i < 12; i++)
      last = (
        await api("POST", "/auth/approle/login", null, { roleId: "r-throttle", secretId: "x" })
      ).status;
    expect(last).toBe(429);
  });

  it("throttles wrong approval codes per person", async () => {
    const who = await makeIdentity();
    const codes = [];
    for (let i = 0; i < 6; i++)
      codes.push((await api("POST", "/cli/approve", who.token, { userCode: "AAAA-AAAA" })).status);
    expect(codes.slice(0, 5)).toEqual([404, 404, 404, 404, 404]);
    expect(codes[5]).toBe(429);
  });

  it("caps body size and validates names", async () => {
    const adm = await admin();
    const big = "x".repeat(70 * 1024);
    expect((await api("POST", "/policies", adm.token, { name: big, rules: [] })).status).toBe(413);
    const r = await api("PUT", "/secret", adm.token, {
      path: "a/b",
      names: ["bad name"],
      wrappedDek: "x",
      ciphertext: "v1.a.b",
      keyringVersion: 1,
      version: 1,
    });
    expect(r.status).toBe(400);
  });

  it("lists and revokes own sessions", async () => {
    const me = await makeIdentity();
    const list = await api("GET", "/sessions", me.token);
    expect(list.body).toHaveLength(1);
    expect((await api("DELETE", `/sessions/${list.body[0].id}`, me.token)).status).toBe(200);
    expect((await api("GET", "/whoami", me.token)).status).toBe(401);
  });
});
