import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { admin, api } from "./helpers.ts";

describe("reserved route names", () => {
  it("rejects reserved groups and new secrets, but permits updates to existing secrets", async () => {
    const owner = await admin();
    for (const prefix of ["new", "offboard", "regrant"]) {
      const result = await api("POST", "/keyrings", owner.token, {
        prefix,
        members: [{ identityId: owner.id, wrappedKey: "wrapped" }],
      });
      expect(result.status).toBe(400);
      expect(result.body.error).toContain("reserved");
    }
    const prefix = `team-${crypto.randomUUID()}`;
    expect(
      (
        await api("POST", "/keyrings", owner.token, {
          prefix,
          members: [{ identityId: owner.id, wrappedKey: "wrapped" }],
        })
      ).status,
    ).toBe(201);
    const body = {
      path: `${prefix}/edit`,
      names: [],
      wrappedDek: "wrapped",
      ciphertext: "v1.data",
      keyringVersion: 1,
      version: 1,
    };
    const rejected = await api("PUT", "/secret", owner.token, body);
    expect(rejected.status).toBe(400);
    expect(rejected.body.error).toContain("reserved");
    const original = { ...body, path: `${prefix}/ordinary` };
    expect((await api("PUT", "/secret", owner.token, original)).status).toBe(201);
    await env.DB.prepare("UPDATE secret SET path = ? WHERE path = ?")
      .bind(body.path, original.path)
      .run();
    expect((await api("PUT", "/secret", owner.token, { ...body, version: 2 })).status).toBe(200);
  });
});
