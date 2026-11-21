import { env } from "cloudflare:test";
import {
  generateKeyPair,
  newGroupKey,
  openSecret,
  sealSecret,
  unwrapGroupKey,
  wrapGroupKey,
} from "@cfs/core";
import { describe, expect, it } from "vitest";
import { admin, api, makeIdentity } from "./helpers.ts";

describe("secrets end to end", () => {
  it("two gates: policy lets you fetch, the group key lets you open; no plaintext on the server", async () => {
    const kp = await generateKeyPair();
    const adm = await admin(kp.publicKey);
    const bot = await makeIdentity({ kind: "app" });
    const gk = await newGroupKey();

    expect(
      (
        await api("POST", "/keyrings", adm.token, {
          prefix: "pay",
          members: [
            { identityId: adm.id, wrappedKey: await wrapGroupKey(gk, kp.publicKey, "pay", 1) },
          ],
        })
      ).status,
    ).toBe(201);

    const marker = "sk_live_MARKER_9f3a";
    const sealed = await sealSecret(gk, "pay/prod", 1, { KEY: marker });
    expect(
      (
        await api("PUT", "/secret", adm.token, {
          path: "pay/prod",
          names: ["KEY"],
          keyringVersion: 1,
          version: 1,
          ...sealed,
        })
      ).status,
    ).toBe(201);

    // stale version is refused
    expect(
      (
        await api("PUT", "/secret", adm.token, {
          path: "pay/prod",
          names: ["KEY"],
          keyringVersion: 1,
          version: 1,
          ...sealed,
        })
      ).status,
    ).toBe(409);

    // default deny, then allowed by policy
    expect((await api("GET", "/secret?path=pay/prod", bot.token)).status).toBe(403);
    const pol = await api("POST", "/policies", adm.token, {
      name: "pay-read",
      rules: [{ path: "pay/*", caps: ["read"] }],
    });
    await api("POST", `/policies/${pol.body.id}/assign`, adm.token, { identityId: bot.id });
    const got = await api("GET", "/secret?path=pay/prod", bot.token);
    expect(got.status).toBe(200);
    expect(
      (
        await api("PUT", "/secret", bot.token, {
          path: "pay/prod",
          names: [],
          wrappedDek: "x",
          ciphertext: "v1.a.b",
          keyringVersion: 1,
          version: 2,
        })
      ).status,
    ).toBe(403);

    // the bot has no group key
    expect((await api("GET", "/keyrings/pay/key", bot.token)).status).toBe(404);

    // the admin can open it
    const k = await api("GET", "/keyrings/pay/key", adm.token);
    const opened = await unwrapGroupKey(
      k.body.wrappedKey,
      kp.privateKey,
      kp.publicKey,
      "pay",
      k.body.version,
    );
    expect(
      await openSecret(
        opened,
        "pay/prod",
        got.body.version,
        got.body.wrappedDek,
        got.body.ciphertext,
      ),
    ).toEqual({ KEY: marker });

    // plaintext appears nowhere: not in the response, not in any table
    expect(JSON.stringify(got.body)).not.toContain(marker);
    for (const t of ["secret_version", "audit", "keyring_member", "identity", "session"]) {
      const rows = await env.DB.prepare(`SELECT * FROM ${t}`).all();
      expect(JSON.stringify(rows.results)).not.toContain(marker);
    }
  });

  it("denials are audited and the chain verifies", async () => {
    const adm = await admin();
    const nobody = await makeIdentity();
    await api("GET", "/secret?path=x/y", nobody.token);
    const v = await api("GET", "/audit/verify", adm.token);
    expect(v.body.ok).toBe(true);
    expect(v.body.rows).toBeGreaterThan(0);
  });
});
