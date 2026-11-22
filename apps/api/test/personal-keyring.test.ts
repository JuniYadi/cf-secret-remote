import { env } from "cloudflare:test";
import { createPersonalKeyring, generateKeyPair, unwrapGroupKey } from "@cfs/core";
import { describe, expect, it } from "vitest";
import { admin, api, makeIdentity } from "./helpers.ts";

describe("personal keyring", () => {
  it("creates once, returns the wrapped key, and prevents sharing", async () => {
    const pair = await generateKeyPair();
    const owner = await admin(pair.publicKey);
    const other = await makeIdentity({ publicKey: pair.publicKey });
    const prefix = `personal-${crypto.randomUUID()}`;
    const made = await createPersonalKeyring(pair.publicKey, prefix);
    const first = await api("POST", "/me/personal-keyring", owner.token, {
      prefix,
      wrappedKey: made.wrappedKey,
    });
    expect(first.status).toBe(201);
    const again = await api("POST", "/me/personal-keyring", owner.token, {
      prefix: `personal-${crypto.randomUUID()}`,
      wrappedKey: "different",
    });
    expect(again.body.id).toBe(first.body.id);
    const got = await api("GET", "/me/personal-keyring", owner.token);
    expect(got.body.prefix).toBe(prefix);
    expect(
      await unwrapGroupKey(got.body.wrappedKey, pair.privateKey, pair.publicKey, prefix, 1),
    ).toEqual(made.key);
    expect((await api("GET", "/me/personal-keyring", other.token)).body).toBeNull();
    expect(
      (
        await api("POST", `/keyrings/${prefix}/members`, owner.token, {
          identityId: other.id,
          wrappedKey: "bad",
        })
      ).status,
    ).not.toBe(201);
    await expect(
      env.DB.prepare(
        "INSERT INTO keyring_member (keyring_id, identity_id, version, wrapped_key) VALUES (?, ?, 1, 'bad')",
      )
        .bind(first.body.id, other.id)
        .run(),
    ).rejects.toThrow();
  });
  it("requires a user with a vault", async () => {
    const user = await makeIdentity();
    expect(
      (
        await api("POST", "/me/personal-keyring", user.token, {
          prefix: "personal-test",
          wrappedKey: "wrapped",
        })
      ).status,
    ).toBe(409);
    const app = await makeIdentity({ kind: "app", publicKey: "pub" });
    expect(
      (
        await api("POST", "/me/personal-keyring", app.token, {
          prefix: "personal-test",
          wrappedKey: "wrapped",
        })
      ).status,
    ).toBe(403);
  });
});
