import { expect, test } from "bun:test";
import { encodeKit, generateKeyPair, newGroupKey, sealLogin, wrapGroupKey } from "@cfs/core";
import { getAccount } from "./index.ts";

test("kit decrypts an account and audits the password and TOTP", async () => {
  const pair = await generateKeyPair();
  const key = await newGroupKey();
  const wrappedKey = await wrapGroupKey(key, pair.publicKey, "team", 1);
  const sealed = await sealLogin(key, "item", 1, {
    v: 1,
    name: "site",
    url: "",
    environment: "dev",
    role: "admin",
    username: "alice",
    password: "secret",
    totp: "JBSWY3DPEHPK3PXP",
    notes: "",
  });
  const audit: unknown[] = [];
  const server = Bun.serve({
    port: 0,
    async fetch(req) {
      const path = new URL(req.url).pathname;
      if (path.endsWith("/reveal")) {
        audit.push(await req.json());
        return Response.json({ ok: true });
      }
      const response = path.endsWith("/auth/approle/login")
        ? { token: "token" }
        : path.endsWith("/logins")
          ? [{ id: "item", keyringId: "ring", version: 1, ...sealed }]
          : path.endsWith("/keyrings")
            ? [{ id: "ring", prefix: "team", version: 1 }]
            : path.endsWith("/whoami")
              ? { publicKey: pair.publicKey }
              : { wrappedKey, version: 1 };
      return Response.json(response);
    },
  });
  const prior = process.env.CFS_KIT;
  process.env.CFS_KIT = encodeKit({
    host: server.url.origin,
    roleId: "role",
    secretId: "secret",
    privateKey: pair.privateKey,
  });
  try {
    const account = await getAccount({ name: "site", env: "dev", purpose: "job" });
    expect(account.username).toBe("alice");
    expect(account.password).toBe("secret");
    expect(await account.totp()).toMatch(/^\d{6}$/);
    expect(audit).toEqual([{ purpose: "job" }, { purpose: "job", field: "totp" }]);
  } finally {
    server.stop();
    if (prior === undefined) delete process.env.CFS_KIT;
    else process.env.CFS_KIT = prior;
  }
});
