import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair, lockPrivateKey, unlockPrivateKey } from "@cfs/core";
import type { Client } from "../client.ts";
import { abortRotation } from "./group.ts";
import { setRecoveryKey, useRecoveryKey } from "./recovery.ts";
import { restoreDeleted } from "./versions.ts";

function client(
  handler: (method: string, path: string, body: unknown) => { status: number; body: unknown },
): Client {
  return {
    host: "https://example.test",
    call: (async (method, path, body) => handler(method, path, body)) as Client["call"],
    send: (() => Promise.reject()) as Client["send"],
    download: (() => Promise.reject()) as Client["download"],
  };
}

describe("CLI recovery commands", () => {
  test("abort and restore call the API and report refusals", async () => {
    const paths: string[] = [];
    const c = client((_method, path) => {
      paths.push(path);
      return { status: 200, body: {} };
    });
    await abortRotation(c, "team");
    await restoreDeleted(c, "team/dev");
    expect(paths).toEqual([
      "/keyrings/team/rotate/abort",
      "/secret/restore-delete?path=team%2Fdev",
    ]);
    const denied = client(() => ({ status: 403, body: { error: "denied" } }));
    await expect(abortRotation(denied, "team")).rejects.toThrow("denied");
    await expect(restoreDeleted(denied, "team/dev")).rejects.toThrow("denied");
  });

  test("recovery key restores the same private key and rotates the phrase", async () => {
    const dir = mkdtempSync(join(tmpdir(), "cfs-recovery-"));
    try {
      const kp = await generateKeyPair();
      let recovery: string | null = null;
      let vault = await lockPrivateKey(kp.privateKey, "old password");
      const c = client((method, path, body) => {
        if (path === "/me/recovery" && method === "GET")
          return { status: 200, body: { lockedKey: recovery } };
        if (path === "/me/recovery") recovery = (body as { lockedKey: string }).lockedKey;
        if (path === "/me/vault") vault = (body as { lockedKey: string }).lockedKey;
        return { status: 200, body: {} };
      });
      const old = join(dir, "old");
      const next = join(dir, "next");
      await setRecoveryKey(c, kp.privateKey, old);
      expect(statSync(old).mode & 0o777).toBe(0o600);
      await expect(useRecoveryKey(c, "wrong", "new password", next)).rejects.toThrow(
        "did not work",
      );
      await useRecoveryKey(c, readFileSync(old, "utf8"), "new password", next);
      expect(await unlockPrivateKey(vault, "new password")).toBe(kp.privateKey);
      await expect(
        useRecoveryKey(c, readFileSync(old, "utf8"), "another password", join(dir, "third")),
      ).rejects.toThrow("did not work");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
