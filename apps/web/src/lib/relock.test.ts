import { generateKeyPair, newGroupKey, sealSecret } from "@cfs/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { api as realApi, SecretVersion } from "./api.ts";
import { clearRelock, currentJob, resetRelockForTests, startRelock } from "./relock.ts";

// The re-locking job the progress screen reads. Its promise settles the job; late updates are ignored.

/** Waits until the job for `prefix` leaves the running state (the crypto takes a few ticks). */
async function settle(prefix: string) {
  for (let i = 0; i < 200; i++) {
    if (currentJob(prefix)?.status !== "running") return;
    await new Promise((r) => setTimeout(r, 2));
  }
}

beforeEach(() => resetRelockForTests());
afterEach(() => resetRelockForTests());

async function fixtures(count: number) {
  const oldKey = await newGroupKey();
  const admin = await generateKeyPair();
  const store = new Map<string, SecretVersion>();
  const secrets = [];
  for (let i = 0; i < count; i++) {
    const path = `data/s${i}`;
    const sealed = await sealSecret(oldKey, path, 2, { TOKEN: `t${i}` });
    store.set(path, {
      version: 2,
      keyringVersion: 3,
      names: ["TOKEN"],
      wrappedDek: sealed.wrappedDek,
      ciphertext: sealed.ciphertext,
      createdAt: 1,
    });
    secrets.push({ path, version: 2, updatedAt: 1, names: ["TOKEN"], meta: {} });
  }
  return { oldKey, admin, store, secrets };
}

function client(store: Map<string, SecretVersion>, failCommit = false) {
  return {
    rotateStart: async () => ({ version: 4, secrets: store.size }),
    secretVersion: async (path: string) => store.get(path) as SecretVersion,
    rotateChunk: async (_p: string, _v: number, batch: unknown[]) => ({ staged: batch.length }),
    rotateCommit: async () => {
      if (failCommit) throw new Error("refused");
      return { version: 4, status: "active" };
    },
    rotateAbort: async () => ({ version: 3, status: "active" }),
  } as unknown as typeof realApi;
}

describe("re-locking job", () => {
  it("runs to done, with every secret marked done and the names of what was openable", async () => {
    const f = await fixtures(2);
    const job = startRelock(
      {
        prefix: "data",
        currentVersion: 3,
        removeIdentityId: "gone",
        remaining: [{ identityId: "me", name: "me", publicKey: f.admin.publicKey }],
        oldKey: f.oldKey,
        secrets: f.secrets,
      },
      "Dewi",
      client(f.store),
    );
    expect(job.status).toBe("running");
    expect(job.openable).toEqual([
      { path: "data/s0", names: ["TOKEN"] },
      { path: "data/s1", names: ["TOKEN"] },
    ]);
    await settle("data");
    const done = currentJob("data");
    expect(done?.status).toBe("done");
    expect(done?.progress.done).toBe(2);
    expect(done?.removedName).toBe("Dewi");
  });

  it("settles as failed with the stage when the commit is refused", async () => {
    const f = await fixtures(1);
    startRelock(
      {
        prefix: "data",
        currentVersion: 3,
        removeIdentityId: "gone",
        remaining: [{ identityId: "me", name: "me", publicKey: f.admin.publicKey }],
        oldKey: f.oldKey,
        secrets: f.secrets,
      },
      "Dewi",
      client(f.store, true),
    );
    await settle("data");
    const failed = currentJob("data");
    expect(failed?.status).toBe("failed");
    expect(failed?.error?.stage).toBe("commit");
  });

  it("only reports the job for the group that started it, and clears on request", async () => {
    const f = await fixtures(1);
    startRelock(
      {
        prefix: "data",
        currentVersion: 3,
        removeIdentityId: "gone",
        remaining: [{ identityId: "me", name: "me", publicKey: f.admin.publicKey }],
        oldKey: f.oldKey,
        secrets: f.secrets,
      },
      "Dewi",
      client(f.store),
    );
    expect(currentJob("backend")).toBeNull();
    clearRelock();
    expect(currentJob("data")).toBeNull();
  });
});
