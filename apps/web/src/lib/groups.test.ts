import {
  b64uEncode,
  generateKeyPair,
  newGroupKey,
  openSecret,
  sealSecret,
  unwrapGroupKey,
  wrapGroupKey,
} from "@cfs/core";
import { afterEach, describe, expect, it } from "vitest";
import type { GroupMember, Identity, api as realApi, SecretListRow, SecretVersion } from "./api.ts";
import {
  addPersonToGroup,
  adminsWithVault,
  CHUNK_SIZE,
  chunk,
  createGroup,
  groupSecrets,
  initialProgress,
  normalizePrefix,
  openMyGroupKey,
  type PersonKey,
  planRemoval,
  RotationError,
  runRotation,
  setState,
  VaultLockedError,
  validatePrefix,
} from "./groups.ts";
import { lock, unlock } from "./keystore.ts";

// The group logic with real @cfs/core crypto. The API is a fake that records every call, so the tests can
// check what would have gone to the server.

type Client = typeof realApi;

interface Call {
  name: string;
  args: unknown[];
}

interface Person {
  id: string;
  name: string;
  publicKey: string;
  privateKey: string;
}

async function person(id: string): Promise<Person> {
  const pair = await generateKeyPair();
  return { id, name: `${id}@myorg.com`, publicKey: pair.publicKey, privateKey: pair.privateKey };
}

const asPersonKey = (p: Person): PersonKey => ({
  identityId: p.id,
  name: p.name,
  publicKey: p.publicKey,
});

/** Stored state for a group with `count` secrets, all at version 2, sealed under `oldKey`. */
async function groupFixture(count: number, oldKey: Uint8Array, prefix = "data") {
  const store = new Map<string, SecretVersion>();
  const list: SecretListRow[] = [];
  for (let i = 0; i < count; i++) {
    const path = `${prefix}/s${i}`;
    const sealed = await sealSecret(oldKey, path, 2, { K: `value-${i}` });
    store.set(path, {
      version: 2,
      keyringVersion: 3,
      names: ["K"],
      wrappedDek: sealed.wrappedDek,
      ciphertext: sealed.ciphertext,
      createdAt: 1,
    });
    list.push({ path, version: 2, updatedAt: 1, names: ["K"], meta: {} });
  }
  return { store, list };
}

interface FakeOptions {
  failChunkNumber?: number;
  failCommit?: boolean;
  failStart?: boolean;
  store?: Map<string, SecretVersion>;
}

function fakeClient(opts: FakeOptions = {}) {
  const calls: Call[] = [];
  let chunkNumber = 0;
  const record = (name: string, args: unknown[]) => calls.push({ name, args });
  const client = {
    rotateStart: async (...args: unknown[]) => {
      record("rotateStart", args);
      if (opts.failStart) throw new Error("server said no");
      return { version: 4, secrets: 0 };
    },
    secretVersion: async (path: string) => {
      record("secretVersion", [path]);
      const row = opts.store?.get(path);
      if (!row) throw new Error("not found");
      return row;
    },
    rotateChunk: async (...args: unknown[]) => {
      record("rotateChunk", args);
      chunkNumber++;
      if (opts.failChunkNumber === chunkNumber) throw new Error("chunk refused");
      return { staged: (args[2] as unknown[]).length };
    },
    rotateCommit: async (...args: unknown[]) => {
      record("rotateCommit", args);
      if (opts.failCommit) throw new Error("commit refused");
      return { version: 4, status: "active" };
    },
    rotateAbort: async (...args: unknown[]) => {
      record("rotateAbort", args);
      return { version: 3, status: "active" };
    },
    myGroupKey: async (...args: unknown[]) => {
      record("myGroupKey", args);
      return { wrappedKey: "", version: 0 };
    },
    createKeyring: async (...args: unknown[]) => {
      record("createKeyring", args);
      return { id: "g1", prefix: "data" };
    },
    addGroupMember: async (...args: unknown[]) => {
      record("addGroupMember", args);
      return { ok: true as const };
    },
  };
  return { client: client as unknown as Client, calls };
}

afterEach(() => lock());

describe("chunking and the group view", () => {
  it("splits into pieces of at most the server's chunk size, keeping order", () => {
    expect(CHUNK_SIZE).toBe(50);
    const sizes = chunk(Array.from({ length: 120 }, (_, i) => i)).map((c) => c.length);
    expect(sizes).toEqual([50, 50, 20]);
    expect(chunk([1, 2, 3], 2)).toEqual([[1, 2], [3]]);
    expect(chunk([])).toEqual([]);
    expect(() => chunk([1], 0)).toThrow(RangeError);
  });

  it("keeps only the secrets under the group's own prefix", () => {
    const list: SecretListRow[] = [
      { path: "data/a", version: 1, updatedAt: 1, names: [], meta: {} },
      { path: "data2/a", version: 1, updatedAt: 1, names: [], meta: {} },
      { path: "other/x", version: 1, updatedAt: 1, names: [], meta: {} },
    ];
    expect(groupSecrets(list, "data").map((s) => s.path)).toEqual(["data/a"]);
  });

  it("counts admins who hold a vault, and only active user admins", () => {
    const id = (over: Partial<Identity>): Identity => ({
      id: "x",
      kind: "user",
      name: "x",
      role: "admin",
      publicKey: "PUB",
      status: "active",
      last_unlocked_at: null,
      ...over,
    });
    expect(
      adminsWithVault([
        id({ id: "a" }),
        id({ id: "b", publicKey: null }),
        id({ id: "c", role: "member" }),
        id({ id: "d", status: "disabled" }),
        id({ id: "e", kind: "app" }),
      ]),
    ).toBe(1);
  });

  it("normalises a trailing slash and refuses bad or duplicate group names", () => {
    expect(normalizePrefix(" data/ ")).toBe("data");
    expect(validatePrefix("data/")).toBeNull();
    expect(validatePrefix("")).toBe("empty");
    expect(validatePrefix("a/b")).toBe("shape");
    expect(validatePrefix("-x")).toBe("shape");
    expect(validatePrefix("data", ["data"])).toBe("exists");
  });
});

describe("removing a member", () => {
  const members: GroupMember[] = [
    { identityId: "me", name: "me", role: "admin", status: "active" },
    { identityId: "a", name: "a", role: "member", status: "active" },
    { identityId: "gone", name: "gone", role: "member", status: "active" },
  ];
  const identities = (keyFor: string[]): Identity[] =>
    ["me", "a", "gone"].map((id) => ({
      id,
      kind: "user",
      name: id,
      role: "member",
      publicKey: keyFor.includes(id) ? "PUB" : null,
      status: "active",
      last_unlocked_at: null,
    }));

  it("keeps everyone else, each with a public key", () => {
    const plan = planRemoval(members, identities(["me", "a", "gone"]), "gone", "me");
    expect(plan).toEqual({
      ok: true,
      remaining: [
        { identityId: "me", name: "me", publicKey: "PUB" },
        { identityId: "a", name: "a", publicKey: "PUB" },
      ],
    });
  });

  it("refuses to remove yourself, or someone who is not in the group", () => {
    const all = identities(["me", "a", "gone"]);
    expect(planRemoval(members, all, "me", "me")).toEqual({ ok: false, reason: "self" });
    expect(planRemoval(members, all, "stranger", "me")).toEqual({ ok: false, reason: "notMember" });
  });

  it("refuses when someone who stays has no key yet, because the new key cannot reach them", () => {
    const plan = planRemoval(members, identities(["me", "gone"]), "gone", "me");
    expect(plan).toEqual({ ok: false, reason: "noKey", name: "a" });
  });
});

describe("staged re-key (ADR 14)", () => {
  it("re-encrypts every secret under the new key, wraps it only to the people who stay, and commits", async () => {
    const admin = await person("me");
    const a = await person("a");
    const removed = await person("gone");
    const oldKey = await newGroupKey();
    const { store, list } = await groupFixture(3, oldKey);
    const { client, calls } = fakeClient({ store });

    const progressSeen: number[] = [];
    const done = await runRotation(
      {
        prefix: "data",
        currentVersion: 3,
        removeIdentityId: removed.id,
        remaining: [asPersonKey(admin), asPersonKey(a)],
        oldKey,
        secrets: list,
        onProgress: (p) => progressSeen.push(p.done),
      },
      client,
    );

    // Start: the removed person is named, and the new key is wrapped to each remaining person only.
    const start = calls.find((c) => c.name === "rotateStart");
    expect(start?.args[1]).toBe(removed.id);
    const startMembers = (start?.args[2] ?? []) as { identityId: string; wrappedKey: string }[];
    expect(startMembers.map((m) => m.identityId).sort()).toEqual(["a", "me"]);
    const forA = startMembers.find((m) => m.identityId === "a")?.wrappedKey ?? "";
    const newKeyForA = await unwrapGroupKey(forA, a.privateKey, a.publicKey, "data", 4);
    const forAdmin = startMembers.find((m) => m.identityId === "me")?.wrappedKey ?? "";
    expect(await unwrapGroupKey(forAdmin, admin.privateKey, admin.publicKey, "data", 4)).toEqual(
      newKeyForA,
    );

    // Chunks: the new keyring version, and each secret's version one above the current.
    const chunks = calls.filter((c) => c.name === "rotateChunk");
    expect(chunks).toHaveLength(1);
    expect(chunks[0]?.args[1]).toBe(4);
    const staged = chunks[0]?.args[2] as {
      path: string;
      version: number;
      wrappedDek: string;
      ciphertext: string;
      names: string[];
    }[];
    expect(staged.map((s) => s.version)).toEqual([3, 3, 3]);
    for (const s of staged) {
      expect(s.names).toEqual(["K"]);
      const values = await openSecret(newKeyForA, s.path, s.version, s.wrappedDek, s.ciphertext);
      expect(values.K).toBe(`value-${s.path.endsWith("s0") ? 0 : s.path.endsWith("s1") ? 1 : 2}`);
    }

    expect(calls.map((c) => c.name)).toEqual([
      "rotateStart",
      "secretVersion",
      "secretVersion",
      "secretVersion",
      "rotateChunk",
      "rotateCommit",
    ]);
    expect(done.done).toBe(3);
    expect(done.current).toBeNull();
    expect(progressSeen[0]).toBe(0);
    expect(progressSeen.at(-1)).toBe(3);
  });

  it("sends at most 50 secrets per chunk", async () => {
    const admin = await person("me");
    const oldKey = await newGroupKey();
    const { store, list } = await groupFixture(120, oldKey);
    const { client, calls } = fakeClient({ store });
    await runRotation(
      {
        prefix: "data",
        currentVersion: 3,
        removeIdentityId: "gone",
        remaining: [asPersonKey(admin)],
        oldKey,
        secrets: list,
      },
      client,
    );
    const sizes = calls
      .filter((c) => c.name === "rotateChunk")
      .map((c) => (c.args[2] as unknown[]).length);
    expect(sizes).toEqual([50, 50, 20]);
  });

  it("aborts and reports the secrets stage when a chunk is refused", async () => {
    const admin = await person("me");
    const oldKey = await newGroupKey();
    const { store, list } = await groupFixture(60, oldKey);
    const { client, calls } = fakeClient({ store, failChunkNumber: 2 });
    const err = await runRotation(
      {
        prefix: "data",
        currentVersion: 3,
        removeIdentityId: "gone",
        remaining: [asPersonKey(admin)],
        oldKey,
        secrets: list,
      },
      client,
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RotationError);
    expect((err as RotationError).stage).toBe("secrets");
    const names = calls.map((c) => c.name);
    expect(names).toContain("rotateAbort");
    expect(names).not.toContain("rotateCommit");
  });

  it("aborts and reports the commit stage when the commit is refused", async () => {
    const admin = await person("me");
    const oldKey = await newGroupKey();
    const { store, list } = await groupFixture(1, oldKey);
    const { client, calls } = fakeClient({ store, failCommit: true });
    const err = (await runRotation(
      {
        prefix: "data",
        currentVersion: 3,
        removeIdentityId: "gone",
        remaining: [asPersonKey(admin)],
        oldKey,
        secrets: list,
      },
      client,
    ).catch((e: unknown) => e)) as RotationError;
    expect(err.stage).toBe("commit");
    expect(calls.map((c) => c.name).at(-1)).toBe("rotateAbort");
  });

  it("does not abort when the start itself is refused, since nothing was staged", async () => {
    const admin = await person("me");
    const oldKey = await newGroupKey();
    const { client, calls } = fakeClient({ failStart: true });
    const err = (await runRotation(
      {
        prefix: "data",
        currentVersion: 3,
        removeIdentityId: "gone",
        remaining: [asPersonKey(admin)],
        oldKey,
        secrets: [],
      },
      client,
    ).catch((e: unknown) => e)) as RotationError;
    expect(err.stage).toBe("start");
    expect(calls.map((c) => c.name)).toEqual(["rotateStart"]);
  });

  it("never sends a private key or a group key in any request", async () => {
    const admin = await person("me");
    const a = await person("a");
    const removed = await person("gone");
    const oldKey = await newGroupKey();
    const { store, list } = await groupFixture(2, oldKey);
    const { client, calls } = fakeClient({ store });
    await runRotation(
      {
        prefix: "data",
        currentVersion: 3,
        removeIdentityId: removed.id,
        remaining: [asPersonKey(admin), asPersonKey(a)],
        oldKey,
        secrets: list,
      },
      client,
    );
    const sent = JSON.stringify(calls);
    for (const secret of [admin.privateKey, a.privateKey, removed.privateKey]) {
      expect(sent).not.toContain(secret);
    }
    expect(sent).not.toContain(b64uEncode(oldKey));
  });
});

describe("creating a group and adding people", () => {
  it("creates a group at version 1, wrapping the key to each member, the creator included", async () => {
    const admin = await person("me");
    const a = await person("a");
    unlock({ publicKey: admin.publicKey, privateKey: admin.privateKey });
    const { client, calls } = fakeClient();
    await createGroup("data", [asPersonKey(admin), asPersonKey(a)], client);

    const create = calls.find((c) => c.name === "createKeyring");
    expect(create?.args[0]).toBe("data");
    const members = create?.args[1] as { identityId: string; wrappedKey: string }[];
    expect(members.map((m) => m.identityId).sort()).toEqual(["a", "me"]);
    const keyForA = await unwrapGroupKey(
      members.find((m) => m.identityId === "a")?.wrappedKey ?? "",
      a.privateKey,
      a.publicKey,
      "data",
      1,
    );
    const keyForAdmin = await unwrapGroupKey(
      members.find((m) => m.identityId === "me")?.wrappedKey ?? "",
      admin.privateKey,
      admin.publicKey,
      "data",
      1,
    );
    expect(keyForA).toEqual(keyForAdmin);
    expect(JSON.stringify(calls)).not.toContain(admin.privateKey);
  });

  it("adds a person by unwrapping the current key and wrapping it to them at the current version", async () => {
    const admin = await person("me");
    const newcomer = await person("new");
    unlock({ publicKey: admin.publicKey, privateKey: admin.privateKey });
    const key = await newGroupKey();
    const wrappedForAdmin = await wrapGroupKey(key, admin.publicKey, "data", 2);
    const { client, calls } = fakeClient();
    (client as unknown as { myGroupKey: () => Promise<unknown> }).myGroupKey = async () => ({
      wrappedKey: wrappedForAdmin,
      version: 2,
    });

    await addPersonToGroup("data", asPersonKey(newcomer), client);

    const add = calls.find((c) => c.name === "addGroupMember");
    expect(add?.args[0]).toBe("data");
    expect(add?.args[1]).toBe("new");
    const got = await unwrapGroupKey(
      add?.args[2] as string,
      newcomer.privateKey,
      newcomer.publicKey,
      "data",
      2,
    );
    expect(got).toEqual(key);
    expect(JSON.stringify(calls)).not.toContain(admin.privateKey);
  });

  it("will not open a group key while the vault is locked", async () => {
    lock();
    const { client } = fakeClient();
    await expect(openMyGroupKey("data", client)).rejects.toBeInstanceOf(VaultLockedError);
  });
});

describe("progress view model", () => {
  it("counts done secrets and points at the one in progress", () => {
    let p = initialProgress(["data/a", "data/b"]);
    p = setState(p, "data/a", "now");
    expect(p).toMatchObject({ total: 2, done: 0, current: "data/a" });
    p = setState(p, "data/a", "done");
    expect(p).toMatchObject({ done: 1, current: null });
    expect(p.items).toEqual([
      { path: "data/a", state: "done" },
      { path: "data/b", state: "waiting" },
    ]);
  });

  it("does not change the input it was given", () => {
    const before = initialProgress(["data/a"]);
    setState(before, "data/a", "done");
    expect(before.items[0]?.state).toBe("waiting");
  });
});
