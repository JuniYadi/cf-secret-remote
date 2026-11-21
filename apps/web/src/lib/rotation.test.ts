import {
  generateKeyPair,
  newGroupKey,
  openSecret,
  sealSecret,
  unwrapGroupKey,
  wrapGroupKey,
} from "@cfs/core";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { api as realApi } from "./api.ts";
import { lock, unlock } from "./keystore.ts";
import { RemovalError, removeMemberFromGroup } from "./rotation.ts";

// The offboarding removal against an in-memory stand-in for the server, using the Groups part's real staged
// re-key (runRotation in groups.ts) and real @cfs/core crypto. The fake keeps only what the server keeps:
// wrapped keys per member, and ciphertext per secret version.

interface Person {
  id: string;
  name: string;
  publicKey: string;
  privateKey: string;
}

async function person(id: string, name: string): Promise<Person> {
  const kp = await generateKeyPair();
  return { id, name, publicKey: kp.publicKey, privateKey: kp.privateKey };
}

type Version = {
  version: number;
  keyringVersion: number;
  names: string[];
  wrappedDek: string;
  ciphertext: string;
  createdAt: number;
};

/** One group "myapp" at key version 1 with `admin` and `member`, and one secret at version 1. */
async function fixture(admin: Person, member: Person, values: Record<string, string>) {
  const prefix = "myapp";
  const path = "myapp/dev";
  const k1 = await newGroupKey();
  const members = new Map<string, string>([
    [admin.id, await wrapGroupKey(k1, admin.publicKey, prefix, 1)],
    [member.id, await wrapGroupKey(k1, member.publicKey, prefix, 1)],
  ]);
  const names = new Map([
    [admin.id, admin.name],
    [member.id, member.name],
  ]);
  const sealed = await sealSecret(k1, path, 1, values);
  const versions = new Map<number, Version>([
    [1, { version: 1, keyringVersion: 1, names: Object.keys(values), ...sealed, createdAt: 1 }],
  ]);
  const state = {
    version: 1,
    status: "active" as "active" | "rotating",
    members,
    staged: new Map<string, string>(),
    current: 1,
  };

  const client = {
    keyringMembers: async () =>
      [...state.members.keys()].map((id) => ({
        identityId: id,
        name: names.get(id) ?? id,
        role: "member",
        status: "active",
      })),
    identities: async () => [
      {
        id: admin.id,
        kind: "user",
        name: admin.name,
        role: "admin",
        status: "active",
        publicKey: admin.publicKey,
      },
      {
        id: member.id,
        kind: "user",
        name: member.name,
        role: "member",
        status: "active",
        publicKey: member.publicKey,
      },
    ],
    secrets: async () => [
      { path, version: state.current, updatedAt: 1, names: Object.keys(values), meta: {} },
    ],
    myGroupKey: async (p: string) => {
      expect(p).toBe(prefix);
      const wrappedKey = state.members.get(admin.id);
      if (!wrappedKey) throw new Error("not in group");
      return { wrappedKey, version: state.version };
    },
    secretVersion: async (p: string) => {
      expect(p).toBe(path);
      const v = versions.get(state.current);
      if (!v) throw new Error("no version");
      return v;
    },
    rotateStart: async (
      p: string,
      removeId: string,
      next: { identityId: string; wrappedKey: string }[],
    ) => {
      state.status = "rotating";
      state.members.delete(removeId);
      state.staged = new Map(next.map((m) => [m.identityId, m.wrappedKey]));
      return { version: state.version + 1, secrets: 1 };
    },
    rotateChunk: async (
      p: string,
      keyringVersion: number,
      items: {
        path: string;
        names: string[];
        wrappedDek: string;
        ciphertext: string;
        version: number;
      }[],
    ) => {
      expect(keyringVersion).toBe(state.version + 1);
      for (const it of items) {
        versions.set(it.version, {
          version: it.version,
          keyringVersion,
          names: it.names,
          wrappedDek: it.wrappedDek,
          ciphertext: it.ciphertext,
          createdAt: 2,
        });
      }
      return { staged: items.length };
    },
    rotateCommit: async () => {
      if (!versions.has(state.current + 1)) throw new Error("missing version");
      state.current += 1;
      state.members = new Map(state.staged);
      state.version += 1;
      state.status = "active";
      return { version: state.version, status: "active" };
    },
    rotateAbort: vi.fn(async () => {
      state.status = "active";
      state.staged = new Map();
      return {};
    }),
  };

  return { client, state, versions, prefix, path };
}

/** The shape the screens pass in: the client is the app's api object, typed as such. */
const asClient = (c: unknown) => c as typeof realApi;

afterEach(() => lock());

describe("offboarding removes a person from a group (ADR 14, ADR 21)", () => {
  it("re-keys the group and keeps the values readable for the people who stay", async () => {
    const admin = await person("a", "alice@myorg.com");
    const member = await person("b", "rina@myorg.com");
    const values = { DATABASE_URL: "postgres://db", API_KEY: "k-123" };
    const fx = await fixture(admin, member, values);
    unlock({ publicKey: admin.publicKey, privateKey: admin.privateKey });

    const out = await removeMemberFromGroup(fx.prefix, member.id, admin.id, asClient(fx.client));
    expect(out.count).toBe(1);
    expect(fx.state.version).toBe(2);
    expect(fx.state.status).toBe("active");
    expect(out.progress.done).toBe(1);

    const k2 = await unwrapGroupKey(
      fx.state.members.get(admin.id) ?? "",
      admin.privateKey,
      admin.publicKey,
      fx.prefix,
      2,
    );
    const now = fx.versions.get(2);
    expect(now).toBeDefined();
    expect(await openSecret(k2, fx.path, 2, now?.wrappedDek ?? "", now?.ciphertext ?? "")).toEqual(
      values,
    );
  });

  it("the removed person cannot open the re-sealed values with the key they had", async () => {
    const admin = await person("a", "alice@myorg.com");
    const member = await person("b", "rina@myorg.com");
    const fx = await fixture(admin, member, { TOKEN: "t" });
    const oldWrapped = fx.state.members.get(member.id) ?? "";
    unlock({ publicKey: admin.publicKey, privateKey: admin.privateKey });

    await removeMemberFromGroup(fx.prefix, member.id, admin.id, asClient(fx.client));
    const now = fx.versions.get(2);
    const oldKey = await unwrapGroupKey(
      oldWrapped,
      member.privateKey,
      member.publicKey,
      fx.prefix,
      1,
    );
    await expect(
      openSecret(oldKey, fx.path, 2, now?.wrappedDek ?? "", now?.ciphertext ?? ""),
    ).rejects.toThrow();
  });

  it("refuses a person who is not in the group, before anything changes", async () => {
    const admin = await person("a", "alice@myorg.com");
    const member = await person("b", "rina@myorg.com");
    const outsider = await person("c", "dewi@myorg.com");
    const fx = await fixture(admin, member, { TOKEN: "t" });
    unlock({ publicKey: admin.publicKey, privateKey: admin.privateKey });
    const start = vi.fn(fx.client.rotateStart);
    fx.client.rotateStart = start;

    const err = await removeMemberFromGroup(
      fx.prefix,
      outsider.id,
      admin.id,
      asClient(fx.client),
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RemovalError);
    expect((err as RemovalError).reason).toBe("notMember");
    expect(start).not.toHaveBeenCalled();
    expect(fx.state.version).toBe(1);
  });

  it("refuses to remove the caller, before anything changes", async () => {
    const admin = await person("a", "alice@myorg.com");
    const member = await person("b", "rina@myorg.com");
    const fx = await fixture(admin, member, { TOKEN: "t" });
    unlock({ publicKey: admin.publicKey, privateKey: admin.privateKey });

    const err = await removeMemberFromGroup(
      fx.prefix,
      admin.id,
      admin.id,
      asClient(fx.client),
    ).catch((e: unknown) => e);
    expect((err as RemovalError).reason).toBe("self");
    expect(fx.state.version).toBe(1);
  });

  it("aborts the rotation when a chunk fails, and the group keeps its old key", async () => {
    const admin = await person("a", "alice@myorg.com");
    const member = await person("b", "rina@myorg.com");
    const fx = await fixture(admin, member, { TOKEN: "t" });
    unlock({ publicKey: admin.publicKey, privateKey: admin.privateKey });
    fx.client.rotateChunk = vi.fn(async () => {
      throw new Error("group changed, reload and retry");
    }) as typeof fx.client.rotateChunk;

    await expect(
      removeMemberFromGroup(fx.prefix, member.id, admin.id, asClient(fx.client)),
    ).rejects.toThrow();
    expect(fx.client.rotateAbort).toHaveBeenCalledWith(fx.prefix);
    expect(fx.state.status).toBe("active");
    expect(fx.state.version).toBe(1);
    expect(fx.state.current).toBe(1);
  });
});
