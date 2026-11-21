import { decodeKit, generateKeyPair, newGroupKey, unwrapGroupKey, wrapGroupKey } from "@cfs/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { api as realApi } from "./api.ts";
import {
  appStatus,
  buildKit,
  clearHeldKit,
  createApp,
  daysLeft,
  holdKit,
  KitError,
  kitFileName,
  type NewAppForm,
  reissueKit,
  takeKit,
  validateNewApp,
} from "./apps.ts";

// Access kit and app creation (ADR 15). The private key must stay in the kit and out of every request body.

const FORM: NewAppForm = {
  name: "agent-billing",
  sessionSeconds: 3600,
  kitDays: 30,
  maxUses: "",
  network: "",
  policyId: "",
  prefixes: [],
};

const HOST = "https://vault.myorg.com";

beforeEach(() => clearHeldKit());
afterEach(() => {
  clearHeldKit();
  vi.unstubAllGlobals();
});

describe("the kit string", () => {
  it("round-trips through decodeKit with all four parts", async () => {
    const pair = await generateKeyPair();
    const kit = buildKit({
      host: HOST,
      roleId: "role1",
      secretId: "cfssid_x",
      privateKey: pair.privateKey,
    });
    expect(kit.startsWith("cfskit1_")).toBe(true);
    expect(decodeKit(kit)).toEqual({
      host: HOST,
      roleId: "role1",
      secretId: "cfssid_x",
      privateKey: pair.privateKey,
    });
  });

  it("is shown once: taken by the kit page, then gone", () => {
    holdKit({ id: "app1", name: "agent-billing", kit: "cfskit1_abc", problems: [] });
    expect(takeKit("other")).toBeNull();
    expect(takeKit("app1")).toMatchObject({ name: "agent-billing", kit: "cfskit1_abc" });
    expect(takeKit("app1")).toBeNull();
  });

  it("names the download file from the app name, with no unsafe characters", () => {
    expect(kitFileName("agent billing/prod")).toBe("agent-billing-prod.cfskit");
    expect(kitFileName("  ")).toBe("cfs.cfskit");
  });
});

describe("creating an app or bot", () => {
  it("sends the public key only, and returns a kit that holds the matching private key", async () => {
    const bodies: { url: string; body: unknown }[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init: RequestInit) => {
        bodies.push({ url, body: init.body ? JSON.parse(String(init.body)) : undefined });
        return new Response(JSON.stringify({ id: "app1", roleId: "role1", secretId: "cfssid_1" }), {
          status: 201,
          headers: { "content-type": "application/json" },
        });
      }),
    );

    const created = await createApp(
      { ...FORM, maxUses: "5", network: "34.120.0.0/16" },
      { host: HOST, now: () => 1000 },
    );

    const post = bodies.find((b) => b.url === "/api/v1/apps");
    const sent = post?.body as Record<string, unknown>;
    expect(Object.keys(sent).sort()).toEqual(
      ["cidr", "expiresAt", "maxUses", "name", "publicKey", "tokenTtl"].sort(),
    );
    expect(sent).toMatchObject({
      name: "agent-billing",
      tokenTtl: 3600,
      maxUses: 5,
      expiresAt: 1000 + 30 * 86400,
      cidr: "34.120.0.0/16",
    });

    // The kit's private key is the partner of the public key that was sent.
    const kit = decodeKit(created.kit);
    expect(kit).toMatchObject({ host: HOST, roleId: "role1", secretId: "cfssid_1" });
    const key = await newGroupKey();
    const wrapped = await wrapGroupKey(key, String(sent.publicKey), "data", 1);
    expect(
      await unwrapGroupKey(wrapped, kit.privateKey, String(sent.publicKey), "data", 1),
    ).toEqual(key);
    expect(created.problems).toEqual([]);
  });

  it("gives an empty limit and network as null, not as an empty string", async () => {
    const bodies: unknown[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, init: RequestInit) => {
        bodies.push(JSON.parse(String(init.body)));
        return new Response(JSON.stringify({ id: "a", roleId: "r", secretId: "s" }), {
          status: 201,
        });
      }),
    );
    await createApp(FORM, { host: HOST });
    expect(bodies[0]).toMatchObject({ maxUses: null, cidr: null });
  });

  it("reports a failed permission or group step, and still returns the kit", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(JSON.stringify({ id: "app1", roleId: "role1", secretId: "s" }), {
            status: 201,
          }),
      ),
    );
    const client = {
      createApp: async () => ({ id: "app1", roleId: "role1", secretId: "s" }),
      assignPolicy: async () => {
        throw new Error("nope");
      },
    } as unknown as typeof realApi;
    const created = await createApp(
      { ...FORM, policyId: "pol1", prefixes: ["data", "backend"] },
      {
        host: HOST,
        client,
        addToGroup: async (prefix) => {
          if (prefix === "backend") throw new Error("not in group");
        },
      },
    );
    expect(created.kit.startsWith("cfskit1_")).toBe(true);
    expect(created.problems).toEqual([
      { step: "permission", target: "pol1" },
      { step: "group", target: "backend" },
    ]);
  });

  it("does not create anything when the form is wrong", () => {
    expect(validateNewApp({ ...FORM, name: "" }).errors.name).toBe("empty");
    expect(validateNewApp({ ...FORM, name: "x".repeat(81) }).errors.name).toBe("tooLong");
    expect(validateNewApp({ ...FORM, name: "bad/name" }).errors.name).toBe("shape");
    expect(validateNewApp({ ...FORM, maxUses: "0" }).errors.maxUses).toBe("shape");
    expect(validateNewApp({ ...FORM, maxUses: "2.5" }).errors.maxUses).toBe("shape");
    expect(validateNewApp({ ...FORM, network: "not an ip" }).errors.network).toBe("shape");
    expect(validateNewApp({ ...FORM, network: "10.0.0.0/8, 2001:db8::/32" }).valid).toBe(true);
    expect(validateNewApp(FORM).valid).toBe(true);
  });
});

describe("re-issuing a kit", () => {
  it("reads the private key from the pasted kit and rotates only the secret ID", async () => {
    const pair = await generateKeyPair();
    const saved = buildKit({
      host: HOST,
      roleId: "role1",
      secretId: "old",
      privateKey: pair.privateKey,
    });
    const rotate = vi.fn(async () => ({ roleId: "role1", secretId: "new" }));
    const client = { rotateApp: rotate } as unknown as typeof realApi;

    const next = await reissueKit(
      ` ${saved} \n`,
      { id: "app1", name: "agent", roleId: "role1" },
      { client, host: HOST },
    );

    expect(rotate).toHaveBeenCalledWith("app1");
    expect(decodeKit(next.kit)).toEqual({
      host: HOST,
      roleId: "role1",
      secretId: "new",
      privateKey: pair.privateKey,
    });
  });

  it("refuses a kit that is unreadable or for another app, before anything is rotated", async () => {
    const pair = await generateKeyPair();
    const other = buildKit({
      host: HOST,
      roleId: "role-other",
      secretId: "s",
      privateKey: pair.privateKey,
    });
    const rotate = vi.fn(async () => ({ roleId: "x", secretId: "y" }));
    const client = { rotateApp: rotate } as unknown as typeof realApi;
    const app = { id: "app1", name: "agent", roleId: "role1" };

    await expect(reissueKit("cfskit1_garbage", app, { client })).rejects.toMatchObject({
      code: "unreadable",
    });
    await expect(reissueKit(other, app, { client })).rejects.toBeInstanceOf(KitError);
    expect(rotate).not.toHaveBeenCalled();
  });
});

describe("status helpers", () => {
  it("shows waiting until the first sign-in, and disabled apps as disabled", () => {
    expect(appStatus({ status: "active", waiting: true })).toBe("waiting");
    expect(appStatus({ status: "active", waiting: false })).toBe("active");
    expect(appStatus({ status: "disabled", waiting: false })).toBe("disabled");
  });

  it("counts whole days left and never goes below zero", () => {
    expect(daysLeft(null, 0)).toBeNull();
    expect(daysLeft(86400 * 14 + 5, 0)).toBe(14);
    expect(daysLeft(10, 100)).toBe(0);
  });
});
