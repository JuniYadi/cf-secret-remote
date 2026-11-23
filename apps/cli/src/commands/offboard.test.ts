import { describe, expect, test } from "bun:test";
import {
  generateKeyPair,
  newGroupKey,
  openLogin,
  sealLogin,
  unwrapGroupKey,
  wrapGroupKey,
} from "@cfs/core";
import { CliError, type Client } from "../client.ts";
import { offboard, type Plan, planLines, REMINDER, reportLines, runOffboard } from "./offboard.ts";

// ADR 21 CLI checks with a fake server that holds real wrapped keys (so the group removal runs its real
// crypto). The API tests cover the server rules.

type KeyPair = Awaited<ReturnType<typeof generateKeyPair>>;
type Reply = { status: number; body: any };
interface Call {
  method: string;
  path: string;
  body?: any;
}

/** A small in-memory stand-in for the parts of the API that offboarding uses. */
function world() {
  const keys = {
    adm: undefined as unknown as KeyPair,
    tgt: undefined as unknown as KeyPair,
    keep: undefined as unknown as KeyPair,
  };
  return {
    keys,
    gk: {} as Record<string, Uint8Array>,
    groups: {
      pay: { version: 1, status: "active", members: ["adm", "tgt", "keep"] },
      ops: { version: 1, status: "active", members: ["adm", "tgt"] },
    } as Record<string, { version: number; status: string; members: string[] }>,
    people: { adm: "active", tgt: "active", keep: "active" } as Record<string, string>,
    app: { id: "app1", name: "deploy-bot", owner: "tgt", status: "active" },
    login: null as null | { id: string; version: number; wrappedDek: string; ciphertext: string },
    failApp: false,
    failFinish: false,
    calls: [] as Call[],
  };
}
type World = ReturnType<typeof world>;

const NAMES: Record<string, string> = {
  adm: "admin@x.test",
  tgt: "gone@x.test",
  keep: "keep@x.test",
};

function planOf(w: World): Plan {
  const groups = Object.keys(w.groups)
    .filter((p) => w.groups[p]?.members.includes("tgt"))
    .sort();
  const apps =
    w.app.owner === "tgt" ? [{ id: w.app.id, name: w.app.name, status: w.app.status }] : [];
  const activeApps = apps.filter((a) => a.status === "active").map((a) => a.name);
  return {
    person: {
      id: "tgt",
      name: NAMES.tgt as string,
      role: "member",
      status: w.people.tgt as string,
    },
    groups,
    apps,
    sessions: [{ id: "s1", kind: "cli", device: null, createdAt: 1, expiresAt: 9999999999 }],
    opened: {
      windowDays: 90,
      secrets: [
        {
          path: "pay/prod",
          versions: [3],
          names: ["API_KEY", "DB_PASS"],
          opens: 2,
          lastOpened: 1_700_000_000,
        },
      ],
    },
    blockers: { groups, apps: activeApps, twoAdmins: false },
    canFinish: groups.length === 0 && activeApps.length === 0,
  };
}

/** Routes a request the way the API would, recording it. */
function serve(w: World) {
  return async (method: string, path: string, body?: any): Promise<Reply> => {
    w.calls.push({ method, path, body });
    const ok = (b: unknown): Reply => ({ status: 200, body: b });
    if (method === "GET" && path === "/whoami")
      return ok({ id: "adm", name: NAMES.adm, role: "admin", publicKey: w.keys.adm.publicKey });
    if (method === "GET" && path === "/identities")
      return ok([
        {
          id: "adm",
          kind: "user",
          name: NAMES.adm,
          role: "admin",
          publicKey: w.keys.adm.publicKey,
          status: w.people.adm,
        },
        {
          id: "tgt",
          kind: "user",
          name: NAMES.tgt,
          role: "member",
          publicKey: w.keys.tgt.publicKey,
          status: w.people.tgt,
        },
        {
          id: "keep",
          kind: "user",
          name: NAMES.keep,
          role: "member",
          publicKey: w.keys.keep.publicKey,
          status: w.people.keep,
        },
        {
          id: "app1",
          kind: "app",
          name: w.app.name,
          role: "member",
          publicKey: null,
          status: "active",
        },
      ]);
    const keyM = path.match(/^\/keyrings\/([^/]+)\/key$/);
    const membersM = path.match(/^\/keyrings\/([^/]+)\/members$/);
    const rotateM = path.match(/^\/keyrings\/([^/]+)\/rotate\/(start|commit|abort)$/);
    if (method === "GET" && keyM) {
      const prefix = keyM[1] as string;
      const g = w.groups[prefix];
      if (!g || !g.members.includes("adm")) return { status: 404, body: { error: "not in group" } };
      const gk = w.gk[prefix] as Uint8Array;
      return ok({
        wrappedKey: await wrapGroupKey(gk, w.keys.adm.publicKey, prefix, g.version),
        version: g.version,
      });
    }
    if (method === "GET" && membersM) {
      const g = w.groups[membersM[1] as string];
      if (!g) return { status: 404, body: { error: "no such group" } };
      return ok(
        g.members.map((id) => ({
          identityId: id,
          name: NAMES[id],
          role: id === "keep" || id === "adm" ? "admin" : "member",
          status: w.people[id],
        })),
      );
    }
    if (method === "POST" && rotateM) {
      const g = w.groups[rotateM[1] as string];
      if (!g) return { status: 404, body: { error: "no such group" } };
      if (rotateM[2] === "start") {
        g.status = "rotating";
        g.members = g.members.filter((id) => id !== body.removeIdentityId);
        return ok({ version: g.version + 1, secrets: 0 });
      }
      if (rotateM[2] === "commit") {
        g.version += 1;
        g.status = "active";
        return ok({ version: g.version, status: "active" });
      }
      g.status = "active";
      return ok({ version: g.version, status: "active" });
    }
    if (method === "GET" && /\/rotate\/logins$/.test(path))
      return ok(path.includes("/pay/") && w.login ? [w.login] : []);
    if (method === "POST" && /\/rotate\/chunk$/.test(path))
      return ok({ staged: body.logins.length });
    if (method === "GET" && path === "/secrets") return ok([]);
    if (method === "GET" && /^\/offboard\/[^/]+\/plan$/.test(path)) return ok(planOf(w));
    if (method === "POST" && /^\/apps\/[^/]+\/disable$/.test(path)) {
      if (w.failApp) return { status: 500, body: { error: "server error" } };
      w.app.status = "disabled";
      return ok({ ok: true });
    }
    if (method === "POST" && /^\/offboard\/[^/]+\/apps\/[^/]+\/reassign$/.test(path)) {
      w.app.owner = body.ownerId;
      return ok({ id: w.app.id, ownerId: body.ownerId, changed: true });
    }
    if (method === "POST" && /^\/offboard\/[^/]+\/finish$/.test(path)) {
      if (w.failFinish)
        return {
          status: 409,
          body: {
            error: "offboarding is not finished",
            blockers: { groups: ["ops"], apps: [], twoAdmins: false },
          },
        };
      const p = planOf(w);
      if (!p.canFinish)
        return {
          status: 409,
          body: { error: "offboarding is not finished", blockers: p.blockers },
        };
      w.people.tgt = "disabled";
      return ok({
        id: "tgt",
        status: "disabled",
        changed: { disabled: true, sessionsEnded: 1, policiesRemoved: 0 },
      });
    }
    return { status: 404, body: { error: "not found" } };
  };
}

async function setup(opts: { keepDisabled?: boolean } = {}) {
  const w = world();
  w.keys.adm = await generateKeyPair();
  w.keys.tgt = await generateKeyPair();
  w.keys.keep = await generateKeyPair();
  if (opts.keepDisabled) w.people.keep = "disabled";
  for (const p of Object.keys(w.groups)) w.gk[p] = await newGroupKey();
  const send = serve(w);
  const client = {
    host: "https://cfs.test",
    privateKey: w.keys.adm.privateKey,
    call: send,
    send,
    download: async () => {
      throw new Error("not used");
    },
  } as unknown as Client;
  return { w, client };
}

function io(answer = true) {
  const logs: string[] = [];
  return {
    logs,
    io: {
      confirm: async () => answer,
      log: (l: string) => {
        logs.push(l);
      },
    },
  };
}

const posts = (w: World) => w.calls.filter((c) => c.method === "POST");

describe("ADR 21: offboard flow", () => {
  test("lists other admins holding missing group keys before changing anything", async () => {
    const { w, client } = await setup();
    w.groups.pay!.members = ["tgt", "keep"];
    await expect(runOffboard(client, "gone@x.test", { yes: true }, io().io)).rejects.toThrow(
      "pay: keep@x.test",
    );
    expect(posts(w)).toHaveLength(0);
  });

  test("removes from each group with the rotation, disables the app, finishes last, and returns the names report", async () => {
    const { w, client } = await setup();
    const { logs, io: ui } = io();
    const report = await runOffboard(client, "gone@x.test", { yes: true }, ui);

    // Group removal runs the rotation (ADR 14) for each group, before the app and finish steps.
    const order = posts(w).map((c) => c.path);
    expect(order.filter((p) => p.endsWith("/rotate/start"))).toEqual([
      "/keyrings/ops/rotate/start",
      "/keyrings/pay/rotate/start",
    ]);
    expect(order.at(-1)).toBe("/offboard/tgt/finish");
    expect(order).toContain("/apps/app1/disable");
    expect(order.indexOf("/apps/app1/disable")).toBeLessThan(order.indexOf("/offboard/tgt/finish"));
    expect(w.groups.pay?.members).not.toContain("tgt");
    expect(w.people.tgt).toBe("disabled");
    expect(w.app.status).toBe("disabled");
    expect(logs).toContain("gone@x.test disabled: 1 session(s) ended, 0 policy link(s) removed.");

    // The report lists names and versions, never values.
    expect(report).toContain("pay/prod\tAPI_KEY, DB_PASS\tversions 3");
    expect(report.join("\n")).not.toMatch(/ciphertext|wrappedDek|secret value/i);
  });

  test("offboarding re-encrypts group logins", async () => {
    const { w, client } = await setup();
    const value = {
      v: 1 as const,
      name: "private",
      url: "https://example.test",
      environment: "dev",
      role: "user",
      username: "u",
      password: "p",
      totp: "",
      notes: "",
    };
    w.login = {
      id: "login1",
      version: 1,
      ...(await sealLogin(w.gk.pay as Uint8Array, "login1", 1, value)),
    };
    await runOffboard(client, "gone@x.test", { yes: true }, io().io);
    const start = w.calls.find((c) => c.path === "/keyrings/pay/rotate/start");
    const wrapped = start?.body.members.find(
      (m: { identityId: string }) => m.identityId === "adm",
    ).wrappedKey;
    const key = await unwrapGroupKey(
      wrapped,
      w.keys.adm.privateKey,
      w.keys.adm.publicKey,
      "pay",
      2,
    );
    const row = w.calls.find((c) => c.path === "/keyrings/pay/rotate/chunk")?.body.logins[0];
    expect(await openLogin(key, row.id, row.version, row.wrappedDek, row.ciphertext)).toEqual(
      value,
    );
  });

  test("without --yes the person is asked first, and answering no changes nothing", async () => {
    const { w, client } = await setup();
    const { io: ui } = io(false);
    await expect(runOffboard(client, "gone@x.test", { yes: false }, ui)).rejects.toThrow(
      "Nothing was changed",
    );
    expect(posts(w)).toEqual([]);
    expect(w.people.tgt).toBe("active");
    expect(w.groups.pay?.members).toContain("tgt");
  });

  test("--reassign-to moves owned apps to an active person instead of disabling them", async () => {
    const { w, client } = await setup();
    const { io: ui } = io();
    await runOffboard(client, "gone@x.test", { yes: true, reassignTo: "keep@x.test" }, ui);
    const reassign = posts(w).find((c) => c.path === "/offboard/tgt/apps/app1/reassign");
    expect(reassign?.body).toEqual({ ownerId: "keep" });
    expect(posts(w).some((c) => c.path === "/apps/app1/disable")).toBe(false);
    expect(w.app.owner).toBe("keep");
    expect(w.people.tgt).toBe("disabled");
  });

  test("a disabled person cannot be given apps; nothing changes", async () => {
    const { w, client } = await setup({ keepDisabled: true });
    const { io: ui } = io();
    await expect(
      runOffboard(client, "gone@x.test", { yes: true, reassignTo: "keep@x.test" }, ui),
    ).rejects.toThrow("disabled");
    expect(posts(w)).toEqual([]);
  });

  test("a failed step stops the run, and a re-run finishes what is left without repeating done steps", async () => {
    const { w, client } = await setup();
    w.failApp = true;
    const first = io();
    await expect(runOffboard(client, "gone@x.test", { yes: true }, first.io)).rejects.toThrow(
      "Could not disable deploy-bot",
    );
    // Groups were already removed; finish never ran.
    expect(posts(w).some((c) => c.path.endsWith("/finish"))).toBe(false);
    expect(w.people.tgt).toBe("active");

    w.failApp = false;
    const second = io();
    await runOffboard(client, "gone@x.test", { yes: true }, second.io);
    const starts = w.calls.filter((c) => c.path.endsWith("/rotate/start"));
    expect(starts.length).toBe(2); // one per group, across both runs
    expect(w.people.tgt).toBe("disabled");
    expect(w.app.status).toBe("disabled");
  });

  test("a refused finish stops with what is still in the way", async () => {
    const { w, client } = await setup();
    w.failFinish = true;
    const { io: ui } = io();
    const err = await runOffboard(client, "gone@x.test", { yes: true }, ui).catch((e) => e);
    expect(err).toBeInstanceOf(CliError);
    expect(err.message).toContain("Still in groups: ops");
    expect(w.people.tgt).toBe("active");
  });

  test("unknown people are refused before any change", async () => {
    const { w, client } = await setup();
    const { io: ui } = io();
    await expect(runOffboard(client, "nobody@x.test", { yes: true }, ui)).rejects.toThrow(
      "not a person on this server",
    );
    expect(posts(w)).toEqual([]);
  });
});

describe("ADR 21: plan and report text", () => {
  test("the plan lines name groups, apps, sessions and opened secrets", () => {
    const p = planOf(world());
    const lines = planLines(p);
    expect(lines.join("\n")).toContain("Groups to remove them from (2): ops, pay");
    expect(lines).toContain("  deploy-bot (active)");
    expect(lines).toContain("Open sessions: 1");
    expect(lines).toContain("Secrets they fetched in the last 90 days: 1");
  });

  test("the report is names and versions only, and says so when empty", () => {
    const p: Plan = { ...planOf(world()), opened: { windowDays: 90, secrets: [] } };
    expect(reportLines(p).at(-1)).toBe("(none)");
    const full = reportLines(planOf(world()));
    expect(full[1]).toContain("Names only");
    expect(full).toContain("pay/prod\tAPI_KEY, DB_PASS\tversions 3");
    const secret = p.opened.secrets;
    secret.push({
      path: "pay/purged",
      names: [],
      namesUnavailable: true,
      versions: [1, 2],
      opens: 1,
      lastOpened: 1,
    });
    expect(reportLines(p)).toContain(
      "pay/purged\t(some key names no longer stored)\tversions 1, 2",
    );
  });

  test("the reminder about the identity provider is printed", () => {
    expect(REMINDER).toContain("identity provider");
  });
});

describe("cfs offboard arguments", () => {
  test("a missing or extra email shows usage without any request", async () => {
    if (!offboard.offboard) throw new Error("offboard command missing");
    const run = offboard.offboard.run;
    await expect(run([])).rejects.toThrow("Usage: cfs offboard");
    await expect(run(["a@x.test", "b@x.test"])).rejects.toThrow("Usage: cfs offboard");
  });
});
