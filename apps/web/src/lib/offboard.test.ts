import { describe, expect, it, vi } from "vitest";
import type { OffboardPlan } from "./api.ts";
import {
  OffboardBlocked,
  type OffboardDeps,
  planSteps,
  reportText,
  runOffboarding,
} from "./offboard.ts";

const plan = (over: Partial<OffboardPlan> = {}): OffboardPlan => ({
  person: { id: "p1", name: "dewi@myorg.com", role: "member", status: "active" },
  groups: ["myapp", "backend"],
  apps: [
    { id: "app1", name: "deploy-ci", status: "active" },
    { id: "app2", name: "old-bot", status: "disabled" },
  ],
  sessions: [{ id: "s1", kind: "web", device: null, createdAt: 1, expiresAt: 2 }],
  opened: {
    windowDays: 90,
    secrets: [
      { path: "myapp/dev", versions: [3], names: ["DATABASE_URL"], opens: 2, lastOpened: 100 },
    ],
  },
  blockers: { groups: ["myapp", "backend"], apps: ["deploy-ci"], twoAdmins: false },
  canFinish: false,
  ...over,
});

const done = {
  changed: { disabled: true, sessionsEnded: 1, policiesRemoved: 0 },
};

/** A fake server: the plan shrinks as the steps finish, the way the real server's answers do. */
function fakeServer(initial: OffboardPlan, failOn?: string) {
  let current = structuredClone(initial);
  const calls: string[] = [];
  const deps: OffboardDeps = {
    // Like the server: finish is allowed only with no groups, no active apps and two admins with a vault.
    plan: vi.fn(async () => ({
      ...structuredClone(current),
      canFinish:
        current.groups.length === 0 &&
        !current.apps.some((a) => a.status === "active") &&
        !current.blockers.twoAdmins,
    })),
    removeFromGroup: vi.fn(async (prefix: string) => {
      if (failOn === `group:${prefix}`) throw new Error("network");
      calls.push(`group:${prefix}`);
      current = { ...current, groups: current.groups.filter((g) => g !== prefix) };
    }),
    reassignApp: vi.fn(async (_p: string, appId: string) => {
      calls.push(`reassign:${appId}`);
      current = { ...current, apps: current.apps.filter((a) => a.id !== appId) };
    }),
    disableApp: vi.fn(async (appId: string) => {
      calls.push(`disable:${appId}`);
      current = { ...current, apps: current.apps.filter((a) => a.id !== appId) };
    }),
    finish: vi.fn(async () => {
      calls.push("finish");
      return done;
    }),
  };
  return { deps, calls };
}

describe("offboarding steps", () => {
  it("orders the group removals first, then the apps", () => {
    const steps = planSteps(plan(), { reassign: { app1: "u9" } });
    expect(steps).toEqual([
      { kind: "remove-group", prefix: "myapp" },
      { kind: "remove-group", prefix: "backend" },
      { kind: "reassign-app", appId: "app1", appName: "deploy-ci", ownerId: "u9" },
    ]);
  });

  it("disables an app when no new owner is chosen, and skips apps already disabled", () => {
    const steps = planSteps(plan(), { reassign: {} });
    expect(steps.filter((s) => s.kind === "disable-app")).toEqual([
      { kind: "disable-app", appId: "app1", appName: "deploy-ci" },
    ]);
    expect(steps.some((s) => "appId" in s && s.appId === "app2")).toBe(false);
  });
});

describe("offboarding runner", () => {
  it("runs every step, then finishes, and returns the names-only report", async () => {
    // The fake server clears the groups and apps as they are done, so the final check passes.
    const server = fakeServer(plan({ canFinish: false }));
    const out = await runOffboarding(server.deps, "p1", { reassign: {} });
    expect(server.calls).toEqual(["group:myapp", "group:backend", "disable:app1", "finish"]);
    expect(out.finish).toEqual({ sessionsEnded: 1, policiesRemoved: 0, disabled: true });
    expect(out.report.secrets[0]?.names).toEqual(["DATABASE_URL"]);
    expect(out.performed).toHaveLength(3);
  });

  it("is resumable: after a failed step, running again does only what is left", async () => {
    // The second group fails once. The plan the server holds has one group gone by then.
    const first = fakeServer(plan({ canFinish: false }), "group:backend");
    await expect(runOffboarding(first.deps, "p1", { reassign: {} })).rejects.toThrow("network");
    expect(first.calls).toEqual(["group:myapp"]);

    // Second run: the server now says backend is still there, myapp is gone.
    const second = fakeServer(plan({ groups: ["backend"], canFinish: false }));
    const out = await runOffboarding(second.deps, "p1", { reassign: {} });
    expect(second.calls).toEqual(["group:backend", "disable:app1", "finish"]);
    expect(out.performed.map((s) => s.kind)).toEqual(["remove-group", "disable-app"]);
  });

  it("refuses to finish while the person is still blocked (ADR 20, ADR 21)", async () => {
    // Nothing to do, but the person is one of two admins with a vault: finish must not run.
    const stuck = fakeServer(
      plan({ groups: [], apps: [], blockers: { groups: [], apps: [], twoAdmins: true } }),
    );
    const err = await runOffboarding(stuck.deps, "p1", { reassign: {} }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(OffboardBlocked);
    expect(stuck.deps.finish).not.toHaveBeenCalled();
  });

  it("reports each step as it starts and finishes", async () => {
    const server = fakeServer(plan({ groups: [], apps: [], canFinish: true }));
    const seen: string[] = [];
    await runOffboarding(server.deps, "p1", { reassign: {} }, (e) =>
      seen.push(`${e.status}:${e.step.kind}`),
    );
    expect(seen).toEqual(["running:finish", "done:finish"]);
  });
});

describe("names-only report", () => {
  it("lists paths and names, never values", () => {
    const text = reportText(plan().opened, "dewi@myorg.com");
    expect(text).toContain("myapp/dev\tDATABASE_URL\tversions 3");
    expect(text).toContain("Names only");
  });

  it("says so when nothing was opened", () => {
    const text = reportText({ windowDays: 90, secrets: [] }, "x");
    expect(text).toContain("(none)");
  });
});
