// @vitest-environment happy-dom
import type { ComponentChildren } from "preact";
import { render } from "preact";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearHeldKit, holdKit } from "../lib/apps.ts";
import { lock } from "../lib/keystore.ts";
import { clearRelock, resetRelockForTests } from "../lib/relock.ts";
import { loadSession, resetSessionForTests } from "../lib/session.ts";
import { AppKitPage } from "./AppKit.tsx";
import { AppDetailPage, AppNewPage, AppsPage } from "./Apps.tsx";
import {
  GroupAddPage,
  GroupDetailPage,
  GroupNewPage,
  GroupRelockPage,
  GroupsPage,
} from "./Groups.tsx";
import { InvitePage } from "./Invite.tsx";
import { PermissionsPage, PermNewPage, RoleNewPage } from "./Permissions.tsx";

// Each screen rendered with the API mocked at fetch. The mock answers by "METHOD /path" and records every
// request, so the tests can check what the screens would have sent.

type Json = unknown;
type Handler = Json | ((body: unknown) => Json | Response);

const ADMIN = {
  id: "me",
  kind: "user",
  name: "alice@myorg.com",
  role: "admin",
  vaultReady: true,
  publicKey: "PUB-ME",
  lockedKey: "LOCK-ME",
};

const MEMBER = { ...ADMIN, id: "bob", name: "bob@myorg.com", role: "member" };

interface Sent {
  method: string;
  path: string;
  url: string;
  body: unknown;
}

// One route table per test. serve() adds to it, so a later call (mount sets /whoami) keeps earlier routes.
let routeTable: Record<string, Handler> = {};
let sentLog: Sent[] = [];

function serve(more: Record<string, Handler>): { sent: Sent[] } {
  Object.assign(routeTable, more);
  const handler = vi.fn(async (url: string, init: RequestInit) => {
    const [pathOnly = ""] = url.replace("/api/v1", "").split("?");
    const method = init.method ?? "GET";
    const body = init.body ? JSON.parse(String(init.body)) : undefined;
    sentLog.push({ method, path: pathOnly, url, body });
    const h = routeTable[`${method} ${pathOnly}`];
    if (h === undefined)
      return new Response(JSON.stringify({ error: "not found" }), { status: 404 });
    const value = typeof h === "function" ? h(body) : h;
    if (value instanceof Response) return value;
    return new Response(JSON.stringify(value), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  });
  vi.stubGlobal("fetch", handler);
  return { sent: sentLog };
}

let host: HTMLElement;

const flush = async () => {
  for (let i = 0; i < 4; i++) await new Promise((r) => setTimeout(r, 5));
};

/** Logs in as `me` (default admin), then renders the screen at `path`. */
async function mount(vnode: ComponentChildren, path: string, me: object = ADMIN) {
  history.replaceState({}, "", path);
  serve({ "GET /whoami": me });
  resetSessionForTests();
  await loadSession();
  render(vnode, host);
  await flush();
}

const text = () => host.textContent ?? "";

function button(label: string): HTMLButtonElement | undefined {
  return Array.from(host.querySelectorAll("button")).find((b) =>
    (b.textContent ?? "").includes(label),
  );
}

async function type(selector: string, value: string) {
  const el = host.querySelector(selector) as HTMLInputElement | HTMLTextAreaElement | null;
  if (!el) throw new Error(`no element ${selector}`);
  el.value = value;
  el.dispatchEvent(new Event("input", { bubbles: true }));
  await flush();
}

async function click(el: HTMLElement | undefined) {
  if (!el) throw new Error("no element to click");
  el.click();
  await flush();
}

const soon = Math.floor(Date.now() / 1000) + 20 * 86400;

beforeEach(() => {
  routeTable = {};
  sentLog = [];
  host = document.createElement("div");
  document.body.appendChild(host);
  lock();
  clearHeldKit();
  resetRelockForTests();
});

afterEach(() => {
  render(null, host);
  host.remove();
  lock();
  clearHeldKit();
  clearRelock();
  vi.unstubAllGlobals();
  history.replaceState({}, "", "/");
});

describe("Groups", () => {
  it("lists groups with their key version, and warns when only one admin holds a key", async () => {
    serve({
      "GET /keyrings": [{ prefix: "data", version: 3 }],
      "GET /identities": [
        {
          id: "me",
          kind: "user",
          name: "alice@myorg.com",
          role: "admin",
          publicKey: "P",
          status: "active",
        },
      ],
    });
    await mount(<GroupsPage />, "/groups");
    expect(text()).toContain("Groups");
    expect(text()).toContain("data");
    expect(text()).toContain("k3");
    expect(text()).toContain("Only one admin has a key.");
  });

  it("asks before removing anyone: nothing is sent until the removal is confirmed", async () => {
    const { sent } = serve({
      "GET /keyrings/data/members": [
        { identityId: "me", name: "alice@myorg.com", role: "admin", status: "active" },
        { identityId: "gone", name: "gone@myorg.com", role: "member", status: "active" },
      ],
      "GET /identities": [
        {
          id: "me",
          kind: "user",
          name: "alice@myorg.com",
          role: "admin",
          publicKey: "P",
          status: "active",
        },
        {
          id: "gone",
          kind: "user",
          name: "gone@myorg.com",
          role: "member",
          publicKey: "Q",
          status: "active",
        },
      ],
      "GET /secrets": [{ path: "data/a", version: 1, updatedAt: 1, names: ["K"], meta: {} }],
      "GET /whoami": ADMIN,
    });
    await mount(<GroupDetailPage prefix="data" />, "/groups/data");
    await click(button("Remove gone@myorg.com"));
    expect(text()).toContain("Remove gone@myorg.com from this group?");
    expect(text()).toContain("1 secrets are re-locked.");
    expect(sent.some((s) => s.path.includes("rotate"))).toBe(false);
  });

  it("does not offer removal to members", async () => {
    serve({
      "GET /keyrings/data/members": [
        { identityId: "bob", name: "bob@myorg.com", role: "member", status: "active" },
        { identityId: "gone", name: "gone@myorg.com", role: "member", status: "active" },
      ],
    });
    await mount(<GroupDetailPage prefix="data" />, "/groups/data", MEMBER);
    expect(button("Remove gone@myorg.com")).toBeUndefined();
  });

  it("checks the group name as it is typed, and keeps the button off until it is valid", async () => {
    serve({
      "GET /keyrings": [{ prefix: "data", version: 1 }],
      "GET /identities": [],
    });
    await mount(<GroupNewPage />, "/groups/new");
    const submit = () => button("Create group") as HTMLButtonElement;
    expect(submit().disabled).toBe(true);
    await type("#group-prefix", "a/b");
    expect(text()).toContain("Use letters, numbers, dots, dashes and underscores.");
    await type("#group-prefix", "data");
    expect(text()).toContain("A group with this name already exists.");
    expect(submit().disabled).toBe(true);
    await type("#group-prefix", "offboard");
    expect(text()).toContain("This name is reserved for a web page.");
    expect(submit().disabled).toBe(true);
    await type("#group-prefix", "backend");
    expect(text()).not.toContain("already exists");
    expect(submit().disabled).toBe(false);
  });

  it("shows who can be added, and marks those who have not set up a vault yet", async () => {
    serve({
      "GET /keyrings/data/members": [],
      "GET /identities": [
        {
          id: "a",
          kind: "user",
          name: "rina@myorg.com",
          role: "member",
          publicKey: "P",
          status: "active",
        },
        {
          id: "b",
          kind: "user",
          name: "rizal@myorg.com",
          role: "member",
          publicKey: null,
          status: "active",
        },
      ],
    });
    await mount(<GroupAddPage prefix="data" />, "/groups/data/add");
    expect(text()).toContain("rina@myorg.com");
    expect(text()).toContain("Ready");
    expect(text()).toContain("Hasn't set up yet");
    const boxes = Array.from(host.querySelectorAll("input[type=checkbox]")) as HTMLInputElement[];
    expect(boxes.map((b) => b.disabled)).toEqual([false, true]);
  });

  it("explains a re-locking screen that is not running in this tab", async () => {
    await mount(<GroupRelockPage prefix="data" />, "/groups/data/relock");
    expect(text()).toContain("This re-locking isn't running in this tab any more.");
  });
});

describe("Permissions", () => {
  it("shows who holds each permission set and what it allows, in words", async () => {
    serve({
      "GET /policies": [
        {
          id: "p1",
          name: "Myapp access",
          rules: [{ path: "myapp/*", caps: ["read", "list"] }],
          assignees: [{ identityId: "u1", name: "rina@myorg.com", kind: "user", expiresAt: null }],
        },
      ],
    });
    await mount(<PermissionsPage />, "/permissions");
    expect(text()).toContain("Myapp access");
    expect(text()).toContain("rina@myorg.com");
    expect(text()).toContain("View values, See names: myapp/*");
  });

  it("asks for a name and a rule before saving a permission set", async () => {
    const { sent } = serve({ "GET /whoami": ADMIN });
    await mount(<PermNewPage />, "/permissions/new");
    await click(button("Save permission set"));
    expect(text()).toContain("Give the set a name.");
    expect(sent.some((s) => s.method === "POST")).toBe(false);
  });

  it("toggles capabilities as pressed buttons, labelled in words", async () => {
    serve({});
    await mount(<PermNewPage />, "/permissions/new");
    const view = button("View values") as HTMLButtonElement;
    expect(view.getAttribute("aria-pressed")).toBe("false");
    await click(view);
    expect((button("View values") as HTMLButtonElement).getAttribute("aria-pressed")).toBe("true");
  });

  it("saves a role as one assignment per person and permission set", async () => {
    const { sent } = serve({
      "GET /identities": [
        {
          id: "u1",
          kind: "user",
          name: "rina@myorg.com",
          role: "member",
          publicKey: "P",
          status: "active",
        },
      ],
      "GET /policies": [{ id: "p1", name: "Myapp access", rules: [], assignees: [] }],
      "POST /policies/p1/assign": { ok: true },
    });
    await mount(<RoleNewPage />, "/permissions/roles/new");
    await click(host.querySelector("input[type=checkbox]") as HTMLElement);
    await click(host.querySelectorAll("input[type=checkbox]")[1] as HTMLElement);
    await click(button("Save role"));
    const assign = sent.find((s) => s.method === "POST" && s.path === "/policies/p1/assign");
    expect(assign?.body).toEqual({ identityId: "u1" });
  });
});

describe("Apps and bots", () => {
  it("lists apps, with waiting for the first sign-in until the bot has signed in", async () => {
    serve({
      "GET /apps": [
        {
          id: "a1",
          name: "deploy-ci",
          status: "active",
          createdAt: 1,
          owner: "alice@myorg.com",
          roleId: "r1",
          tokenTtl: 3600,
          maxUses: null,
          uses: 0,
          cidr: null,
          expiresAt: soon,
          firstLoginAt: null,
          lastLoginAt: null,
          lastIp: null,
          waiting: true,
        },
      ],
    });
    await mount(<AppsPage />, "/apps");
    expect(text()).toContain("deploy-ci");
    expect(text()).toContain("Waiting for first sign-in");
  });

  it("does not create an app while the name is empty, and sends nothing with a private key", async () => {
    const { sent } = serve({
      "GET /policies": [],
      "GET /keyrings": [],
    });
    await mount(<AppNewPage />, "/apps/new");
    await click(button("Create and get kit"));
    expect(text()).toContain("Give it a name.");
    expect(sent.some((s) => s.method === "POST" && s.path === "/apps")).toBe(false);
  });

  it("creates an app with the public key only, then holds the kit for the kit page", async () => {
    const { sent } = serve({
      "GET /policies": [],
      "GET /keyrings": [],
      "POST /apps": { id: "a9", roleId: "r9", secretId: "cfssid_9" },
    });
    await mount(<AppNewPage />, "/apps/new");
    await type("#app-name", "deploy-ci");
    await click(button("Create and get kit"));
    const post = sent.find((s) => s.method === "POST" && s.path === "/apps");
    const body = post?.body as Record<string, unknown>;
    expect(body.name).toBe("deploy-ci");
    expect(typeof body.publicKey).toBe("string");
    expect(Object.keys(body)).not.toContain("privateKey");
    expect(JSON.stringify(sent)).not.toMatch(/"privateKey"/);
  });

  it("shows the kit once: the page takes it, and a second visit says it is gone", async () => {
    serve({ "GET /apps/a1": { waiting: true } });
    holdKit({ id: "a1", name: "deploy-ci", kit: "cfskit1_TESTKIT", problems: [] });
    await mount(<AppKitPage id="a1" />, "/apps/a1/kit");
    expect(text()).toContain("cfskit1_TESTKIT");
    expect(text()).toContain("You can't see this again.");

    render(null, host);
    await flush();
    render(<AppKitPage id="a1" />, host);
    await flush();
    expect(text()).not.toContain("cfskit1_TESTKIT");
    expect(text()).toContain("This kit was shown once.");
  });

  it("clears the copied kit after 30 seconds only if the clipboard still holds it", async () => {
    let clip = "";
    vi.stubGlobal("navigator", {
      clipboard: {
        writeText: async (v: string) => {
          clip = v;
        },
        readText: async () => clip,
      },
    });
    const clears: Array<() => void> = [];
    const realSetTimeout = globalThis.setTimeout;
    vi.spyOn(globalThis, "setTimeout").mockImplementation(((fn: () => void, ms?: number) => {
      if (ms === 30_000) {
        clears.push(fn);
        return 0;
      }
      return realSetTimeout(fn, ms);
    }) as typeof setTimeout);
    serve({ "GET /apps/a1": { waiting: true } });
    holdKit({ id: "a1", name: "deploy-ci", kit: "cfskit1_COPY", problems: [] });
    await mount(<AppKitPage id="a1" />, "/apps/a1/kit");

    await click(button("Copy kit"));
    expect(clip).toBe("cfskit1_COPY");
    clip = "something the person copied later";
    for (const fn of clears) fn();
    await flush();
    expect(clip).toBe("something the person copied later");

    clip = "cfskit1_COPY";
    for (const fn of clears) fn();
    await flush();
    expect(clip).toBe("");
  });

  it("switches the destination tab and shows that tab's steps", async () => {
    serve({ "GET /apps/a1": { waiting: true } });
    holdKit({ id: "a1", name: "deploy-ci", kit: "cfskit1_X", problems: [] });
    await mount(<AppKitPage id="a1" />, "/apps/a1/kit");
    expect(text()).toContain("CFS_KIT: ${{ secrets.CFS_KIT }}");
    await click(button("AI agent"));
    expect(text()).toContain("cfs proxy --agent deploy-ci");
    expect(text()).not.toContain("CFS_KIT: ${{ secrets.CFS_KIT }}");
  });

  it("shows an app's sessions and recent activity, with its waiting status", async () => {
    serve({
      "GET /apps/a1": {
        id: "a1",
        name: "agent-billing",
        status: "active",
        createdAt: 1,
        owner: "alice@myorg.com",
        roleId: "r1",
        tokenTtl: 3600,
        maxUses: null,
        uses: 0,
        cidr: ["34.120.0.0/16"],
        expiresAt: soon,
        firstLoginAt: null,
        lastLoginAt: null,
        lastIp: null,
        waiting: true,
        sessions: [{ id: "s1", createdAt: 1, expiresAt: 4000 }],
        activity: [
          { at: 2, action: "secret.read", result: "ok", ip: null, note: "Monthly billing" },
        ],
      },
    });
    await mount(<AppDetailPage id="a1" />, "/apps/a1");
    expect(host.querySelector("h1")?.textContent).toBe("agent-billing");
    expect(text()).toContain("Waiting for first sign-in.");
    expect(text()).toContain("Active sessions");
    expect(text()).toContain("Recent activity");
    expect(text()).toContain("Opened a value");
    expect(text()).toContain("34.120.0.0/16");
  });
});

describe("Invite", () => {
  it("checks the email before sending, then sends the invite with the role", async () => {
    const { sent } = serve({ "POST /invites": { ok: true } });
    await mount(<InvitePage />, "/invite");
    await type("#invite-email", "not-an-email");
    await click(button("Send invite"));
    expect(text()).toContain("Type an email address");
    expect(sent.some((s) => s.path === "/invites")).toBe(false);

    await type("#invite-email", "Dimas@myorg.com");
    await click(button("Send invite"));
    const post = sent.find((s) => s.path === "/invites");
    expect(post?.body).toEqual({ email: "dimas@myorg.com", role: "member" });
    expect(text()).toContain("Invite saved.");
  });
});
