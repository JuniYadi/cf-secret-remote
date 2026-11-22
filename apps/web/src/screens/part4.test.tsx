// @vitest-environment happy-dom
import type { VNode } from "preact";
import { render } from "preact";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../lib/api.ts";
import { setLang } from "../lib/i18n.ts";
import { lock } from "../lib/keystore.ts";
import { loadSession, resetSessionForTests } from "../lib/session.ts";
import { type Routes, routeFetch } from "../test/route-fetch.ts";
import { ActivityPage } from "./Activity.tsx";
import { AgentRulesPage } from "./AgentRules.tsx";
import { AlertsPage } from "./Alerts.tsx";
import { CliAuthorizePage } from "./CliAuthorize.tsx";
import { CliDonePage } from "./CliDone.tsx";
import { DevicesPage } from "./Devices.tsx";
import { RequestsPage } from "./Requests.tsx";

// Each screen is rendered with the Worker's API replaced by a fake fetch. Crypto is not exercised here
// (lib/requests.test.ts covers it), so the vault is shown as unlocked with placeholder keys.

const ADMIN: Me = {
  id: "me-1",
  kind: "user",
  name: "alice@myorg.com",
  role: "admin",
  vaultReady: true,
  publicKey: "PUB-TEST",
  lockedKey: "LOCK-TEST",
};

const MEMBER: Me = { ...ADMIN, id: "me-2", name: "bob@myorg.com", role: "member" };

let host: HTMLElement;

const flush = async () => {
  for (let i = 0; i < 4; i++) await new Promise((r) => setTimeout(r, 10));
};

const nowSec = () => Math.floor(Date.now() / 1000);

async function mount(me: Me, routes: Routes, node: () => VNode) {
  const stub = routeFetch({ "GET /whoami": { body: me }, ...routes });
  vi.stubGlobal("fetch", stub.fn);
  await loadSession();
  render(node(), host);
  await flush();
  return stub;
}

const text = () => host.textContent ?? "";

function buttonByLabel(label: string): HTMLButtonElement | undefined {
  return Array.from(host.querySelectorAll("button")).find(
    (b) => b.getAttribute("aria-label") === label || b.textContent?.trim() === label,
  );
}

/** Types into a field, then waits for the render, as a person's next keystroke or click would. */
async function setInput(selector: string, value: string) {
  const el = host.querySelector<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>(
    selector,
  );
  if (!el) throw new Error(`missing ${selector}`);
  el.value = value;
  // Text fields listen to input, selects to change. Sending both matches what a browser does for each.
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
  await flush();
}

function submit(selector: string) {
  const form = host.querySelector<HTMLFormElement>(selector);
  if (!form) throw new Error(`missing form ${selector}`);
  form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
}

beforeEach(() => {
  host = document.createElement("div");
  document.body.appendChild(host);
  lock();
  resetSessionForTests();
  setLang("en", undefined);
});

afterEach(() => {
  render(null, host);
  host.remove();
  lock();
  vi.unstubAllGlobals();
  history.replaceState({}, "", "/");
});

describe("Activity", () => {
  const audit = [
    {
      seq: 12,
      hash: "h12",
      at: nowSec() - 60,
      who: "bob@myorg.com",
      action: "secret.read",
      path: "myapp/prod",
      result: "denied",
      note: "",
    },
    {
      seq: 11,
      hash: "h11",
      at: nowSec() - 120,
      who: "agent-billing",
      action: "secret.read",
      path: "backend/payments/dev",
      result: "ok",
      note: "Monthly billing",
    },
  ];

  it("shows the title, the meter, the chain status and the log", async () => {
    await mount(
      ADMIN,
      {
        "GET /usage": {
          body: { day: "2026-11-21", writes: 62400, readsLogged: 0, limit: 100000, warning: false },
        },
        "GET /audit/verify": {
          body: {
            ok: true,
            rows: 2,
            firstBad: null,
            firstBadSeq: null,
            head: "h12",
            base: null,
            checkpoints: { stored: 1, verified: 1, pruned: 0, mismatched: [] },
          },
        },
        "GET /audit": { body: audit },
      },
      () => <ActivityPage />,
    );
    expect(host.querySelector("h1")?.textContent).toBe("Activity");
    expect(document.title).toBe("Activity");
    expect(text()).toContain("62,400 / 100,000");
    expect(text()).toContain("Verified");
    expect(host.querySelectorAll("tbody tr")).toHaveLength(2);
    expect(host.querySelector("tr.denied")).not.toBeNull();
    expect(host.querySelector(".usage-meter.warn")).toBeNull();
  });

  it("warns at 80% of the free writes, in words as well as colour", async () => {
    await mount(
      ADMIN,
      {
        "GET /usage": {
          body: { day: "2026-11-21", writes: 85000, readsLogged: 0, limit: 100000, warning: true },
        },
        "GET /audit/verify": {
          body: {
            ok: true,
            rows: 0,
            firstBad: null,
            firstBadSeq: null,
            head: "",
            base: null,
            checkpoints: { stored: 0, verified: 0, pruned: 0, mismatched: [] },
          },
        },
        "GET /audit": { body: [] },
      },
      () => <ActivityPage />,
    );
    expect(host.querySelector(".usage-meter.warn")).not.toBeNull();
    expect(text()).toContain("You've used 85% of today's free writes");
  });

  it("explains a broken chain and where it stopped", async () => {
    await mount(
      ADMIN,
      {
        "GET /usage": {
          body: { day: "d", writes: 1, readsLogged: 0, limit: 100000, warning: false },
        },
        "GET /audit/verify": {
          body: {
            ok: false,
            rows: 40,
            firstBad: 7,
            firstBadSeq: 12,
            head: "h40",
            base: null,
            checkpoints: { stored: 2, verified: 1, pruned: 0, mismatched: ["2026-11-20"] },
          },
        },
        "GET /audit": { body: [] },
      },
      () => <ActivityPage />,
    );
    expect(text()).toContain("Broken");
    expect(text()).toContain("entry #12");
  });

  it("filters the log by who and sends the query", async () => {
    const stub = await mount(
      ADMIN,
      {
        "GET /usage": {
          body: { day: "d", writes: 1, readsLogged: 0, limit: 100000, warning: false },
        },
        "GET /audit/verify": {
          body: {
            ok: true,
            rows: 0,
            firstBad: null,
            firstBadSeq: null,
            head: "",
            base: null,
            checkpoints: { stored: 0, verified: 0, pruned: 0, mismatched: [] },
          },
        },
        "GET /audit": { body: audit },
      },
      () => <ActivityPage />,
    );
    await setInput("#f-who", "bob@myorg.com");
    await setInput("#f-result", "denied");
    submit("form.filters");
    await flush();
    const last = stub.to("GET /audit").at(-1);
    expect(last?.search.get("who")).toBe("bob@myorg.com");
    expect(last?.search.get("result")).toBe("denied");
    expect(last?.search.get("from")).not.toBeNull();
  });

  const quiet = {
    "GET /usage": {
      body: { day: "d", writes: 1, readsLogged: 0, limit: 100000, warning: false },
    },
    "GET /audit/verify": {
      body: {
        ok: true,
        rows: 0,
        firstBad: null,
        firstBadSeq: null,
        head: "",
        base: null,
        checkpoints: { stored: 0, verified: 0, pruned: 0, mismatched: [] },
      },
    },
  };

  it("shows the 24-hour stat cards and a Type pill for each row", async () => {
    await mount(
      ADMIN,
      {
        ...quiet,
        "GET /audit/stats": {
          body: { since: 0, accesses: 1204, byApps: 310, blocked: 7, actors: 9 },
        },
        "GET /audit": {
          body: [
            { ...audit[0], kind: "user" },
            { ...audit[1], kind: "app" },
          ],
        },
      },
      () => <ActivityPage />,
    );
    expect(text()).toContain("1,204");
    expect(text()).toContain("accesses in the last 24 hours");
    expect(text()).toContain("blocked");
    const pills = Array.from(host.querySelectorAll("td .pill")).map((p) => p.textContent);
    expect(pills).toContain("Person");
    expect(pills).toContain("App");
  });

  it("filters by type and sends kind", async () => {
    const stub = await mount(ADMIN, { ...quiet, "GET /audit": { body: [] } }, () => (
      <ActivityPage />
    ));
    await setInput("#f-kind", "app");
    submit("form.filters");
    await flush();
    expect(stub.to("GET /audit").at(-1)?.search.get("kind")).toBe("app");
  });

  it("exports the applied filters as CSV", async () => {
    const created = vi.fn(() => "blob:x");
    vi.stubGlobal(
      "URL",
      Object.assign(URL, { createObjectURL: created, revokeObjectURL: vi.fn() }),
    );
    const stub = await mount(
      ADMIN,
      { ...quiet, "GET /audit": { body: [] }, "GET /audit/export.csv": { body: {} } },
      () => <ActivityPage />,
    );
    await setInput("#f-who", "bob@myorg.com");
    submit("form.filters");
    await flush();
    buttonByLabel("Export CSV")?.click();
    await flush();
    const hit = stub.to("GET /audit/export.csv").at(-1);
    expect(hit?.search.get("who")).toBe("bob@myorg.com");
    expect(hit?.search.get("limit")).toBeNull();
    expect(created).toHaveBeenCalledOnce();
  });

  it("rejects a path that is not a path before sending", async () => {
    const stub = await mount(
      ADMIN,
      {
        "GET /usage": {
          body: { day: "d", writes: 1, readsLogged: 0, limit: 100000, warning: false },
        },
        "GET /audit/verify": {
          body: {
            ok: true,
            rows: 0,
            firstBad: null,
            firstBadSeq: null,
            head: "",
            base: null,
            checkpoints: { stored: 0, verified: 0, pruned: 0, mismatched: [] },
          },
        },
        "GET /audit": { body: [] },
      },
      () => <ActivityPage />,
    );
    const before = stub.to("GET /audit").length;
    await setInput("#f-path", "back end/*");
    submit("form.filters");
    await flush();
    expect(text()).toContain("Use a path such as myapp/prod");
    expect(stub.to("GET /audit").length).toBe(before);
  });

  it("says that activity is for admins to a member, and loads nothing", async () => {
    const stub = await mount(MEMBER, {}, () => <ActivityPage />);
    expect(text()).toContain("Activity is for admins");
    expect(stub.to("GET /audit")).toHaveLength(0);
  });
});

describe("Alerts", () => {
  const settings = {
    webhook: "https://hooks.slack.com/services/T0••••/B0••••/••••",
    email: { available: false, recipients: [] },
    rules: {
      blocked: { webhook: true, email: false },
      agent_prod_read: { webhook: false, email: false },
      new_network: { webhook: false, email: false },
      read_burst: { webhook: false, email: false },
      quota_80: { webhook: false, email: false },
      chain_broken: { webhook: false, email: false },
      recovery_requested: { webhook: false, email: false },
      access_request: { webhook: false, email: false },
    },
  };

  it("shows the webhook masked and the rules", async () => {
    await mount(ADMIN, { "GET /alerts": { body: settings } }, () => <AlertsPage />);
    expect(text()).toContain("hooks.slack.com/services/T0");
    expect(text()).toContain("A blocked attempt");
    expect(host.querySelectorAll('[role="switch"]').length).toBe(16);
  });

  it("switches a rule's channel and sends the whole rule map", async () => {
    const stub = await mount(
      ADMIN,
      {
        "GET /alerts": { body: settings },
        "PUT /alerts": (hit) => ({
          body: { ...settings, rules: (hit.body as { rules: unknown }).rules },
        }),
      },
      () => <AlertsPage />,
    );
    buttonByLabel("A blocked attempt: webhook")?.click();
    await flush();
    const put = stub.to("PUT /alerts").at(-1);
    const rules =
      (put?.body as { rules: Record<string, { webhook: boolean }> } | undefined)?.rules ?? {};
    expect(rules.blocked?.webhook).toBe(false);
    expect(Object.keys(rules)).toHaveLength(8);
  });

  it("saves a webhook once and clears the field", async () => {
    const stub = await mount(
      ADMIN,
      {
        "GET /alerts": { body: { ...settings, webhook: null } },
        "PUT /alerts": { body: settings },
      },
      () => <AlertsPage />,
    );
    await setInput("#webhook-url", "https://hooks.example.com/services/abc");
    submit("form:not(.filters)");
    await flush();
    const put = stub.to("PUT /alerts")[0];
    const webhook = (put?.body as { webhook: string } | undefined)?.webhook;
    expect(webhook).toBe("https://hooks.example.com/services/abc");
    expect(host.querySelector<HTMLInputElement>("#webhook-url")?.value).toBe("");
    expect(text()).toContain("shown masked from now on");
  });

  it("refuses an http webhook before sending", async () => {
    const stub = await mount(
      ADMIN,
      { "GET /alerts": { body: settings }, "PUT /alerts": { body: settings } },
      () => <AlertsPage />,
    );
    await setInput("#webhook-url", "http://hooks.example.com/x");
    submit("form:not(.filters)");
    await flush();
    expect(stub.to("PUT /alerts")).toHaveLength(0);
    expect(text()).toContain("Use an https:// address.");
  });
});

describe("Access requests", () => {
  const waiting = {
    id: "req-1",
    requesterId: "u-bob",
    requester: "bob@myorg.com",
    path: "shop/prod",
    groupPrefix: "shop",
    reason: "Hotfix for checkout bug #482",
    duration: 3600,
    rekeyAfter: false,
    status: "pending",
    approver: null,
    createdAt: nowSec() - 240,
    decidedAt: null,
    expiresAt: null,
  };
  const approved = {
    ...waiting,
    id: "req-2",
    requester: "rina@myorg.com",
    status: "approved",
    approver: "alice@myorg.com",
    expiresAt: nowSec() + 4320,
  };

  it("shows the approver queue and the decisions for an admin", async () => {
    await mount(ADMIN, { "GET /requests": { body: [waiting, approved] } }, () => <RequestsPage />);
    expect(text()).toContain("Waiting for you");
    expect(text()).toContain("Hotfix for checkout bug #482");
    expect(text()).toContain("Approve for 1 hour");
    expect(text()).toContain("Approved");
    expect(text()).toContain("in 1 h");
  });

  it("asks to unlock before approving, and sends nothing", async () => {
    const stub = await mount(ADMIN, { "GET /requests": { body: [waiting] } }, () => (
      <RequestsPage />
    ));
    buttonByLabel("Approve for 1 hour")?.click();
    await flush();
    expect(text()).toContain("Unlock your vault to approve.");
    expect(stub.to("POST /requests/req-1/approve")).toHaveLength(0);
    expect(stub.to("GET /keyrings/shop/key")).toHaveLength(0);
  });

  it("denies a waiting request", async () => {
    const stub = await mount(
      ADMIN,
      {
        "GET /requests": { body: [waiting] },
        "POST /requests/req-1/deny": { body: { ...waiting, status: "denied" } },
      },
      () => <RequestsPage />,
    );
    buttonByLabel("Deny")?.click();
    await flush();
    expect(stub.to("POST /requests/req-1/deny")).toHaveLength(1);
  });

  it("checks the request form before sending", async () => {
    const stub = await mount(
      MEMBER,
      { "GET /requests": { body: [] }, "POST /requests": { status: 201, body: waiting } },
      () => <RequestsPage />,
    );
    submit("form.ask-form");
    await flush();
    expect(text()).toContain("Use a path such as myapp/prod");
    expect(text()).toContain("Add a short reason");
    expect(stub.to("POST /requests")).toHaveLength(0);
  });

  it("sends a valid request with the chosen duration", async () => {
    const stub = await mount(
      MEMBER,
      { "GET /requests": { body: [] }, "POST /requests": { status: 201, body: waiting } },
      () => <RequestsPage />,
    );
    await setInput("#ask-path", "shop/prod");
    await setInput("#ask-reason", "Month-end reconciliation");
    await setInput("#ask-duration", "7200");
    submit("form.ask-form");
    await flush();
    const sent = stub.to("POST /requests")[0]?.body as {
      path: string;
      reason: string;
      duration: number;
    };
    expect(sent).toEqual({ path: "shop/prod", reason: "Month-end reconciliation", duration: 7200 });
  });
});

describe("Agent rules", () => {
  const rule = {
    alias: "billing",
    secretPath: "payments/prod",
    name: "STRIPE_KEY",
    upstream: "https://api.stripe.com/v1",
    inject: "header:Authorization:Bearer {value}",
    maxReadsPerHour: 60,
    requireReason: true,
    requireApproval: true,
  };

  it("lists the apps and the rules of the chosen one", async () => {
    await mount(
      ADMIN,
      {
        "GET /apps": { body: [{ id: "a1", name: "agent-billing", status: "active" }] },
        "GET /apps/a1/rules": { body: [rule] },
      },
      () => <AgentRulesPage />,
    );
    expect(host.querySelector<HTMLSelectElement>("#rules-app")?.value).toBe("a1");
    expect(text()).toContain("billing");
    expect(text()).toContain("Needs a person");
    expect(text()).toContain("The agent");
  });

  it("defaults approval on for a /prod path and sends the rule", async () => {
    const stub = await mount(
      ADMIN,
      {
        "GET /apps": { body: [{ id: "a1", name: "agent-billing", status: "active" }] },
        "GET /apps/a1/rules": { body: [] },
        "POST /apps/a1/rules": { status: 201, body: rule },
      },
      () => <AgentRulesPage />,
    );
    await setInput("#rule-alias", "reports");
    await setInput("#rule-secretPath", "reports/prod");
    await setInput("#rule-name", "REPORT_TOKEN");
    await setInput("#rule-upstream", "https://reports.example.com");
    submit("form.rule-form");
    await flush();
    const sent = stub.to("POST /apps/a1/rules")[0]?.body as {
      alias: string;
      requireApproval: boolean;
      maxReadsPerHour: number;
    };
    expect(sent.alias).toBe("reports");
    expect(sent.requireApproval).toBe(true);
    expect(sent.maxReadsPerHour).toBe(60);
  });

  it("does not send an invalid rule", async () => {
    const stub = await mount(
      ADMIN,
      {
        "GET /apps": { body: [{ id: "a1", name: "agent-billing", status: "active" }] },
        "GET /apps/a1/rules": { body: [] },
        "POST /apps/a1/rules": { status: 201, body: rule },
      },
      () => <AgentRulesPage />,
    );
    await setInput("#rule-alias", "Bad Alias");
    submit("form.rule-form");
    await flush();
    expect(stub.to("POST /apps/a1/rules")).toHaveLength(0);
    expect(text()).toContain("Check the highlighted fields.");
  });
});

describe("Signed-in devices", () => {
  const device = {
    id: "dev1abc",
    kind: "cli",
    device: "dev-laptop",
    createdAt: nowSec() - 3600,
    expiresAt: nowSec() + 25200,
  };

  it("signs out of a device only after a second press", async () => {
    const stub = await mount(
      ADMIN,
      {
        "GET /sessions": { body: [device] },
        "DELETE /sessions/dev1abc": { body: { ok: true } },
      },
      () => <DevicesPage />,
    );
    expect(text()).toContain("dev-laptop");
    buttonByLabel("Sign out of dev-laptop")?.click();
    await flush();
    expect(stub.to("DELETE /sessions/dev1abc")).toHaveLength(0);
    expect(buttonByLabel("Confirm sign out of dev-laptop")).toBeDefined();
    buttonByLabel("Confirm sign out of dev-laptop")?.click();
    await flush();
    expect(stub.to("DELETE /sessions/dev1abc")).toHaveLength(1);
  });
});

describe("CLI authorize", () => {
  const future = nowSec() + 600;

  it("checks the code, shows the device, and approves it", async () => {
    const stub = await mount(
      ADMIN,
      {
        "GET /cli/login": (hit) =>
          hit.search.get("code") === "ABCD-2EFG"
            ? { body: { userCode: "ABCD-2EFG", device: "dev-laptop", expiresAt: future } }
            : { status: 404, body: { error: "code not found or expired", attemptsLeft: 3 } },
        "POST /cli/approve": { body: { ok: true } },
      },
      () => <CliAuthorizePage />,
    );
    expect(host.querySelector("h1")?.textContent).toBe("Authorize cfs");
    await setInput("#cli-code", "abcd2efg");
    submit("form");
    await flush();
    expect(text()).toContain("dev-laptop");
    expect(text()).toContain("ABCD-2EFG");
    buttonByLabel("Authorize")?.click();
    await flush();
    expect(stub.to("POST /cli/approve")[0]?.body).toEqual({ userCode: "ABCD-2EFG" });
    history.replaceState({}, "", "/");
  });

  it("says how many tries are left after a wrong code", async () => {
    const stub = await mount(
      ADMIN,
      {
        "GET /cli/login": {
          status: 404,
          body: { error: "code not found or expired", attemptsLeft: 3 },
        },
      },
      () => <CliAuthorizePage />,
    );
    await setInput("#cli-code", "zzzz-zzzz");
    submit("form");
    await flush();
    expect(text()).toContain("3 tries left before a 10-minute wait");
    expect(stub.to("GET /cli/login")).toHaveLength(1);
    expect(stub.to("POST /cli/approve")).toHaveLength(0);
  });

  it("refuses a code that is too short before sending", async () => {
    const stub = await mount(ADMIN, { "GET /cli/login": { body: {} } }, () => <CliAuthorizePage />);
    await setInput("#cli-code", "abc");
    submit("form");
    await flush();
    expect(stub.to("GET /cli/login")).toHaveLength(0);
    expect(text()).toContain("Enter the 8 characters");
  });
});

describe("CLI done", () => {
  it("says you're signed in, with the next steps", async () => {
    await mount(ADMIN, {}, () => <CliDonePage />);
    expect(host.querySelector("h1")?.textContent).toBe("You're signed in");
    expect(text()).toContain("cfs unlock");
  });
});
