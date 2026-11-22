// @vitest-environment happy-dom

import type { VNode } from "preact";
import { render } from "preact";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { QuotaBanner } from "../components/parts.tsx";
import { setLang } from "../lib/i18n.ts";
import { getStatus, lock, unlock } from "../lib/keystore.ts";
import { markQuotaReached, resetQuotaForTests } from "../lib/quota.ts";
import { clearPendingRecovery, setPendingRecovery } from "../lib/recovery-flow.ts";
import { loadSession, resetSessionForTests } from "../lib/session.ts";
import * as vault from "../lib/vault.ts";
import { ForgotPage } from "./Forgot.tsx";
import { OffboardPage } from "./Offboard.tsx";
import { PasswordChangePage } from "./PasswordChange.tsx";
import { QuotaReachedPage } from "./QuotaReached.tsx";
import { RecoverPage } from "./Recover.tsx";
import { RegrantPage } from "./Regrant.tsx";
import { RestorePage } from "./Restore.tsx";
import { SettingsPage } from "./Settings.tsx";
import { SettingsAdminsPage } from "./SettingsAdmins.tsx";
import { SettingsBackupPage } from "./SettingsBackup.tsx";
import { UnlockPage } from "./Unlock.tsx";
import { WasYouPage } from "./WasYou.tsx";

// Each screen rendered with the API mocked by a fetch stand-in (no network). Checks the text a person sees,
// and what the screen sends.

const ADMIN = {
  id: "u-alice",
  kind: "user",
  name: "alice@myorg.com",
  role: "admin",
  vaultReady: true,
  publicKey: "PUB-ALICE",
  lockedKey: "LOCK-ALICE",
};
const MEMBER = { ...ADMIN, id: "u-rina", name: "rina@myorg.com", role: "member" };

interface Call {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | undefined;
}

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });

/** Serves the given routes ("METHOD /path" keys, query strings ignored). Unknown routes answer 404. */
function serve(routes: Record<string, () => Response>) {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) => {
      const method = init.method ?? "GET";
      const path = url.split("?")[0];
      calls.push({
        method,
        url,
        headers: { ...(init.headers as Record<string, string>) },
        body: typeof init.body === "string" ? init.body : undefined,
      });
      const handler = routes[`${method} ${path}`];
      return handler ? handler() : json({ error: "not found" }, 404);
    }),
  );
  return calls;
}

const HEALTH = () => json({ ok: true, protocol: 1, version: "0.4.1" });
const WHOAMI = (me: unknown) => () => json(me);

let host: HTMLElement;
const flush = async () => {
  for (let i = 0; i < 4; i++) await new Promise((r) => setTimeout(r, 5));
};

async function mount(vnode: VNode) {
  render(vnode, host);
  await flush();
}

const text = () => host.textContent ?? "";

beforeEach(async () => {
  host = document.createElement("div");
  document.body.appendChild(host);
  setLang("en", undefined);
  resetQuotaForTests();
  clearPendingRecovery();
  lock();
  resetSessionForTests();
});

afterEach(() => {
  render(null, host);
  host.remove();
  lock();
  clearPendingRecovery();
  resetQuotaForTests();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

async function signIn(me: typeof ADMIN) {
  serve({ "GET /api/v1/whoami": WHOAMI(me) });
  await loadSession();
  unlock({ publicKey: "PUB-ALICE", privateKey: "PRIV-ALICE" });
}

describe("Settings, General", () => {
  it("shows the Worker version from /api/health and today's usage", async () => {
    await signIn(ADMIN);
    serve({
      "GET /api/health": HEALTH,
      "GET /api/v1/usage": () =>
        json({ day: "2026-11-21", writes: 62400, readsLogged: 0, limit: 100000, warning: false }),
      "GET /api/v1/identities": () => json([]),
    });
    await mount(<SettingsPage />);
    expect(text()).toContain("0.4.1");
    expect(text()).toContain("62,400 / 100,000");
    expect(text()).toContain("All good");
  });

  it("shows the usage warning as a state, not only as colour", async () => {
    await signIn(ADMIN);
    serve({
      "GET /api/health": HEALTH,
      "GET /api/v1/usage": () =>
        json({ day: "2026-11-21", writes: 85000, readsLogged: 0, limit: 100000, warning: true }),
      "GET /api/v1/identities": () => json([]),
    });
    await mount(<SettingsPage />);
    expect(text()).toContain("Check usage");
  });
});

describe("Unlock", () => {
  async function submitPassword(password: string) {
    const input = host.querySelector("#unlock-password") as HTMLInputElement;
    input.value = password;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();
    host
      .querySelector("form")
      ?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await flush();
  }

  it("pings after unlocking without waiting for the request", async () => {
    await signIn(ADMIN);
    lock();
    vi.spyOn(vault, "unlockVault").mockResolvedValue("PRIV-ALICE");
    const fetch = vi.fn((_url: string, _init: RequestInit) => new Promise<Response>(() => {}));
    vi.stubGlobal("fetch", fetch);
    await mount(<UnlockPage />);
    await submitPassword("password");
    expect(fetch).toHaveBeenCalledOnce();
    expect(fetch.mock.calls[0]?.[0]).toBe("/api/v1/me/unlocked");
    expect(fetch.mock.calls[0]?.[1]?.method).toBe("POST");
    expect(getStatus().unlocked).toBe(true);
  });

  it("keeps the vault open when the ping fails and never pings for a wrong password", async () => {
    await signIn(ADMIN);
    lock();
    const decrypt = vi
      .spyOn(vault, "unlockVault")
      .mockRejectedValueOnce(new Error("wrong password"))
      .mockResolvedValueOnce("PRIV-ALICE");
    const fetch = vi.fn().mockRejectedValue(new Error("offline"));
    vi.stubGlobal("fetch", fetch);
    await mount(<UnlockPage />);
    await submitPassword("wrong");
    expect(fetch).not.toHaveBeenCalled();
    expect(getStatus().unlocked).toBe(false);
    expect(text()).toContain("That password didn't work.");
    await submitPassword("correct");
    expect(decrypt).toHaveBeenCalledTimes(2);
    expect(fetch).toHaveBeenCalledOnce();
    expect(getStatus().unlocked).toBe(true);
  });
});

describe("Settings, Admins", () => {
  it("warns when only one admin holds a vault, and shows each admin's key and recovery status", async () => {
    await signIn(ADMIN);
    serve({
      "GET /api/v1/identities": () =>
        json([
          {
            id: "u-alice",
            kind: "user",
            name: "alice@myorg.com",
            role: "admin",
            publicKey: "PUB",
            status: "active",
            recoverySet: 1,
            last_unlocked_at: 1700000000,
          },
          {
            id: "u-bob",
            kind: "user",
            name: "bob@myorg.com",
            role: "admin",
            publicKey: null,
            status: "active",
            recoverySet: 0,
            last_unlocked_at: null,
          },
        ]),
    });
    await mount(<SettingsAdminsPage />);
    expect(text()).toContain("Only one admin can open the vault");
    expect(text()).toContain("Saved");
    expect(text()).toContain("Hasn't set up");
    expect(text()).toContain("Last unlocked");
    expect(text()).toContain(
      new Date(1700000000 * 1000).toLocaleString("en-GB", {
        day: "2-digit",
        month: "short",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      }),
    );
    expect(text()).toContain("Never");
    setLang("id", undefined);
    await flush();
    expect(text()).toContain("Terakhir dibuka");
    expect(text()).toContain("Belum pernah");
    expect(text()).toContain(
      new Date(1700000000 * 1000).toLocaleString("id-ID", {
        day: "2-digit",
        month: "short",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      }),
    );
  });

  it("demotes through PATCH /identities/:id, and never sends the server a key", async () => {
    await signIn(ADMIN);
    const calls = serve({
      "GET /api/v1/identities": () =>
        json([
          {
            id: "u-alice",
            kind: "user",
            name: "alice@myorg.com",
            role: "admin",
            publicKey: "PUB",
            status: "active",
            recoverySet: 0,
          },
          {
            id: "u-carl",
            kind: "user",
            name: "carl@myorg.com",
            role: "admin",
            publicKey: "PUB2",
            status: "active",
            recoverySet: 0,
          },
          {
            id: "u-dana",
            kind: "user",
            name: "dana@myorg.com",
            role: "admin",
            publicKey: "PUB3",
            status: "active",
            recoverySet: 0,
          },
        ]),
      "PATCH /api/v1/identities/u-carl": () =>
        json({ id: "u-carl", role: "member", status: "active" }),
    });
    await mount(<SettingsAdminsPage />);
    const buttons = Array.from(host.querySelectorAll("button")).filter(
      (b) => b.textContent === "Make member",
    );
    expect(buttons).toHaveLength(3);
    buttons[1]?.click();
    await flush();
    const patch = calls.find((c) => c.method === "PATCH");
    expect(patch?.url).toBe("/api/v1/identities/u-carl");
    expect(patch?.body).toBe(JSON.stringify({ role: "member" }));
  });

  it("is not shown to a member", async () => {
    await signIn(MEMBER);
    await mount(<SettingsAdminsPage />);
    expect(text()).toContain("Only admins can see this.");
  });
});

describe("Settings, Backup", () => {
  it("downloads with the passphrase in a header, never in the URL", async () => {
    await signIn(ADMIN);
    const calls = serve({
      "GET /api/v1/backup": () => new Response(new Uint8Array([9, 9]), { status: 200 }),
    });
    const createUrl = vi.fn(() => "blob:test");
    vi.stubGlobal(
      "URL",
      Object.assign(URL, { createObjectURL: createUrl, revokeObjectURL: vi.fn() }),
    );
    await mount(<SettingsBackupPage />);

    const input = host.querySelector("#backup-passphrase") as HTMLInputElement;
    input.value = "correct horse battery";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();
    const form = host.querySelector("form") as HTMLFormElement;
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await flush();

    const get = calls.find((c) => c.method === "GET" && c.url === "/api/v1/backup");
    expect(get).toBeDefined();
    expect(get?.url).toBe("/api/v1/backup");
    expect(get?.url).not.toContain("correct");
    expect(get?.headers["X-Backup-Passphrase"]).toBe("correct horse battery");
    // The page itself never shows the passphrase after the download.
    expect(text()).not.toContain("correct horse battery");
    expect(createUrl).toHaveBeenCalled();
  });

  it("shows the latest backup and the list, with a size for automatic copies only", async () => {
    await signIn(ADMIN);
    serve({
      "GET /api/v1/backup/history": () =>
        json({
          r2: true,
          copies: [
            { at: 1_800_000_100, type: "auto", size: 4501 },
            { at: 1_800_000_000, type: "manual", size: null },
          ],
        }),
    });
    await mount(<SettingsBackupPage />);
    expect(text()).toContain("Latest backup");
    expect(text()).toContain("Automatic");
    const rows = Array.from(host.querySelectorAll("tbody tr")).map((r) => r.textContent ?? "");
    expect(rows[0]).toContain("4.4 KB");
    expect(rows[1]).toContain("Manual");
    expect(rows[1]).toContain("-");
    expect(text()).not.toContain("Automatic daily backups are off");
  });

  it("says automatic backups are off without R2, and still lets you download", async () => {
    await signIn(ADMIN);
    serve({ "GET /api/v1/backup/history": () => json({ r2: false, copies: [] }) });
    await mount(<SettingsBackupPage />);
    expect(text()).toContain("No backup has been made yet.");
    expect(text()).toContain("Automatic daily backups are off");
    expect(host.querySelector("#backup-passphrase")).not.toBeNull();
  });

  it("says what is and is not encrypted", async () => {
    await signIn(ADMIN);
    await mount(<SettingsBackupPage />);
    expect(text()).toContain("Names, paths, emails and dates are in clear");
    expect(text()).toContain("AES-256-GCM");
  });

  it("refuses a passphrase shorter than the minimum, before any request", async () => {
    await signIn(ADMIN);
    const calls = serve({});
    await mount(<SettingsBackupPage />);
    const input = host.querySelector("#backup-passphrase") as HTMLInputElement;
    input.value = "short";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();
    (host.querySelector("form") as HTMLFormElement).dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await flush();
    expect(text()).toContain("The passphrase needs at least 8 characters.");
    expect(calls.filter((c) => c.url === "/api/v1/backup")).toHaveLength(0);
  });
});

describe("Restore", () => {
  it("opens on the first step, with the three steps named", async () => {
    await signIn(ADMIN);
    await mount(<RestorePage />);
    expect(host.querySelector("h1")?.textContent).toBe("Restore from a backup");
    expect(text()).toContain("Choose file");
    expect(text()).toContain("Check file");
  });
});

describe("Offboard", () => {
  it("lists the people who can be offboarded, not the admin themself", async () => {
    await signIn(ADMIN);
    serve({
      "GET /api/v1/identities": () =>
        json([
          {
            id: "u-alice",
            kind: "user",
            name: "alice@myorg.com",
            role: "admin",
            publicKey: "P",
            status: "active",
            recoverySet: 0,
          },
          {
            id: "u-dewi",
            kind: "user",
            name: "dewi@myorg.com",
            role: "member",
            publicKey: "P",
            status: "active",
            recoverySet: 0,
          },
          {
            id: "app1",
            kind: "app",
            name: "deploy-ci",
            role: "member",
            publicKey: null,
            status: "active",
            recoverySet: 0,
          },
        ]),
    });
    await mount(<OffboardPage />);
    const options = Array.from(host.querySelectorAll("#offboard-who option")).map(
      (o) => o.textContent,
    );
    expect(options).toContain("dewi@myorg.com");
    expect(options).not.toContain("alice@myorg.com");
    expect(options).not.toContain("deploy-ci");
  });

  it("is not shown to a member", async () => {
    await signIn(MEMBER);
    await mount(<OffboardPage />);
    expect(text()).toContain("Only admins can see this.");
  });
});

describe("Give access again", () => {
  it("shows an empty list when nobody is waiting", async () => {
    await signIn(ADMIN);
    serve({ "GET /api/v1/recovery": () => json([]) });
    await mount(<RegrantPage />);
    expect(text()).toContain("Nobody is waiting for access.");
  });

  it("keeps the give button off until the four words match", async () => {
    await signIn(ADMIN);
    serve({
      "GET /api/v1/recovery/r1": () =>
        json({
          id: "r1",
          name: "rina@myorg.com",
          status: "pending",
          attemptsLeft: 5,
          publicKey:
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJ2hEYo9q0x3k7qkIskBE5SDryBZ1dQHhe1gHYR5EE8T9NXUwMHTCmgJ7S0osVvhgh0u-AEJvnNRJxaKdnR4SLQ",
          groups: ["myapp"],
        }),
    });
    await mount(<RegrantPage id="r1" />);
    expect(text()).toContain("rina@myorg.com");
    const give = Array.from(host.querySelectorAll("button")).find(
      (b) => b.textContent === "Give access again",
    );
    expect(give?.disabled).toBe(true);
  });
});

describe("Forgot your vault password", () => {
  it("asks for a new vault password, and says what happens next", async () => {
    serve({});
    await mount(<ForgotPage />);
    expect(host.querySelector("h1")?.textContent).toBe("Forgot your vault password?");
    expect(host.querySelector("#forgot-password")).not.toBeNull();
    expect(text()).toContain("Start recovery");
  });

  it("waits with the four words once a request is pending", async () => {
    setPendingRecovery({
      id: "r9",
      words: "anchor velvet kiwi sixty",
      cancelToken: "cfsr_x",
      publicKey: "PUB",
      lockedKey: "LOCK",
    });
    serve({});
    await mount(<ForgotPage />);
    expect(text()).toContain("anchor velvet kiwi sixty");
    expect(text()).toContain("Cancel this request");
  });
});

describe("Use your recovery key", () => {
  it("explains when there is no recovery key saved", async () => {
    serve({
      "GET /api/v1/me/recovery": () => json({ set: false, lockedKey: null }),
    });
    await mount(<RecoverPage />);
    await flush();
    expect(text()).toContain("You don't have a recovery key saved.");
  });

  it("asks for the 24 words and a new password when a key is saved", async () => {
    serve({
      "GET /api/v1/me/recovery": () =>
        json({ set: true, lockedKey: "rk1.v1.AAAAAAAAAAAAAAAA.BBBBBBBBBBBBBBBBBBBB" }),
    });
    await mount(<RecoverPage />);
    await flush();
    expect(host.querySelector("#recover-words")).not.toBeNull();
    expect(host.querySelector("#recover-password")).not.toBeNull();
  });
});

describe("Was this you?", () => {
  it("says so when there is no request on this device", async () => {
    await mount(<WasYouPage />);
    expect(text()).toContain("There's no request to cancel on this device.");
  });

  it("cancels with the token in the body, not the URL", async () => {
    setPendingRecovery({
      id: "r7",
      words: "anchor velvet kiwi sixty",
      cancelToken: "cfsr_secret_token",
      publicKey: "PUB",
      lockedKey: "LOCK",
    });
    const calls = serve({
      "POST /api/v1/recovery/r7/cancel": () => json({ ok: true }),
    });
    await mount(<WasYouPage />);
    const cancel = Array.from(host.querySelectorAll("button")).find(
      (b) => b.textContent === "No, cancel it",
    );
    cancel?.click();
    await flush();
    const post = calls.find((c) => c.method === "POST");
    expect(post?.url).toBe("/api/v1/recovery/r7/cancel");
    expect(post?.url).not.toContain("cfsr_secret_token");
    expect(post?.body).toBe(JSON.stringify({ token: "cfsr_secret_token" }));
    expect(text()).toContain("The request is cancelled. Nothing was unlocked.");
  });
});

describe("Change vault password", () => {
  it("shows the three fields and what changes", async () => {
    await signIn(ADMIN);
    await mount(<PasswordChangePage />);
    expect(host.querySelector("h1")?.textContent).toBe("Change vault password");
    expect(host.querySelector("#pw-current")).not.toBeNull();
    expect(text()).toContain("Only the password that locks your key changes.");
  });
});

describe("Quota reached", () => {
  it("shows the Quota screen with what still works and what is paused", async () => {
    await signIn(ADMIN);
    serve({
      "GET /api/v1/usage": () =>
        json({ day: "2026-11-21", writes: 100000, readsLogged: 0, limit: 100000, warning: true }),
    });
    await mount(<QuotaReachedPage />);
    expect(host.querySelector("h1")?.textContent).toBe("Free plan limit reached");
    expect(text()).toContain("Still works");
    expect(text()).toContain("Paused until it resets");
    expect(text()).toContain("Saving works again.");
  });

  it("the banner appears on shell pages while the quota is reached", async () => {
    markQuotaReached(120);
    await mount(<QuotaBanner />);
    expect(text()).toContain("Free plan limit reached for today");
    expect(text()).toContain("Opening secrets still works.");
  });

  it("no banner when the quota is not reached", async () => {
    await mount(<QuotaBanner />);
    expect(text()).toBe("");
  });
});
