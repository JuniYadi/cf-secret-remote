// @vitest-environment happy-dom
import { render } from "preact";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./app.tsx";
import type { Me } from "./lib/api.ts";
import { lock, unlock } from "./lib/keystore.ts";
import { resetSessionForTests } from "./lib/session.ts";

// Smoke test of the real app shell in a DOM: boot, the route guard, and lock. Crypto is not exercised here.

const ME: Me = {
  id: "u1",
  kind: "user",
  name: "alice@myorg.com",
  role: "admin",
  vaultReady: true,
  publicKey: "PUB-TEST",
  lockedKey: "LOCK-TEST",
};

let host: HTMLElement;

const flush = async () => {
  for (let i = 0; i < 3; i++) await new Promise((r) => setTimeout(r, 10));
};

function serveWhoami(body: Me | null, status = 200) {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(body ? JSON.stringify(body) : "{}", {
          status,
          headers: { "content-type": "application/json" },
        }),
    ),
  );
}

async function mount(path: string) {
  history.replaceState({}, "", path);
  render(<App />, host);
  await flush();
}

const heading = () => host.querySelector("h1")?.textContent ?? "";

beforeEach(() => {
  host = document.createElement("div");
  document.body.appendChild(host);
  lock();
  resetSessionForTests();
});

afterEach(() => {
  render(null, host);
  host.remove();
  lock();
  vi.unstubAllGlobals();
  history.replaceState({}, "", "/");
});

describe("app shell", () => {
  it("shows Session ended when /whoami answers 401", async () => {
    serveWhoami(null, 401);
    await mount("/secrets");
    expect(heading()).toBe("Your session ended");
    expect(document.title).toBe("Your session ended");
  });

  it("sends a locked vault to Unlock, with the title equal to the h1", async () => {
    serveWhoami(ME);
    await mount("/secrets");
    expect(window.location.pathname).toBe("/unlock");
    expect(heading()).toBe("Unlock your vault");
    expect(document.title).toBe("Unlock your vault");
  });

  it("Lock vault drops the key and returns to Unlock", async () => {
    serveWhoami(ME);
    unlock({ publicKey: "PUB-TEST", privateKey: "PRIV-TEST" });
    await mount("/secrets");
    expect(heading()).toBe("Secrets");
    const lockButton = Array.from(host.querySelectorAll("button")).find(
      (b) => b.textContent === "Lock vault",
    );
    expect(lockButton).toBeTruthy();
    lockButton?.click();
    await flush();
    expect(window.location.pathname).toBe("/unlock");
    expect(heading()).toBe("Unlock your vault");
  });
});
