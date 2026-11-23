// @vitest-environment happy-dom
import { render } from "preact";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../lib/api.ts";
import { setLang } from "../lib/i18n.ts";
import { loginClient } from "../lib/logins.ts";
import { LoginsListPage } from "./LoginsList.tsx";

let host: HTMLDivElement;
afterEach(() => {
  if (host) {
    render(null, host);
    host.remove();
  }
  vi.restoreAllMocks();
  setLang("en");
});
const tick = () => new Promise((resolve) => setTimeout(resolve, 20));
describe("login list", () => {
  it("shows an empty state and translated navigation", async () => {
    vi.spyOn(loginClient, "list").mockResolvedValue([]);
    vi.spyOn(api, "keyrings").mockResolvedValue([]);
    vi.spyOn(api, "personalKeyring").mockResolvedValue(null);
    setLang("id");
    host = document.createElement("div");
    document.body.append(host);
    render(<LoginsListPage />, host);
    await tick();
    expect(host.textContent).toContain("Belum ada akun");
    expect(host.querySelector('a[href="/logins/new"]')).not.toBeNull();
  });
  it("offers retry when loading fails", async () => {
    vi.spyOn(loginClient, "list").mockRejectedValue(new Error());
    vi.spyOn(api, "keyrings").mockResolvedValue([]);
    vi.spyOn(api, "personalKeyring").mockResolvedValue(null);
    host = document.createElement("div");
    document.body.append(host);
    render(<LoginsListPage />, host);
    await tick();
    expect(host.querySelector('[role="alert"]')?.textContent).toContain("Could not load");
    expect(host.querySelector("button")?.textContent).toContain("Try again");
  });
});
