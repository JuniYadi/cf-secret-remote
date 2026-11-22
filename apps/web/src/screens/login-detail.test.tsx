// @vitest-environment happy-dom
import { generateKeyPair, newGroupKey, sealLogin, wrapGroupKey } from "@cfs/core";
import { render } from "preact";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../lib/api.ts";
import { lock, unlock } from "../lib/keystore.ts";
import { loginClient } from "../lib/logins.ts";
import { LoginDetailPage } from "./LoginDetail.tsx";

let host: HTMLDivElement;
afterEach(() => {
  if (host) {
    render(null, host);
    host.remove();
  }
  lock();
  vi.restoreAllMocks();
});
const tick = () => new Promise((resolve) => setTimeout(resolve, 30));
it("shows the TOTP without an audit and audits a password reveal", async () => {
  const pair = await generateKeyPair();
  unlock(pair);
  const key = await newGroupKey();
  const sealed = await sealLogin(key, "a", 1, {
    v: 1,
    name: "Example",
    url: "",
    environment: "",
    role: "",
    username: "",
    password: "hidden-value",
    totp: "JBSWY3DPEHPK3PXP",
    notes: "",
  });
  vi.spyOn(api, "personalKeyring").mockResolvedValue({
    id: "p",
    prefix: "personal",
    version: 1,
    wrappedKey: await wrapGroupKey(key, pair.publicKey, "personal", 1),
  });
  vi.spyOn(api, "keyrings").mockResolvedValue([]);
  vi.spyOn(loginClient, "get").mockResolvedValue({
    id: "a",
    keyringId: "p",
    keyringVersion: 1,
    version: 1,
    ...sealed,
    fps: {},
    createdAt: 1,
    updatedAt: 1,
    size: 1,
  });
  const audit = vi.spyOn(loginClient, "reveal").mockResolvedValue({ ok: true });
  host = document.createElement("div");
  document.body.append(host);
  render(<LoginDetailPage id="a" />, host);
  await tick();
  await tick();
  expect(host.textContent).toContain("Verification code");
  expect(host.textContent).not.toContain("hidden-value");
  expect(audit).not.toHaveBeenCalled();
  host.querySelector<HTMLButtonElement>('button[aria-label="Show Password"]')?.click();
  await tick();
  expect(audit).toHaveBeenCalledWith("a", { field: "password" });
  expect(host.textContent).toContain("hidden-value");
});
