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

it("moves the encrypted login to a group the caller can access", async () => {
  const { openLogin } = await import("@cfs/core");
  const pair = await generateKeyPair();
  unlock(pair);
  const personal = await newGroupKey();
  const group = await newGroupKey();
  const payload = {
    v: 1 as const,
    name: "Example",
    url: "",
    environment: "",
    role: "",
    username: "",
    password: "secret",
    totp: "",
    notes: "",
  };
  const sealed = await sealLogin(personal, "move", 1, payload);
  vi.spyOn(api, "personalKeyring").mockResolvedValue({
    id: "p",
    prefix: "personal",
    version: 1,
    wrappedKey: await wrapGroupKey(personal, pair.publicKey, "personal", 1),
  });
  vi.spyOn(api, "keyrings").mockResolvedValue([{ id: "g", prefix: "team", version: 2 }]);
  vi.spyOn(api, "groupKey").mockResolvedValue({
    version: 2,
    wrappedKey: await wrapGroupKey(group, pair.publicKey, "team", 2),
  });
  vi.spyOn(loginClient, "get").mockResolvedValue({
    id: "move",
    keyringId: "p",
    keyringVersion: 1,
    version: 1,
    ...sealed,
    fps: {},
    createdAt: 1,
    updatedAt: 1,
    size: 1,
  });
  const move = vi.spyOn(loginClient, "move").mockResolvedValue({ id: "move", version: 2 });
  host = document.createElement("div");
  document.body.append(host);
  render(<LoginDetailPage id="move" />, host);
  await tick();
  await tick();
  const select = host.querySelector<HTMLSelectElement>("#login-move");
  if (!select) throw new Error("missing target");
  select.value = "g";
  select.dispatchEvent(new Event("change", { bubbles: true }));
  await tick();
  Array.from(host.querySelectorAll("button")).find((x) => x.textContent === "Move")?.click();
  await tick();
  await tick();
  const call = move.mock.calls[0];
  if (!call) throw new Error("missing move");
  expect(call[1].keyringId).toBe("g");
  expect(call[1].keyringVersion).toBe(2);
  expect(await openLogin(group, "move", 2, call[1].wrappedDek, call[1].ciphertext)).toEqual(
    payload,
  );
});
