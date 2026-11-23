// @vitest-environment happy-dom
import { generateKeyPair, newGroupKey, openLogin, wrapGroupKey } from "@cfs/core";
import { render } from "preact";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../lib/api.ts";
import { lock, unlock } from "../lib/keystore.ts";
import { loginClient } from "../lib/logins.ts";
import { LoginFormPage } from "./LoginForm.tsx";

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
it("validates TOTP and encrypts a new login to the personal key", async () => {
  const pair = await generateKeyPair();
  unlock(pair);
  const key = await newGroupKey();
  vi.spyOn(api, "personalKeyring").mockResolvedValue({
    id: "p",
    prefix: "personal",
    version: 1,
    wrappedKey: await wrapGroupKey(key, pair.publicKey, "personal", 1),
  });
  vi.spyOn(api, "keyrings").mockResolvedValue([]);
  vi.spyOn(loginClient, "list").mockResolvedValue([]);
  const create = vi.spyOn(loginClient, "create").mockResolvedValue({ id: "ok", version: 1 });
  host = document.createElement("div");
  document.body.append(host);
  render(<LoginFormPage />, host);
  await tick();
  const set = (name: string, value: string) => {
    const input = host.querySelector<HTMLInputElement>(`#login-${name}`);
    if (!input) throw new Error("missing field");
    input.value = value;
    input.dispatchEvent(new Event("input", { bubbles: true }));
  };
  set("name", "Example");
  set("totp", "invalid!");
  await tick();
  host
    .querySelector("form")
    ?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  await tick();
  expect(host.textContent).toContain("valid TOTP");
  expect(create).not.toHaveBeenCalled();
  set("totp", "JBSWY3DPEHPK3PXP");
  set("password", "secret");
  await tick();
  host
    .querySelector("form")
    ?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  await tick();
  await tick();
  expect(create).toHaveBeenCalledOnce();
  const call = create.mock.calls[0];
  if (!call) throw new Error("missing create call");
  const [id, body] = call;
  expect(body.keyringId).toBe("p");
  expect(JSON.stringify(body)).not.toContain("secret");
  expect((await openLogin(key, id, 1, body.wrappedDek, body.ciphertext)).password).toBe("secret");
});
