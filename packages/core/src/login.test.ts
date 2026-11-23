import { describe, expect, it } from "vitest";
import {
  type Login,
  loginFingerprints,
  loginOrigin,
  moveLogin,
  openLogin,
  sameLoginOrigin,
  sealLogin,
  totp,
} from "./login.ts";

const login: Login = {
  v: 1,
  name: "site",
  url: "https://example.com",
  environment: "test",
  role: "admin",
  username: "alice",
  password: "secret",
  totp: "",
  notes: "",
};
const key = new Uint8Array(32).fill(1);

describe("Login", () => {
  it("round-trips, uses fresh keys, and binds ciphertext to identity and version", async () => {
    const a = await sealLogin(key, "id", 1, login);
    const b = await sealLogin(key, "id", 1, login);
    expect(a).not.toEqual(b);
    expect(await openLogin(key, "id", 1, a.wrappedDek, a.ciphertext)).toEqual(login);
    await expect(openLogin(key, "other", 1, a.wrappedDek, a.ciphertext)).rejects.toThrow();
    await expect(openLogin(key, "id", 2, a.wrappedDek, a.ciphertext)).rejects.toThrow();
    await expect(
      openLogin(new Uint8Array(32), "id", 1, a.wrappedDek, a.ciphertext),
    ).rejects.toThrow();
    const other = new Uint8Array(32).fill(2);
    const moved = await moveLogin(key, other, "id", 1, a.wrappedDek, a.ciphertext);
    expect(await openLogin(other, "id", 2, moved.wrappedDek, moved.ciphertext)).toEqual(login);
    expect(await loginFingerprints(key, "id", login)).not.toEqual(
      await loginFingerprints(key, "id", { ...login, password: "changed" }),
    );
  });
  it("rejects oversized ciphertext", async () => {
    await expect(sealLogin(key, "id", 1, { ...login, notes: "x".repeat(65536) })).rejects.toThrow();
  });
  it("matches exact HTTP origins", () => {
    expect(loginOrigin("https://EXAMPLE.com:443/a")).toBe("https://example.com");
    expect(sameLoginOrigin("https://example.com/a", "https://example.com/b")).toBe(true);
    expect(sameLoginOrigin("https://example.com", "https://example.com:444")).toBe(false);
    expect(sameLoginOrigin("https://example.com", "http://example.com")).toBe(false);
    expect(sameLoginOrigin("bad", "bad")).toBe(false);
  });
  it("accepts raw base32 and rejects malformed TOTP input", async () => {
    expect(await totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59)).toBe("287082");
    await expect(totp("!", 59)).rejects.toThrow();
    await expect(totp("otpauth://hotp/a?secret=AA", 59)).rejects.toThrow();
  });
});
