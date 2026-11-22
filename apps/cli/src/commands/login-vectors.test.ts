import { describe, expect, test } from "bun:test";
import { type Login, loginFingerprints, openLogin, totp } from "@cfs/core";
import vector from "../../../../packages/core/test-vectors/login.json";

describe("shared Login vectors", () => {
  test("opens the Login and computes its fingerprints and RFC 6238 codes", async () => {
    const key = Uint8Array.from(vector.groupKeyHex.match(/../g) ?? [], (x) =>
      Number.parseInt(x, 16),
    );
    const login = vector.login as Login;
    expect(
      await openLogin(key, vector.id, vector.version, vector.wrappedDek, vector.ciphertext),
    ).toEqual(login);
    expect(await loginFingerprints(key, vector.id, login)).toEqual(vector.fps);
    for (const item of vector.totp) expect(await totp(item.uri, item.time)).toBe(item.code);
  });
});
