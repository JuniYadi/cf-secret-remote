import { SELF } from "cloudflare:test";
import { expect, it } from "vitest";

it("reports the build-stamped version in health", async () => {
  const response = await SELF.fetch("http://t.test/api/health");
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({ ok: true, version: "v9.8.7-test" });
});
