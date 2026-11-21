import { describe, expect, it } from "vitest";
import { admin, api } from "./helpers.ts";

describe("cli device login", () => {
  it("pending, approved, then single use", async () => {
    const adm = await admin();
    const s = await api("POST", "/cli/start", null, { device: "laptop" });
    expect(s.body.userCode).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
    expect((await api("POST", "/cli/poll", null, { deviceCode: s.body.deviceCode })).status).toBe(
      202,
    );
    expect((await api("POST", "/cli/approve", adm.token, { userCode: "ZZZZ-ZZZZ" })).status).toBe(
      404,
    );
    expect(
      (await api("POST", "/cli/approve", adm.token, { userCode: s.body.userCode })).status,
    ).toBe(200);
    const p = await api("POST", "/cli/poll", null, { deviceCode: s.body.deviceCode });
    expect(p.status).toBe(200);
    expect(p.body.token).toMatch(/^cfs_/);
    expect((await api("GET", "/whoami", p.body.token)).status).toBe(200);
    expect((await api("POST", "/cli/poll", null, { deviceCode: s.body.deviceCode })).status).toBe(
      410,
    );
  });
});
