import { describe, expect, it } from "vitest";
import { admin, api, makeIdentity } from "./helpers.ts";

// ADR 5 and the web Permissions page: GET /policies lists who holds each policy, and only admins read it.

describe("policy list shows holders", () => {
  it("returns assignees for each policy, with expiry when set", async () => {
    const adm = await admin();
    const name = `pl-${Date.now().toString(36)}`;
    const pol = await api("POST", "/policies", adm.token, {
      name,
      rules: [{ path: "pl/*", caps: ["read", "list"] }],
    });
    expect(pol.status).toBe(201);
    const person = await makeIdentity({ name: `${name}@test.dev` });
    await api("POST", `/policies/${pol.body.id}/assign`, adm.token, {
      identityId: person.id,
      expiresAt: 9999999999,
    });

    const list = await api<{ id: string; name: string; rules: unknown[]; assignees: unknown[] }[]>(
      "GET",
      "/policies",
      adm.token,
    );
    expect(list.status).toBe(200);
    const row = list.body.find((p) => p.id === pol.body.id);
    expect(row?.rules).toEqual([{ path: "pl/*", caps: ["read", "list"] }]);
    expect(row?.assignees).toEqual([
      { identityId: person.id, name: `${name}@test.dev`, kind: "user", expiresAt: 9999999999 },
    ]);
  });

  it("gives an empty assignee list when nobody holds the policy", async () => {
    const adm = await admin();
    const pol = await api("POST", "/policies", adm.token, {
      name: `pl-empty-${Date.now().toString(36)}`,
      rules: [],
    });
    const list = await api<{ id: string; assignees: unknown[] }[]>("GET", "/policies", adm.token);
    expect(list.body.find((p) => p.id === pol.body.id)?.assignees).toEqual([]);
  });

  it("refuses the list to members", async () => {
    const member = await makeIdentity({ role: "member" });
    const r = await api("GET", "/policies", member.token);
    expect(r.status).toBe(403);
  });
});
