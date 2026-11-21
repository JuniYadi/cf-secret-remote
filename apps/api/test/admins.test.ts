import { describe, expect, it } from "vitest";
import { admin, api } from "./helpers.ts";

// ADR 20 two-admin rule (ADR 14 identity admin). Kept in its own file: the count is over every admin in
// storage, so the steps run in order in one test with no other admins created here.

describe("ADR 20: two admins must hold a vault", () => {
  it("demote and disable are refused until two other admins hold a vault", async () => {
    const a = await admin("pk-a");
    const b = await admin("pk-b");

    // Demoting or disabling b leaves one other admin with a vault: refused both ways.
    const demote = await api("PATCH", `/identities/${b.id}`, a.token, { role: "member" });
    expect(demote.status).toBe(409);
    const disable = await api("PATCH", `/identities/${b.id}`, a.token, { status: "disabled" });
    expect(disable.status).toBe(409);
    expect((await api("GET", "/whoami", b.token)).body.role).toBe("admin");

    // An admin without a vault does not count toward the two.
    await admin();
    expect((await api("PATCH", `/identities/${b.id}`, a.token, { role: "member" })).status).toBe(
      409,
    );

    // A third admin with a vault: now one may go.
    await admin("pk-c");
    const ok = await api("PATCH", `/identities/${b.id}`, a.token, { role: "member" });
    expect(ok.status).toBe(200);
    expect(ok.body.role).toBe("member");
  });
});
