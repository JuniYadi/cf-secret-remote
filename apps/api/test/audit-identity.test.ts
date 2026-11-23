import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { audit } from "../src/audit.ts";
import { planData } from "../src/repository/offboard.ts";
import { historyRows } from "../src/repository/versions.ts";
import { makeIdentity } from "./helpers.ts";

describe("audit identity", () => {
  it("keeps a person and an app with the same name separate", async () => {
    const person = await makeIdentity();
    const app = await makeIdentity({ name: person.name, kind: "app" });
    const path = `collision${Math.random().toString(36).slice(2)}/prod`;
    await audit(env.DB, {
      who: person.name,
      actor: { id: person.id, kind: "user" },
      action: "secret.read",
      path,
      version: 1,
      result: "ok",
    });
    await audit(env.DB, {
      who: app.name,
      actor: { id: app.id, kind: "app" },
      action: "secret.read",
      path,
      version: 2,
      result: "ok",
    });
    const plan = await planData(env.DB, person.id, person.name, 0, 0);
    expect(plan.reads.results.filter((r) => r.path === path).map((r) => r.version)).toEqual([1]);
    const history = await historyRows(env.DB, path, 0);
    expect(new Set(history.results.map((r) => r.identityId))).toEqual(new Set([person.id, app.id]));
  });
});

it("backfills only unambiguous historical names", async () => {
  const migration = (
    env as unknown as { TEST_MIGRATIONS: { name: string; queries: string[] }[] }
  ).TEST_MIGRATIONS.find((m) => m.name.startsWith("0018_"));
  expect(migration).toBeDefined();
  await env.DB.exec(
    "CREATE TABLE audit_backfill_test (who TEXT, entry TEXT); CREATE TABLE identity_backfill_test (id TEXT, name TEXT, kind TEXT);",
  );
  await env.DB.exec(
    "INSERT INTO identity_backfill_test VALUES ('u', 'unique', 'user'), ('p', 'shared', 'user'), ('a', 'shared', 'app'); INSERT INTO audit_backfill_test VALUES ('unique', '{}'), ('shared', '{}'), ('missing', '{}');",
  );
  for (const query of migration?.queries ?? []) {
    await env.DB.prepare(
      query
        .replaceAll(/\baudit\b/g, "audit_backfill_test")
        .replaceAll(/\bidentity\b/g, "identity_backfill_test")
        .replaceAll(/idx_identity_name_backfill/g, "idx_identity_name_backfill_test")
        .replaceAll(/idx_audit_(identity|path|action)/g, "idx_audit_test_$1"),
    ).run();
  }
  const rows = await env.DB.prepare(
    "SELECT who, identity_id, identity_kind FROM audit_backfill_test ORDER BY who",
  ).all();
  expect(rows.results).toEqual([
    { who: "missing", identity_id: null, identity_kind: null },
    { who: "shared", identity_id: null, identity_kind: null },
    { who: "unique", identity_id: "u", identity_kind: "user" },
  ]);
});
