import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { loadLimits } from "../src/settings.ts";
import type { Env } from "../src/types.ts";
import { api, makeIdentity } from "./helpers.ts";

describe("limits settings", () => {
  it("defaults and falls back to the retention variable", async () => {
    const values = await loadLimits({ ...env, AUDIT_RETENTION_DAYS: "120" } as unknown as Env);
    expect(values).toEqual({
      maxRequestDuration: 86400,
      defaultApprovalDuration: 3600,
      auditRetentionDays: 120,
    });
    expect(
      (await loadLimits({ ...env, AUDIT_RETENTION_DAYS: "3" } as unknown as Env))
        .auditRetentionDays,
    ).toBe(90);
  });
  it("validates limits, restricts writes, and audits changes", async () => {
    const admin = await makeIdentity({ role: "admin" });
    const member = await makeIdentity({ role: "member" });
    const value = {
      maxRequestDuration: 7200,
      defaultApprovalDuration: 3600,
      auditRetentionDays: 100,
    };
    expect((await api("PUT", "/settings/limits", member.token, value)).status).toBe(403);
    for (const bad of [
      { ...value, maxRequestDuration: 2592001 },
      { ...value, defaultApprovalDuration: 7201 },
      { ...value, auditRetentionDays: 89 },
      { ...value, auditRetentionDays: "100" },
    ]) {
      expect((await api("PUT", "/settings/limits", admin.token, bad)).status).toBe(400);
    }
    expect((await api("PUT", "/settings/limits", admin.token, value)).status).toBe(200);
    expect((await api("GET", "/settings/limits", member.token)).body).toEqual(value);
    expect(
      (
        await api("POST", "/requests", member.token, {
          path: "shop/prod",
          reason: "test",
          duration: 7201,
        })
      ).status,
    ).toBe(400);
    const rows = await env.DB.prepare(
      "SELECT entry FROM audit WHERE action = 'settings.update'",
    ).all<{ entry: string }>();
    expect(rows.results.some((row) => row.entry.includes("auditRetentionDays"))).toBe(true);
  });
});
