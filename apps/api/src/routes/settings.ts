import { Hono } from "hono";
import { audit } from "../audit.ts";
import { requireAdmin } from "../auth.ts";
import { writeLimits } from "../repository/settings.ts";
import { type Limits, loadLimits, validLimits } from "../settings.ts";
import type { AppEnv } from "../types.ts";

export const settings = new Hono<AppEnv>();
settings.get("/settings/limits", async (c) => c.json(await loadLimits(c.env)));
settings.put("/settings/limits", requireAdmin, async (c) => {
  const body = await c.req.json<Limits>().catch(() => null);
  if (!body || !validLimits(body)) return c.json({ error: "invalid limits" }, 400);
  const value: Limits = {
    maxRequestDuration: body.maxRequestDuration,
    defaultApprovalDuration: body.defaultApprovalDuration,
    auditRetentionDays: body.auditRetentionDays,
  };
  await writeLimits(c.env.DB, JSON.stringify(value));
  const who = c.get("who");
  await audit(c.env.DB, {
    who: who.name,
    actor: who,
    action: "settings.update",
    note: JSON.stringify(value),
    result: "ok",
  });
  return c.json(value);
});
