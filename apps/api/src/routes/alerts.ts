import { Hono } from "hono";
import {
  adminEmails,
  channelOn,
  loadConfig,
  maskWebhook,
  parseToggles,
  RULES,
  recentAlerts,
  saveConfig,
  sendTestAlert,
  type Toggles,
  validWebhookUrl,
} from "../alerts.ts";
import { audit } from "../audit.ts";
import { requireAdmin } from "../auth.ts";
import type { AppEnv, Env } from "../types.ts";

// ADR 18: alert settings. Admin only. The webhook URL is stored whole for sending, but only ever returned masked.
export const alerts = new Hono<AppEnv>();
alerts.use("/alerts", requireAdmin);
alerts.use("/alerts/*", requireAdmin);

async function settingsView(env: Env) {
  const cfg = await loadConfig(env.DB);
  return {
    webhook: cfg.webhookUrl ? maskWebhook(cfg.webhookUrl) : null,
    email: {
      available: Boolean(env.SEND_EMAIL && env.ALERT_EMAIL_FROM),
      recipients: await adminEmails(env.DB),
    },
    rules: rulesView(cfg.toggles),
  };
}

const rulesView = (toggles: Toggles) =>
  Object.fromEntries(
    RULES.map((r) => [
      r,
      { webhook: channelOn(toggles, r, "webhook"), email: channelOn(toggles, r, "email") },
    ]),
  );

alerts.get("/alerts", async (c) => c.json(await settingsView(c.env)));

alerts.put("/alerts", async (c) => {
  const b = await c.req.json<{ webhook?: unknown; rules?: unknown }>().catch(() => null);
  if (!b || typeof b !== "object") return c.json({ error: "bad request" }, 400);

  const patch: { webhookUrl?: string | null; toggles?: Toggles } = {};
  const changed: string[] = [];
  if (b.webhook !== undefined) {
    if (b.webhook === null || b.webhook === "") patch.webhookUrl = null;
    else if (typeof b.webhook === "string" && validWebhookUrl(b.webhook))
      patch.webhookUrl = b.webhook;
    else return c.json({ error: "webhook must be an https URL" }, 400);
    changed.push("webhook");
  }
  if (b.rules !== undefined) {
    const toggles = parseToggles(b.rules);
    if (!toggles) return c.json({ error: "rules must map known rules to channel booleans" }, 400);
    patch.toggles = toggles;
    changed.push("rules");
  }
  if (changed.length === 0) return c.json({ error: "bad request" }, 400);

  await saveConfig(c.env.DB, patch);
  // The audit note names the fields that changed, never their values.
  await audit(c.env.DB, {
    who: c.get("who").name,
    actor: c.get("who"),
    action: "alerts.update",
    note: changed.join(","),
    result: "ok",
  });
  return c.json(await settingsView(c.env));
});

// ADR 24: the Alerts screen's "Recent alerts" list and its "Send test" button.
alerts.get("/alerts/recent", async (c) => c.json(await recentAlerts(c.env.DB)));

alerts.post("/alerts/test", async (c) => {
  const who = c.get("who");
  const result = await sendTestAlert(c.env, who.name);
  await audit(c.env.DB, {
    who: who.name,
    actor: who,
    action: "alerts.test",
    note: `webhook ${result.webhook}, email ${result.email}`,
    result: "ok",
  });
  return c.json(result);
});
