import { describe, expect, it } from "vitest";
import { validWebhook, withChannel } from "./alerts.ts";
import type { ChannelToggles, RuleName } from "./api.ts";

const off: ChannelToggles = { webhook: false, email: false };
const rules = {
  blocked: { webhook: true, email: false },
  agent_prod_read: off,
} as Record<RuleName, ChannelToggles>;

describe("alert webhook (ADR 18)", () => {
  it("accepts an https URL only", () => {
    expect(validWebhook("https://hooks.slack.com/services/T0/B0/xyz")).toBe(true);
    expect(validWebhook("  https://example.com/hook  ")).toBe(true);
    expect(validWebhook("http://example.com/hook")).toBe(false);
    expect(validWebhook("hooks.slack.com/x")).toBe(false);
    expect(validWebhook("")).toBe(false);
    expect(validWebhook(`https://example.com/${"a".repeat(2050)}`)).toBe(false);
  });
});

describe("per-rule channel toggles", () => {
  it("switches one channel of one rule and leaves the rest alone", () => {
    const next = withChannel(rules, "agent_prod_read", "email", true);
    expect(next.agent_prod_read).toEqual({ webhook: false, email: true });
    expect(next.blocked).toEqual({ webhook: true, email: false });
  });

  it("does not change the map it was given", () => {
    withChannel(rules, "blocked", "webhook", false);
    expect(rules.blocked.webhook).toBe(true);
  });
});
