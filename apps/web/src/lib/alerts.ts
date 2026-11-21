// Alert settings (ADR 18). The webhook URL is typed once, sent once, and then only the masked form comes back.
// It is never logged, stored in the browser, or put in a URL.

import type { ChannelToggles, RuleName } from "./api.ts";
// Only the shape of the rule map matters here. The Worker checks it again on save.

/** Lowercase https URL, as the Worker requires. Returns false for anything else. */
export function validWebhook(raw: string): boolean {
  const v = raw.trim();
  if (v === "" || v.length > 2048) return false;
  try {
    return new URL(v).protocol === "https:";
  } catch {
    return false;
  }
}

/** One channel of one rule switched on or off. Returns a new map; the old one is not changed. */
export function withChannel(
  rules: Record<RuleName, ChannelToggles>,
  rule: RuleName,
  channel: keyof ChannelToggles,
  on: boolean,
): Record<RuleName, ChannelToggles> {
  return { ...rules, [rule]: { ...rules[rule], [channel]: on } };
}
