import { describe, expect, it } from "vitest";
import {
  checkInject,
  checkRule,
  checkUpstream,
  DEFAULT_INJECT,
  isProdPath,
  type RuleDraft,
  ruleInput,
} from "./agent-rules.ts";

const draft: RuleDraft = {
  alias: "billing",
  secretPath: "payments/dev",
  name: "STRIPE_KEY",
  upstream: "https://api.stripe.com/v1",
  inject: DEFAULT_INJECT,
  maxReadsPerHour: "60",
  requireReason: true,
  requireApproval: false,
};

describe("agent rule checks (ADR 17)", () => {
  it("passes a complete rule", () => {
    expect(checkRule(draft, false)).toEqual({});
  });

  it("makes the */prod default visible: a path ending in /prod is a prod path", () => {
    expect(isProdPath("payments/prod")).toBe(true);
    expect(isProdPath("backend/payments/prod")).toBe(true);
    expect(isProdPath("payments/prod-eu")).toBe(false);
    expect(isProdPath("payments/dev")).toBe(false);
  });

  it("requires https upstreams with no credentials, query or fragment", () => {
    expect(checkUpstream("https://api.stripe.com/v1/")).toBe("https://api.stripe.com/v1");
    expect(checkUpstream("http://api.stripe.com")).toBeNull();
    expect(checkUpstream("https://user:pw@api.stripe.com")).toBeNull();
    expect(checkUpstream("https://api.stripe.com?x=1")).toBeNull();
    expect(checkUpstream("https://api.stripe.com#frag")).toBeNull();
    expect(checkUpstream("https://")).toBeNull();
  });

  it("accepts header:Name:Template with {value} once, or query:name", () => {
    expect(checkInject("header:Authorization:Bearer {value}")).toBe(true);
    expect(checkInject("query:api_key")).toBe(true);
    expect(checkInject("header:Authorization:Bearer")).toBe(false);
    expect(checkInject("header:Authorization:{value}-{value}")).toBe(false);
    expect(checkInject("header:Bad Name:{value}")).toBe(false);
    expect(checkInject("query:bad name")).toBe(false);
  });

  it("refuses a bad alias, a wildcard path and a budget out of range", () => {
    expect(checkRule({ ...draft, alias: "Billing" }, false).alias).toBe(true);
    expect(checkRule({ ...draft, secretPath: "payments/*" }, false).secretPath).toBe(true);
    expect(checkRule({ ...draft, maxReadsPerHour: "0" }, false).maxReadsPerHour).toBe(true);
    expect(checkRule({ ...draft, maxReadsPerHour: "100001" }, false).maxReadsPerHour).toBe(true);
    expect(checkRule({ ...draft, maxReadsPerHour: "1.5" }, false).maxReadsPerHour).toBe(true);
  });

  it("does not check the alias when editing, because it cannot change", () => {
    expect(checkRule({ ...draft, alias: "Billing" }, true).alias).toBeUndefined();
  });

  it("builds the request body with trimmed text and numeric budget", () => {
    const body = ruleInput({ ...draft, alias: " billing ", maxReadsPerHour: " 120 " });
    expect(body.alias).toBe("billing");
    expect(body.maxReadsPerHour).toBe(120);
    expect(body.requireApproval).toBe(false);
  });
});
