import { describe, expect, test } from "bun:test";
import { type AppView, formatAppDetail, formatAppLine, parseDuration } from "./app.ts";

const base: AppView = {
  id: "i1",
  name: "agent-billing",
  status: "active",
  createdAt: 1,
  owner: "admin@example.com",
  roleId: "r1",
  tokenTtl: 3600,
  maxUses: null,
  uses: 0,
  cidr: null,
  expiresAt: null,
  firstLoginAt: null,
  lastLoginAt: null,
  lastIp: null,
  waiting: true,
};

describe("ADR 15 CLI: durations", () => {
  test("parses seconds, minutes, hours and days", () => {
    expect(parseDuration("90")).toBe(90);
    expect(parseDuration("30m")).toBe(1800);
    expect(parseDuration("1h")).toBe(3600);
    expect(parseDuration("7d")).toBe(604800);
  });

  test("rejects anything else", () => {
    expect(parseDuration("")).toBeNull();
    expect(parseDuration("1.5h")).toBeNull();
    expect(parseDuration("1w")).toBeNull();
    expect(parseDuration("-1h")).toBeNull();
  });
});

describe("ADR 15 CLI: list and show", () => {
  test("shows waiting apps as waiting for first sign-in", () => {
    expect(formatAppLine(base)).toContain("waiting for first sign-in");
  });

  test("shows the last sign-in with its IP once the app has signed in", () => {
    const line = formatAppLine({
      ...base,
      waiting: false,
      lastLoginAt: 1_700_000_000,
      lastIp: "203.0.113.7",
    });
    expect(line).toContain("last seen 2023-11-14T22:13:20.000Z from 203.0.113.7");
  });

  test("show lists limits, networks and recent activity", () => {
    const text = formatAppDetail({
      ...base,
      maxUses: 5,
      uses: 2,
      cidr: ["203.0.113.0/24", "2001:db8::/32"],
      activity: [
        {
          at: 1_700_000_000,
          action: "login.denied",
          result: "denied",
          ip: null,
          note: "bad secret",
        },
      ],
    }).join("\n");
    expect(text).toContain("Uses:             2 of 5");
    expect(text).toContain("Networks:         203.0.113.0/24, 2001:db8::/32");
    expect(text).toContain("login.denied  denied (bad secret)");
  });
});
