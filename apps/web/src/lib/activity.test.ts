import { describe, expect, it } from "vitest";
import {
  ACTION_NAMES,
  auditQuery,
  chainState,
  exportQuery,
  formatCount,
  meterState,
  NO_FILTERS,
  PAGE_SIZE,
  validPathFilter,
} from "./activity.ts";

const NOW = 1_800_000_000;

describe("audit query building", () => {
  it("sends nothing for empty filters except the time window and the page size", () => {
    expect(auditQuery(NO_FILTERS, NOW)).toEqual({ from: NOW - 86400, limit: PAGE_SIZE });
  });

  it("trims text, drops empty ones, and maps the result and range", () => {
    const q = auditQuery(
      {
        who: "  alice@myorg.com ",
        action: "secret.read",
        path: " backend/* ",
        result: "denied",
        kind: "app",
        range: "7d",
      },
      NOW,
    );
    expect(q).toEqual({
      who: "alice@myorg.com",
      action: "secret.read",
      path: "backend/*",
      result: "denied",
      kind: "app",
      from: NOW - 7 * 86400,
      limit: PAGE_SIZE,
    });
  });

  it("exports the same filters without paging", () => {
    expect(exportQuery({ ...NO_FILTERS, kind: "user", who: "bob" }, NOW)).toEqual({
      who: "bob",
      kind: "user",
      from: NOW - 86400,
    });
  });

  it("has no lower time bound for 'all kept'", () => {
    expect(auditQuery({ ...NO_FILTERS, range: "all" }, NOW).from).toBeUndefined();
  });

  it("passes the paging cursor as before", () => {
    expect(auditQuery(NO_FILTERS, NOW, 41).before).toBe(41);
    expect(auditQuery(NO_FILTERS, NOW).before).toBeUndefined();
  });

  it("accepts an exact path, a prefix with *, and rejects odd shapes", () => {
    expect(validPathFilter("")).toBe(true);
    expect(validPathFilter("myapp/prod")).toBe(true);
    expect(validPathFilter("backend/*")).toBe(true);
    expect(validPathFilter("back end/*")).toBe(false);
    expect(validPathFilter("a/**")).toBe(false);
    expect(validPathFilter("x".repeat(201))).toBe(false);
  });

  it("offers the action names the Worker writes, with no duplicates", () => {
    expect(new Set(ACTION_NAMES).size).toBe(ACTION_NAMES.length);
    expect(ACTION_NAMES).toContain("secret.read");
    expect(ACTION_NAMES).toContain("request.approve");
  });
});

describe("free-tier meter thresholds (ADR 19)", () => {
  it("is quiet below 80%", () => {
    const s = meterState(79_999, 100_000);
    expect(s.warn).toBe(false);
    expect(s.percent).toBe(79);
  });

  it("warns at exactly 80%", () => {
    const s = meterState(80_000, 100_000);
    expect(s.warn).toBe(true);
    expect(s.over).toBe(false);
    expect(s.percent).toBe(80);
  });

  it("is over at the whole quota and never above 100%", () => {
    const s = meterState(120_000, 100_000);
    expect(s.over).toBe(true);
    expect(s.percent).toBe(100);
  });

  it("reads zero for a missing or zero limit", () => {
    expect(meterState(5, 0)).toEqual({ percent: 0, warn: false, over: false });
  });
});

describe("chain status", () => {
  const base = {
    rows: 3,
    firstBad: null,
    firstBadSeq: null,
    head: "h",
    base: null,
    checkpoints: { stored: 0, verified: 0, pruned: 0, mismatched: [] },
  };

  it("is unchecked until a check has run", () => {
    expect(chainState(null)).toBe("unchecked");
  });

  it("is verified when the Worker says ok, and broken otherwise", () => {
    expect(chainState({ ...base, ok: true })).toBe("verified");
    expect(chainState({ ...base, ok: false, firstBad: 1, firstBadSeq: 9 })).toBe("broken");
  });

  it("is broken when a checkpoint no longer matches, even if the chain links are fine", () => {
    expect(chainState({ ...base, ok: false, firstBad: null, firstBadSeq: null })).toBe("broken");
  });
});

describe("number formatting", () => {
  it("groups thousands in each language", () => {
    expect(formatCount(62400, "en")).toBe("62,400");
    expect(formatCount(100000, "en")).toBe("100,000");
  });
});
