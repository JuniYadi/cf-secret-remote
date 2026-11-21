import { describe, expect, it } from "vitest";
import { ipInRanges, normalizeAllowlist } from "./cidr.ts";

describe("ADR 15 allowlist: IPv4", () => {
  it("matches exact addresses and ranges", () => {
    expect(ipInRanges("203.0.113.7", ["203.0.113.7"])).toBe(true);
    expect(ipInRanges("203.0.113.8", ["203.0.113.7"])).toBe(false);
    expect(ipInRanges("203.0.113.200", ["203.0.113.0/24"])).toBe(true);
    expect(ipInRanges("203.0.114.1", ["203.0.113.0/24"])).toBe(false);
    expect(ipInRanges("10.20.30.40", ["10.0.0.0/8"])).toBe(true);
    expect(ipInRanges("11.0.0.1", ["10.0.0.0/8"])).toBe(false);
  });

  it("handles the edge prefixes", () => {
    expect(ipInRanges("1.2.3.4", ["0.0.0.0/0"])).toBe(true);
    expect(ipInRanges("1.2.3.4", ["1.2.3.5/32"])).toBe(false);
    expect(ipInRanges("1.2.3.5", ["1.2.3.5/32"])).toBe(true);
  });

  it("ignores the host bits of the range", () => {
    expect(ipInRanges("192.168.1.9", ["192.168.1.77/24"])).toBe(true);
  });
});

describe("ADR 15 allowlist: IPv6", () => {
  it("matches compressed and full forms", () => {
    expect(ipInRanges("2001:db8::1", ["2001:db8::/32"])).toBe(true);
    expect(ipInRanges("2001:0db8:0000:0000:0000:0000:0000:0001", ["2001:db8::1"])).toBe(true);
    expect(ipInRanges("2001:db9::1", ["2001:db8::/32"])).toBe(false);
    expect(ipInRanges("::1", ["::1"])).toBe(true);
    expect(ipInRanges("::2", ["::1"])).toBe(false);
  });

  it("accepts an embedded IPv4 tail", () => {
    expect(ipInRanges("::ffff:203.0.113.5", ["::ffff:203.0.113.0/120"])).toBe(true);
    expect(ipInRanges("::ffff:203.0.113.5", ["203.0.113.0/24"])).toBe(false);
  });

  it("never matches an IPv4 range with an IPv6 client or the reverse", () => {
    expect(ipInRanges("2001:db8::1", ["0.0.0.0/0"])).toBe(false);
    expect(ipInRanges("203.0.113.5", ["::/0"])).toBe(false);
  });
});

describe("ADR 15 allowlist: default deny", () => {
  it("denies with no ip, an empty list, or a malformed ip", () => {
    expect(ipInRanges(null, ["0.0.0.0/0"])).toBe(false);
    expect(ipInRanges(undefined, ["0.0.0.0/0"])).toBe(false);
    expect(ipInRanges("", ["0.0.0.0/0"])).toBe(false);
    expect(ipInRanges("203.0.113.5", [])).toBe(false);
    expect(ipInRanges("not-an-ip", ["0.0.0.0/0"])).toBe(false);
    expect(ipInRanges("1.2.3", ["1.2.3.0/24"])).toBe(false);
  });
});

describe("ADR 15 allowlist: validation", () => {
  it("accepts a mixed list and normalizes spacing", () => {
    expect(normalizeAllowlist("203.0.113.0/24, 2001:db8::/32 ,198.51.100.4")).toBe(
      "203.0.113.0/24,2001:db8::/32,198.51.100.4",
    );
  });

  it("rejects bad entries", () => {
    for (const bad of [
      "",
      "203.0.113.0/33",
      "2001:db8::/129",
      "203.0.113.0/",
      "203.0.113.0/24/8",
      "256.0.0.1",
      "010.0.0.1",
      "2001:db8:::1",
      "1::2::3",
      "1:2:3:4:5:6:7:8:9",
      "1:2:3:4:5:6:7::8:9",
      "gggg::1",
      "203.0.113.0,,198.51.100.1",
      "203.0.113.0, ",
      "::1.2.3.4.5",
    ]) {
      expect(normalizeAllowlist(bad), bad).toBeNull();
    }
  });
});
