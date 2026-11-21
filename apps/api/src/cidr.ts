// ADR 15: network allowlist for AppRole logins. Accepts IPv4 and IPv6 addresses and CIDR ranges.
// Pure functions, no I/O. An IPv4-mapped IPv6 address (::ffff:a.b.c.d) is not matched by IPv4 entries.

const V4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const HEX16 = /^[0-9a-fA-F]{1,4}$/;

interface Addr {
  version: 4 | 6;
  value: bigint;
}

function parseV4(s: string): bigint | null {
  const m = V4.exec(s);
  if (!m) return null;
  let v = 0n;
  for (const part of m.slice(1)) {
    // Leading zeros are rejected: "010" is ambiguous (octal in some parsers).
    if ((part.length > 1 && part.startsWith("0")) || Number(part) > 255) return null;
    v = (v << 8n) | BigInt(Number(part));
  }
  return v;
}

function parseV6(s: string): bigint | null {
  const halves = s.split("::");
  if (halves.length > 2) return null;

  // Parses one side of "::". An embedded IPv4 tail is allowed only at the very end of the address.
  const groups = (part: string, allowV4Tail: boolean): number[] | null => {
    if (part === "") return [];
    const segs = part.split(":");
    const out: number[] = [];
    for (let i = 0; i < segs.length; i++) {
      const seg = segs[i] as string;
      if (seg.includes(".")) {
        if (!allowV4Tail || i !== segs.length - 1) return null;
        const v4 = parseV4(seg);
        if (v4 === null) return null;
        out.push(Number(v4 >> 16n), Number(v4 & 0xffffn));
      } else {
        if (!HEX16.test(seg)) return null;
        out.push(Number.parseInt(seg, 16));
      }
    }
    return out;
  };

  let all: number[] | null;
  if (halves.length === 1) {
    all = groups(halves[0] as string, true);
    if (all?.length !== 8) return null;
  } else {
    const left = groups(halves[0] as string, false);
    const right = groups(halves[1] as string, true);
    if (!left || !right) return null;
    // "::" stands for one or more zero groups (RFC 4291).
    const fill = 8 - left.length - right.length;
    if (fill < 1) return null;
    all = [...left, ...new Array<number>(fill).fill(0), ...right];
  }
  return all.reduce((acc, g) => (acc << 16n) | BigInt(g), 0n);
}

function parseAddr(s: string): Addr | null {
  if (s.includes(":")) {
    const value = parseV6(s);
    return value === null ? null : { version: 6, value };
  }
  const value = parseV4(s);
  return value === null ? null : { version: 4, value };
}

interface Range {
  version: 4 | 6;
  network: bigint;
  mask: bigint;
}

function parseRange(s: string): Range | null {
  const [addr, prefix, ...rest] = s.split("/");
  if (!addr || rest.length > 0) return null;
  const a = parseAddr(addr);
  if (!a) return null;
  const bits = a.version === 4 ? 32 : 128;
  let len = bits;
  if (prefix !== undefined) {
    if (!/^\d{1,3}$/.test(prefix)) return null;
    len = Number(prefix);
    if (len > bits) return null;
  }
  const ones = (1n << BigInt(len)) - 1n;
  const mask = ones << BigInt(bits - len);
  return { version: a.version, network: a.value & mask, mask };
}

/** True if `ip` is inside any of the ranges. A missing or malformed ip never matches (default deny). */
export function ipInRanges(ip: string | null | undefined, ranges: string[]): boolean {
  if (!ip) return false;
  const a = parseAddr(ip.trim());
  if (!a) return false;
  return ranges.some((r) => {
    const range = parseRange(r);
    return (
      range !== null && range.version === a.version && (a.value & range.mask) === range.network
    );
  });
}

/**
 * Validates a comma-separated allowlist such as "203.0.113.0/24, 2001:db8::1".
 * Returns the trimmed entries joined with commas, or null if any entry is invalid or the list is empty.
 */
export function normalizeAllowlist(list: string): string | null {
  const entries = list.split(",").map((e) => e.trim());
  if (entries.some((e) => e === "" || parseRange(e) === null)) return null;
  return entries.join(",");
}
