import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  clearUnlock,
  DEFAULT_TTL,
  fileStore,
  loadUnlock,
  macKeychain,
  parseTtl,
  pickStore,
  type Runner,
  type RunResult,
  saveUnlock,
  secretTool,
  unlockAccount,
  withFallback,
} from "./keychain.ts";

const SECRET = "PRIVATE-KEY-MARKER-7f3a";
const HOST = "https://vault.example.com";
const ok = (stdout = ""): RunResult => ({ code: 0, stdout, stderr: "" });
const notFound: RunResult = {
  code: 44,
  stdout: "",
  stderr: "security: The specified item could not be found in the keychain.",
};

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cfs-keychain-"));
  process.env.CFS_CONFIG_DIR = dir;
});
afterEach(() => {
  delete process.env.CFS_CONFIG_DIR;
  rmSync(dir, { recursive: true, force: true });
});

/** A recording fake of macOS `security`, with an in-memory keychain. */
function fakeSecurity(opts: { keep?: boolean } = {}) {
  const items = new Map<string, string>();
  const calls: { argv: string[]; stdin?: string }[] = [];
  const run: Runner = async (argv, stdin) => {
    calls.push({ argv, stdin });
    const acct = (flagName: string) => argv[argv.indexOf(flagName) + 1] ?? "";
    if (argv[1] === "-i") {
      const line = stdin ?? "";
      const a = /-a (\S+)/.exec(line)?.[1] ?? "";
      const hex = /-X (\S+)/.exec(line)?.[1] ?? "";
      if (opts.keep !== false) items.set(a, Buffer.from(hex, "hex").toString("utf8"));
      return ok();
    }
    if (argv[1] === "find-generic-password") {
      const v = items.get(acct("-a"));
      return v === undefined ? notFound : ok(`${v}\n`);
    }
    if (argv[1] === "delete-generic-password") {
      items.delete(acct("-a"));
      return ok();
    }
    return { code: 2, stdout: "", stderr: "unknown" };
  };
  return { run, calls, items };
}

/** A recording fake of `secret-tool` (store reads the secret from stdin). */
function fakeSecretTool() {
  const items = new Map<string, string>();
  const calls: { argv: string[]; stdin?: string }[] = [];
  const run: Runner = async (argv, stdin) => {
    calls.push({ argv, stdin });
    const account = argv[argv.indexOf("account") + 1] ?? "";
    if (argv[1] === "store") {
      items.set(account, stdin ?? "");
      return ok();
    }
    if (argv[1] === "lookup") {
      const v = items.get(account);
      return v === undefined ? { code: 1, stdout: "", stderr: "" } : ok(v);
    }
    if (argv[1] === "clear") {
      items.delete(account);
      return ok();
    }
    return { code: 2, stdout: "", stderr: "unknown" };
  };
  return { run, calls, items };
}

describe("secrets never go on a command line (ADR 25)", () => {
  test("macOS: the value goes through stdin only, hex encoded", async () => {
    const sec = fakeSecurity();
    const store = macKeychain(sec.run);
    await store.set("acct", SECRET);
    for (const c of sec.calls) {
      expect(c.argv.join(" ")).not.toContain(SECRET);
      expect(c.argv.join(" ")).not.toContain(Buffer.from(SECRET).toString("hex"));
    }
    const setCall = sec.calls.find((c) => c.argv[1] === "-i");
    expect(setCall?.stdin).toContain(Buffer.from(SECRET).toString("hex"));
    expect(await store.get("acct")).toBe(SECRET);
  });

  test("Linux: secret-tool reads the value from stdin", async () => {
    const tool = fakeSecretTool();
    const store = secretTool(tool.run);
    await store.set("acct", SECRET);
    for (const c of tool.calls) expect(c.argv.join(" ")).not.toContain(SECRET);
    expect(tool.calls.find((c) => c.argv[1] === "store")?.stdin).toBe(SECRET);
    expect(await store.get("acct")).toBe(SECRET);
    await store.delete("acct");
    expect(await store.get("acct")).toBeUndefined();
  });

  test("a keychain that does not keep the value is an error, so the fallback is used", async () => {
    const sec = fakeSecurity({ keep: false });
    await expect(macKeychain(sec.run).set("acct", SECRET)).rejects.toThrow(/did not keep/);
  });
});

describe("keychain fallback to the 0600 file (ADR 25)", () => {
  test("when the keychain fails, the value is kept in the file and read back", async () => {
    const broken: Runner = async () => {
      throw new Error("no Secret Service on this machine");
    };
    const path = join(dir, "unlock.json");
    const store = withFallback(
      secretTool(broken),
      fileStore(() => path),
    );
    await store.set("acct", SECRET);
    expect(await store.get("acct")).toBe(SECRET);
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  test("a working keychain keeps a single copy: no file is written", async () => {
    const tool = fakeSecretTool();
    const path = join(dir, "unlock.json");
    const store = withFallback(
      secretTool(tool.run),
      fileStore(() => path),
    );
    await store.set("acct", SECRET);
    expect(existsSync(path)).toBe(false);
    expect(await store.get("acct")).toBe(SECRET);
  });

  test("pickStore uses the file when no keychain tool exists", () => {
    expect(pickStore({ platform: "linux", which: () => null }).kind).toBe("file");
    expect(pickStore({ platform: "win32", which: () => "x" }).kind).toBe("file");
    expect(pickStore({ platform: "darwin", which: () => "/usr/bin/security" }).kind).toBe(
      "macos-keychain",
    );
    expect(pickStore({ platform: "linux", which: () => "/usr/bin/secret-tool" }).kind).toBe(
      "secret-tool",
    );
  });

  test("CFS_UNLOCK_STORE=file forces the file even where a keychain exists (ADR 26)", () => {
    const before = process.env.CFS_UNLOCK_STORE;
    process.env.CFS_UNLOCK_STORE = "file";
    try {
      expect(pickStore({ platform: "darwin", which: () => "/usr/bin/security" }).kind).toBe("file");
    } finally {
      if (before === undefined) delete process.env.CFS_UNLOCK_STORE;
      else process.env.CFS_UNLOCK_STORE = before;
    }
  });
});

describe("unlock TTL (ADR 25, --ttl default 24 h)", () => {
  test("the default is 24 hours", () => {
    expect(DEFAULT_TTL).toBe("24h");
    expect(parseTtl(DEFAULT_TTL)).toBe(86400);
  });

  test("durations parse to seconds", () => {
    expect(parseTtl("90s")).toBe(90);
    expect(parseTtl("30m")).toBe(1800);
    expect(parseTtl("2d")).toBe(172800);
    expect(parseTtl("45")).toBe(45);
  });

  test("bad durations are refused", () => {
    for (const bad of ["1x", "0m", "", "-5m", "soon"]) expect(() => parseTtl(bad)).toThrow();
  });

  test("the unlocked key expires after its TTL and is deleted", async () => {
    const store = fileStore(() => join(dir, "unlock.json"));
    const t0 = 1_000_000;
    await saveUnlock(store, HOST, SECRET, 60, t0);
    expect(await loadUnlock(store, HOST, t0 + 59_000)).toBe(SECRET);
    expect(await loadUnlock(store, HOST, t0 + 60_000)).toBeUndefined();
    expect(await store.get(unlockAccount(HOST))).toBeUndefined();
  });

  test("each host has its own unlocked key, and lock removes it", async () => {
    const store = fileStore(() => join(dir, "unlock.json"));
    await saveUnlock(store, HOST, SECRET, 3600);
    expect(unlockAccount(HOST)).not.toBe(unlockAccount("https://other.example.com"));
    expect(await loadUnlock(store, "https://other.example.com")).toBeUndefined();
    await clearUnlock(store, HOST);
    expect(await loadUnlock(store, HOST)).toBeUndefined();
  });
});
