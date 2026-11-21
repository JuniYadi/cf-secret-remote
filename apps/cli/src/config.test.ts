import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ensureTrusted,
  isTrusted,
  loadSession,
  loadUserConfig,
  mergeSecrets,
  normalizeHost,
  projectFile,
  resolveHost,
  runPaths,
  saveProfile,
  saveSession,
  useProfile,
} from "./config.ts";

let root: string;
let repo: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "cfs-config-"));
  process.env.CFS_CONFIG_DIR = join(root, "cfg");
  repo = join(root, "repo");
  mkdirSync(repo, { recursive: true });
  useProfile(undefined);
});

afterEach(() => {
  useProfile(undefined);
  delete process.env.CFS_CONFIG_DIR;
  rmSync(root, { recursive: true, force: true });
});

const writeProject = (data: unknown, dir = repo) =>
  writeFileSync(join(dir, ".cfs.json"), JSON.stringify(data));

const noPrompt = async () => {
  throw new Error("the prompt must not run");
};

describe("https only (ADR 25)", () => {
  test("https addresses are accepted and reduced to their origin", () => {
    expect(normalizeHost("https://vault.example.com/")).toBe("https://vault.example.com");
  });

  test("http is accepted for localhost and 127.0.0.1 only", () => {
    expect(normalizeHost("http://localhost:8787")).toBe("http://localhost:8787");
    expect(normalizeHost("http://127.0.0.1:8787")).toBe("http://127.0.0.1:8787");
    expect(() => normalizeHost("http://vault.example.com")).toThrow(/must start with https/);
    expect(() => normalizeHost("http://localhost.evil.example")).toThrow(/must start with https/);
  });

  test("a non-https host in .cfs.json, CFS_HOST or a flag is refused", () => {
    writeProject({ host: "http://vault.example.com" });
    expect(() => resolveHost(undefined, { cwd: repo, env: {} })).toThrow(/https/);
    expect(() =>
      resolveHost(undefined, { cwd: root, env: { CFS_HOST: "http://x.example" } }),
    ).toThrow(/https/);
    expect(() => resolveHost("http://x.example", { cwd: root, env: {} })).toThrow(/https/);
  });

  test("paths and credentials are refused in a host", () => {
    expect(() => normalizeHost("https://x.example.com/api")).toThrow(/without a path/);
    expect(() => normalizeHost("https://user:pw@x.example.com")).toThrow(/username/);
    expect(() => normalizeHost("vault")).toThrow(/not a URL/);
  });
});

describe("host precedence: flag > CFS_HOST > .cfs.json > profile (ADR 13, 25)", () => {
  const profile = "https://profile.example.com";
  const file = "https://project.example.com";
  const env = "https://env.example.com";
  const flagHost = "https://flag.example.com";

  beforeEach(() => {
    saveProfile("work", profile);
    writeProject({ host: file, project: "myapp" });
  });

  test("the --host flag wins over everything", () => {
    expect(resolveHost(flagHost, { cwd: repo, env: { CFS_HOST: env } })).toEqual({
      host: flagHost,
      source: "flag",
    });
  });

  test("CFS_HOST wins over .cfs.json and the profile", () => {
    expect(resolveHost(undefined, { cwd: repo, env: { CFS_HOST: env } })).toEqual({
      host: env,
      source: "env",
    });
  });

  test(".cfs.json wins over the profile", () => {
    expect(resolveHost(undefined, { cwd: repo, env: {} })).toEqual({
      host: file,
      source: "project",
    });
  });

  test("the profile is used when nothing else is set", () => {
    rmSync(join(repo, ".cfs.json"));
    expect(resolveHost(undefined, { cwd: repo, env: {} })).toEqual({
      host: profile,
      source: "profile",
    });
  });

  test("--profile picks a named profile; an unknown name fails with a hint", () => {
    saveProfile("other", "https://other.example.com");
    rmSync(join(repo, ".cfs.json"));
    useProfile("other");
    expect(resolveHost(undefined, { cwd: repo, env: {} })?.host).toBe("https://other.example.com");
    useProfile("nope");
    expect(() => resolveHost(undefined, { cwd: repo, env: {} })).toThrow(/No profile "nope"/);
  });

  test("no source at all gives undefined", () => {
    rmSync(join(repo, ".cfs.json"));
    rmSync(join(root, "cfg", "config.json"));
    useProfile(undefined);
    expect(resolveHost(undefined, { cwd: repo, env: {} })).toBeUndefined();
  });

  test("a single host from an earlier version becomes profile default", () => {
    const dir = join(root, "cfg");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "config.json"), JSON.stringify({ host: "https://old.example.com" }));
    expect(loadUserConfig().profiles.default?.host).toBe("https://old.example.com");
    expect(isTrusted("https://old.example.com")).toBe(true);
  });
});

describe("trust prompt (ADR 25)", () => {
  const host = "https://project.example.com";

  test("flags and profiles never prompt", async () => {
    await ensureTrusted(
      { host, source: "flag" },
      { interactive: true, confirm: noPrompt, signIn: noPrompt },
    );
    saveProfile("work", host);
    await ensureTrusted(
      { host, source: "profile" },
      { interactive: true, confirm: noPrompt, signIn: noPrompt },
    );
  });

  test("without a terminal an untrusted host fails with a clear message and does not sign in", async () => {
    let signedIn = false;
    const err = await ensureTrusted(
      { host, source: "project" },
      {
        interactive: false,
        confirm: noPrompt,
        signIn: async () => {
          signedIn = true;
        },
      },
    ).catch((e: Error) => e);
    expect((err as Error).message).toContain(`cfs login --host ${host}`);
    expect((err as Error).message).toContain(".cfs.json");
    expect(signedIn).toBe(false);
  });

  test("a no answer changes nothing", async () => {
    let signedIn = false;
    await expect(
      ensureTrusted(
        { host, source: "env" },
        {
          interactive: true,
          confirm: async () => false,
          signIn: async () => {
            signedIn = true;
          },
        },
      ),
    ).rejects.toThrow(/Nothing was changed/);
    expect(signedIn).toBe(false);
    expect(isTrusted(host)).toBe(false);
  });

  test("a yes asks the exact question, signs in and saves the host as trusted", async () => {
    const asked: string[] = [];
    let signedIn = "";
    await ensureTrusted(
      { host, source: "project" },
      {
        interactive: true,
        confirm: async (q) => {
          asked.push(q);
          return true;
        },
        signIn: async (h) => {
          signedIn = h;
        },
      },
    );
    expect(asked[0]).toContain(`Sign in to ${host}? (y/N)`);
    expect(signedIn).toBe(host);
    expect(isTrusted(host)).toBe(true);
  });

  test("a trusted host is never asked about again", async () => {
    await ensureTrusted(
      { host, source: "env" },
      { interactive: true, confirm: async () => true, signIn: async () => {} },
    );
    await ensureTrusted(
      { host, source: "env" },
      { interactive: true, confirm: noPrompt, signIn: noPrompt },
    );
  });

  test("a failed sign-in does not trust the host", async () => {
    await expect(
      ensureTrusted(
        { host, source: "env" },
        {
          interactive: true,
          confirm: async () => true,
          signIn: async () => {
            throw new Error("The code expired.");
          },
        },
      ),
    ).rejects.toThrow("The code expired.");
    expect(isTrusted(host)).toBe(false);
  });
});

describe(".cfs.json envs (ADR 25)", () => {
  test("the minimal form maps to <project>/<env>, env defaults to dev", () => {
    const file = { project: "myapp" };
    expect(runPaths(file)).toEqual({ env: "dev", paths: ["myapp/dev"] });
    expect(runPaths(file, "staging")).toEqual({ env: "staging", paths: ["myapp/staging"] });
  });

  test("explicit envs list their secrets in order, and the file's default env is used", () => {
    const file = {
      default: "staging",
      envs: { dev: ["shared/common", "myapp/dev"], staging: ["shared/common", "myapp/staging"] },
    };
    expect(runPaths(file)).toEqual({ env: "staging", paths: ["shared/common", "myapp/staging"] });
  });

  test("an env that is not defined fails and lists the defined ones", () => {
    const file = { envs: { dev: ["myapp/dev"], prod: ["myapp/prod"] } };
    expect(() => runPaths(file, "qa")).toThrow(/No env "qa" in .cfs.json. Defined: dev, prod/);
  });

  test("later secrets override earlier ones", async () => {
    const data: Record<string, Record<string, string>> = {
      "shared/common": { A: "1", B: "common" },
      "myapp/dev": { B: "dev", C: "3" },
    };
    const merged = await mergeSecrets(
      ["shared/common", "myapp/dev"],
      async (p) => data[p] ?? {},
      "dev",
    );
    expect(merged).toEqual({ A: "1", B: "dev", C: "3" });
  });

  test("if one listed secret cannot be opened the command fails, names it and loads nothing", async () => {
    const read: string[] = [];
    const err = await mergeSecrets(
      ["shared/common", "myapp/prod", "myapp/after"],
      async (p) => {
        read.push(p);
        if (p === "myapp/prod") throw new Error('No secret at "myapp/prod".');
        return { A: "1" };
      },
      "prod",
    ).catch((e: Error) => e);
    expect((err as Error).message).toContain('"myapp/prod"');
    expect((err as Error).message).toContain('env "prod"');
    expect(read).toEqual(["shared/common", "myapp/prod"]);
  });

  test("an envs entry that is not a list of paths is refused with its name", () => {
    writeProject({ envs: { dev: "myapp/dev" } });
    expect(() => projectFile(repo)).toThrow(/envs\.dev must be a list/);
  });

  test("a .cfs.json that is not JSON is an error, not silently ignored", () => {
    writeFileSync(join(repo, ".cfs.json"), "{ not json");
    expect(() => projectFile(repo)).toThrow(/not valid JSON/);
  });

  test("the nearest .cfs.json is found in a parent folder", () => {
    const deep = join(repo, "src", "pkg");
    mkdirSync(deep, { recursive: true });
    writeProject({ project: "myapp" });
    expect(projectFile(deep).project).toBe("myapp");
  });
});

describe("session file and local state (ADR 12, 25)", () => {
  test("the session file is written with mode 0600 and holds no private key", () => {
    saveSession({ host: "https://x.example.com", token: "t", expiresAt: Date.now() / 1000 + 600 });
    const path = join(root, "cfg", "session.json");
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(loadSession()?.host).toBe("https://x.example.com");
  });

  test("an expired session is not loaded", () => {
    saveSession({ host: "https://x.example.com", token: "t", expiresAt: 1 });
    expect(loadSession()).toBeUndefined();
  });
});
