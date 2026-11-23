import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test";
import * as childProcess from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { type BundleManifest, PROTOCOL_VERSION, parseManifest } from "@cfs/core";
import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { CliError } from "../config.ts";
import type { Fetch } from "../server.ts";
import {
  applyMigrations,
  assetHash,
  type Bundle,
  type Cf,
  checkDomain,
  checkEmail,
  checkWorkerName,
  contentType,
  type DeployRun,
  deploy,
  deployPlan,
  ensureAccess,
  makeCf,
  redact,
  runDeploy,
  setProjectHost,
  verifyBundle,
} from "./deploy.ts";

const TOKEN = "cfut_SECRET_token_value_12345";
const ACC = "a".repeat(32);
const sha = (s: string | Uint8Array) =>
  createHash("sha256")
    .update(typeof s === "string" ? new TextEncoder().encode(s) : s)
    .digest("hex");
const enc = (s: string) => new TextEncoder().encode(s);

let dir: string;
let projectPath: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cfs-deploy-run-"));
  projectPath = join(dir, ".cfs.json");
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

interface BundleOpts {
  migrations?: Record<string, string>;
  assets?: Record<string, string>;
  protocol?: number;
}

/** Builds an in-memory bundle the way scripts/bundle-worker.ts lays it out. */
function makeBundle(o: BundleOpts = {}): Bundle {
  const migrations = o.migrations ?? {
    "0001_init.sql": "CREATE TABLE a_0001 (x);",
    "0002_more.sql": "CREATE TABLE a_0002 (y);",
  };
  const assets = o.assets ?? { "index.html": "<!doctype html><title>cfs</title>" };
  const texts: Record<string, string> = {
    "worker/index.js": "export default { fetch() { return new Response('ok'); } };",
    ...Object.fromEntries(Object.entries(assets).map(([k, v]) => [`assets/${k}`, v])),
    ...Object.fromEntries(Object.entries(migrations).map(([k, v]) => [`migrations/${k}`, v])),
  };
  const files = new Map<string, Uint8Array>(Object.entries(texts).map(([k, v]) => [k, enc(v)]));
  const manifest: BundleManifest = parseManifest({
    format: 1,
    version: "0.2.0",
    protocol: o.protocol ?? PROTOCOL_VERSION,
    main: "worker/index.js",
    compatibility_date: "2026-08-01",
    crons: ["5 0 * * *"],
    assets: { not_found_handling: "single-page-application", run_worker_first: ["/api/*"] },
    vars: { AUDIT_RETENTION_DAYS: "365" },
    migrations: Object.keys(migrations).sort(),
    files: Object.fromEntries([...files].map(([k, v]) => [k, sha(v)])),
  });
  files.set("manifest.json", enc(JSON.stringify(manifest)));
  return { manifest, files };
}

/**
 * A stateful stand-in for the Cloudflare API, behind the injectable `cf` function. It records
 * every call so tests can check order and count. It never touches the network.
 */
function fakeCf() {
  const calls: string[] = [];
  const sqls: string[] = [];
  const s = {
    dbs: [] as { uuid: string; name: string }[],
    migrations: new Map<string, string>(),
    apps: [] as { id: string; domain: string; aud: string; policies: unknown[] }[],
    seenAssets: new Set<string>(),
    metadata: undefined as undefined | Record<string, unknown>,
    code: "",
    schedules: undefined as unknown,
    changeset: undefined as unknown,
    workersDev: false,
    nextId: 1,
  };
  const cf: Cf = async (method, path, body) => {
    const [p = "", q = ""] = path.split("?");
    calls.push(`${method} ${p}`);
    const key = `${method} ${p}`;
    const b = body as Record<string, unknown> | FormData | undefined;
    const id = () => `id${s.nextId++}`;

    if (key === "GET /accounts") return [{ id: ACC, name: "Test" }];
    if (key === `GET /accounts/${ACC}/d1/database`) return s.dbs;
    if (key === `POST /accounts/${ACC}/d1/database`) {
      const db = { uuid: id(), name: (b as { name: string }).name };
      s.dbs.push(db);
      return db;
    }
    if (
      method === "POST" &&
      p.startsWith(`/accounts/${ACC}/d1/database/`) &&
      p.endsWith("/query")
    ) {
      const sql = (b as { sql: string }).sql;
      sqls.push(sql);
      if (sql.startsWith("SELECT name")) {
        return [{ results: [...s.migrations].map(([name, sha256]) => ({ name, sha256 })) }];
      }
      const rec = /VALUES \('([^']+)', '([^']+)'/.exec(sql);
      if (rec) s.migrations.set(rec[1] as string, rec[2] as string);
      return [{ results: [], success: true }];
    }
    if (key === `GET /accounts/${ACC}/access/organizations`)
      return { auth_domain: "team.cloudflareaccess.com" };
    if (key === `GET /accounts/${ACC}/access/apps`) return s.apps;
    if (key === `POST /accounts/${ACC}/access/apps`) {
      const app = { ...(b as object), id: id(), aud: `aud-${s.nextId}` } as (typeof s.apps)[number];
      s.apps.push(app);
      return app;
    }
    if (method === "PUT" && p.startsWith(`/accounts/${ACC}/access/apps/`)) {
      const app = s.apps.find((x) => x.id === p.split("/").pop());
      if (!app) throw new CliError("no such app");
      Object.assign(app, b);
      return app;
    }
    if (key === `POST /accounts/${ACC}/workers/scripts/cfs/assets-upload-session`) {
      const manifest = (b as { manifest: Record<string, { hash: string }> }).manifest;
      const hashes = Object.values(manifest).map((m) => m.hash);
      const missing = hashes.filter((h) => !s.seenAssets.has(h));
      return { jwt: "session-jwt", buckets: missing.length ? [missing] : [] };
    }
    if (key === `POST /accounts/${ACC}/workers/assets/upload`) {
      const form = b as FormData;
      for (const [k] of form.entries()) s.seenAssets.add(k);
      return { jwt: "completion-jwt" };
    }
    if (method === "PUT" && p === `/accounts/${ACC}/workers/scripts/cfs`) {
      const form = b as FormData;
      s.metadata = JSON.parse(await (form.get("metadata") as Blob).text());
      s.code = await (form.get("index.js") as Blob).text();
      return { id: "cfs" };
    }
    if (method === "PUT" && p.endsWith("/schedules")) {
      s.schedules = b;
      return [];
    }
    if (key === `GET /accounts/${ACC}/workers/subdomain`) return { subdomain: "acme" };
    if (method === "POST" && p.endsWith("/subdomain")) {
      s.workersDev = (b as { enabled: boolean }).enabled;
      return {};
    }
    if (p === "/zones") {
      const name = new URLSearchParams(q).get("name");
      return name === "example.com" ? [{ id: "zone1" }] : [];
    }
    if (method === "POST" && p.endsWith("/domains/changeset")) {
      s.changeset = b;
      return {};
    }
    throw new CliError(`fake cloudflare: no route for ${key}`);
  };
  return { cf, calls, sqls, s };
}

function runOpts(over: Partial<DeployRun> = {}, bundle?: Bundle): DeployRun {
  return {
    name: "cfs",
    admin: "admin@example.com",
    dryRun: false,
    bundle: bundle ?? makeBundle(),
    bundleSource: "test bundle",
    projectPath,
    ...over,
  };
}

function deps(cf?: Cf) {
  const lines: string[] = [];
  return {
    lines,
    text: () => lines.join("\n"),
    d: {
      cf,
      interactive: false,
      ask: async () => {
        throw new Error("no prompt in tests");
      },
      log: (l: string) => lines.push(l),
    },
  };
}

describe("cfs deploy --dry-run (ADR 25)", () => {
  test("prints the plan and makes no calls, even with a client present", async () => {
    const f = fakeCf();
    const out = deps(f.cf);
    const host = await runDeploy(runOpts({ dryRun: true, domain: "vault.example.com" }), out.d);
    expect(host).toBeUndefined();
    expect(f.calls).toEqual([]);
    expect(out.text()).toContain('D1 database "cfs"');
    expect(out.text()).toContain("Access: protect https://vault.example.com");
    expect(out.text()).toContain("vault.example.com/api/v1/*");
    expect(out.text()).toContain("Dry run: no calls were made");
    expect(existsSync(projectPath)).toBe(false);
  });

  test("the plan works with no token and no bundle, and says where the bundle comes from", () => {
    const lines = deployPlan(
      runOpts({ dryRun: true, bundle: undefined, bundleSource: "latest release" }),
    );
    expect(lines.join("\n")).toContain("latest release");
    expect(lines.join("\n")).toContain("Access: skipped (no --domain)");
  });

  test("without --domain the plan says Access is skipped and the workers.dev route is enabled", () => {
    const text = deployPlan(runOpts({ dryRun: true })).join("\n");
    expect(text).toContain("Access: skipped");
    expect(text).toContain("workers.dev");
  });
});

describe("first deploy (ADR 25)", () => {
  test("creates the D1 database and applies every migration once, in order", async () => {
    const f = fakeCf();
    const out = deps(f.cf);
    await runDeploy(runOpts(), out.d);
    expect(f.s.dbs).toEqual([{ uuid: "id1", name: "cfs" }]);
    const applied = f.sqls.filter((s) => s.includes("CREATE TABLE a_"));
    expect(applied.map((s) => /a_(\d+)/.exec(s)?.[1])).toEqual(["0001", "0002"]);
    expect([...f.s.migrations.keys()]).toEqual(["0001_init.sql", "0002_more.sql"]);
  });

  test("the Worker upload binds DB and ASSETS, sets the admin email, and uses the assets token", async () => {
    const f = fakeCf();
    await runDeploy(runOpts(), deps(f.cf).d);
    const m = f.s.metadata as {
      main_module: string;
      bindings: { type: string; name: string; id?: string; text?: string }[];
      assets: { jwt: string; config: { run_worker_first: string[] } };
    };
    expect(m.main_module).toBe("index.js");
    expect(m.bindings).toContainEqual({ type: "d1", name: "DB", id: "id1" });
    expect(m.bindings).toContainEqual({ type: "assets", name: "ASSETS" });
    expect(m.bindings).toContainEqual({
      type: "plain_text",
      name: "BOOTSTRAP_ADMIN_EMAIL",
      text: "admin@example.com",
    });
    expect(m.bindings).toContainEqual({
      type: "plain_text",
      name: "AUDIT_RETENTION_DAYS",
      text: "365",
    });
    expect(m.assets.jwt).toBe("completion-jwt");
    expect(m.assets.config.run_worker_first).toEqual(["/api/*"]);
    expect(f.s.code).toContain("new Response");
  });

  test("cron schedules are set and the host is written to .cfs.json without losing other keys", async () => {
    writeFileSync(projectPath, JSON.stringify({ project: "myapp", envs: { dev: ["myapp/dev"] } }));
    const f = fakeCf();
    const host = await runDeploy(runOpts(), deps(f.cf).d);
    expect(f.s.schedules).toEqual([{ cron: "5 0 * * *" }]);
    expect(f.s.workersDev).toBe(true);
    expect(host).toBe("https://cfs.acme.workers.dev");
    expect(JSON.parse(readFileSync(projectPath, "utf8"))).toEqual({
      host: "https://cfs.acme.workers.dev",
      project: "myapp",
      envs: { dev: ["myapp/dev"] },
    });
  });

  test("the first-run steps mention the admin email and the login command", async () => {
    const f = fakeCf();
    const out = deps(f.cf);
    await runDeploy(runOpts({ domain: "vault.example.com" }), out.d);
    expect(out.text()).toContain("sign in as admin@example.com");
    expect(out.text()).toContain("cfs login --host https://vault.example.com");
  });

  test("a missing admin email is refused when there is no terminal to ask in", async () => {
    const f = fakeCf();
    await expect(runDeploy(runOpts({ admin: undefined }), deps(f.cf).d)).rejects.toThrow(/--admin/);
    expect(f.calls).toEqual([]);
  });
});

describe("--domain: Access application (ADR 25, ADR 4)", () => {
  test("UI app allows only the admin; /api/v1/* and the health check bypass Access", async () => {
    const f = fakeCf();
    await runDeploy(runOpts({ domain: "vault.example.com" }), deps(f.cf).d);
    const ui = f.s.apps.find((a) => a.domain === "vault.example.com");
    expect(ui?.policies).toEqual([
      {
        name: "cfs admin",
        decision: "allow",
        include: [{ email: { email: "admin@example.com" } }],
      },
    ]);
    const api = f.s.apps.find((a) => a.domain === "vault.example.com/api/v1/*");
    expect(api?.policies).toEqual([
      { name: "cfs bypass", decision: "bypass", include: [{ everyone: {} }] },
    ]);
    expect(f.s.apps.find((a) => a.domain === "vault.example.com/api/health")).toBeDefined();
  });

  test("the Worker gets the team domain and the UI app's audience for JWT checks", async () => {
    const f = fakeCf();
    await runDeploy(runOpts({ domain: "vault.example.com" }), deps(f.cf).d);
    const ui = f.s.apps.find((a) => a.domain === "vault.example.com");
    const bindings = (f.s.metadata as { bindings: { type: string; name: string; text?: string }[] })
      .bindings;
    expect(bindings).toContainEqual({
      type: "plain_text",
      name: "ACCESS_TEAM_DOMAIN",
      text: "team.cloudflareaccess.com",
    });
    expect(bindings).toContainEqual({ type: "plain_text", name: "ACCESS_AUD", text: ui?.aud });
  });

  test("the custom domain is attached in its zone and the host is written", async () => {
    writeFileSync(projectPath, "{}");
    const f = fakeCf();
    const host = await runDeploy(runOpts({ domain: "vault.example.com" }), deps(f.cf).d);
    expect(f.s.changeset).toEqual([
      { hostname: "vault.example.com", zone_id: "zone1", enabled: true, previews_enabled: false },
    ]);
    expect(host).toBe("https://vault.example.com");
    expect(JSON.parse(readFileSync(projectPath, "utf8")).host).toBe("https://vault.example.com");
  });

  test("a domain with no zone in the account is refused with a clear message", async () => {
    const f = fakeCf();
    await expect(runDeploy(runOpts({ domain: "other.test" }), deps(f.cf).d)).rejects.toThrow(
      /No zone for other.test/,
    );
    expect(existsSync(projectPath)).toBe(false);
  });

  test("ensureAccess on its own reuses an app that already exists instead of making a second one", async () => {
    const f = fakeCf();
    const info1 = await ensureAccess(f.cf, ACC, "vault.example.com", "admin@example.com");
    const info2 = await ensureAccess(f.cf, ACC, "vault.example.com", "admin@example.com");
    expect(f.s.apps.length).toBe(3);
    expect(info2.aud).toBe(info1.aud);
  });
});

describe("re-run is an upgrade (idempotent)", () => {
  test("a second run creates nothing new, applies no migration, and leaves .cfs.json the same", async () => {
    const f = fakeCf();
    const bundle = makeBundle();
    await runDeploy(runOpts({ domain: "vault.example.com", bundle }), deps(f.cf).d);
    const after1 = readFileSync(projectPath, "utf8");
    const sqls1 = f.sqls.length;
    const apps1 = f.s.apps.length;
    const dbs1 = f.s.dbs.length;

    const out = deps(f.cf);
    await runDeploy(runOpts({ domain: "vault.example.com", bundle }), out.d);

    expect(f.s.dbs.length).toBe(dbs1);
    expect(f.s.apps.length).toBe(apps1);
    const second = f.sqls.slice(sqls1);
    expect(second.some((s) => s.includes("CREATE TABLE a_"))).toBe(false);
    expect(
      second.every((s) => s.startsWith("CREATE TABLE IF NOT EXISTS") || s.startsWith("SELECT")),
    ).toBe(true);
    expect(out.text()).toContain("Migrations up to date");
    expect(readFileSync(projectPath, "utf8")).toBe(after1);
  });

  test("a later migration is applied after the recorded ones and nothing earlier runs again", async () => {
    const f = fakeCf();
    await runDeploy(
      runOpts({
        bundle: makeBundle({ migrations: { "0001_init.sql": "CREATE TABLE a_0001 (x);" } }),
      }),
      deps(f.cf).d,
    );
    const bundle2 = makeBundle();
    await runDeploy(runOpts({ bundle: bundle2 }), deps(f.cf).d);
    const ran = f.sqls
      .filter((s) => s.includes("CREATE TABLE a_"))
      .map((s) => /a_(\d+)/.exec(s)?.[1]);
    expect(ran).toEqual(["0001", "0002"]);
  });
});

describe("migrations are forward only and tracked (ADR 25)", () => {
  test("a migration whose file changed after it was applied is refused and nothing runs", async () => {
    const f = fakeCf();
    await runDeploy(runOpts(), deps(f.cf).d);
    const before = f.sqls.length;
    const edited = makeBundle({
      migrations: {
        "0001_init.sql": "CREATE TABLE a_0001 (changed);",
        "0002_more.sql": "CREATE TABLE a_0002 (y);",
      },
    });
    await expect(runDeploy(runOpts({ bundle: edited }), deps(f.cf).d)).rejects.toThrow(
      /0001_init.sql changed after it was applied/,
    );
    expect(f.sqls.slice(before).some((s) => s.includes("CREATE TABLE a_"))).toBe(false);
  });

  test("a database with a migration this bundle does not know is refused (no downgrade)", async () => {
    const f = fakeCf();
    f.s.migrations.set("0009_future.sql", "abc");
    await expect(runDeploy(runOpts(), deps(f.cf).d)).rejects.toThrow(/0009_future.sql/);
  });

  test("applied migrations are recorded in _cfs_migrations with the file hash", async () => {
    const f = fakeCf();
    const bundle = makeBundle();
    const applied = await applyMigrations(f.cf, ACC, "db1", bundle, () => {});
    expect(applied).toEqual(["0001_init.sql", "0002_more.sql"]);
    expect(f.s.migrations.get("0001_init.sql")).toBe(sha("CREATE TABLE a_0001 (x);"));
    expect(f.sqls.some((s) => s.includes("CREATE TABLE IF NOT EXISTS _cfs_migrations"))).toBe(true);
  });
});

describe("bundle verification before any call (ADR 25)", () => {
  test("a bundle with a tampered file is refused", async () => {
    const bundle = makeBundle();
    bundle.files.set("worker/index.js", enc("evil"));
    await expect(verifyBundle(bundle)).rejects.toThrow(/does not match its hash/);
  });

  test("a bundle with an unlisted file is refused", async () => {
    const bundle = makeBundle();
    bundle.files.set("assets/extra.js", enc("x"));
    await expect(verifyBundle(bundle)).rejects.toThrow(/unlisted file assets\/extra.js/);
  });

  test("a bundle for another protocol is refused and says which protocol it speaks", async () => {
    await expect(verifyBundle(makeBundle({ protocol: PROTOCOL_VERSION + 1 }))).rejects.toThrow(
      /speaks protocol 2/,
    );
  });
});

describe("the Cloudflare token (ADR 25 security rules)", () => {
  /** A fetch that always answers with an API error that echoes the token back. */
  function echoingFetch(calls: { url: string; init?: RequestInit }[]): Fetch {
    return async (url, init) => {
      calls.push({ url, init });
      return new Response(
        JSON.stringify({
          success: false,
          errors: [{ code: 10000, message: `bad token ${TOKEN}` }],
        }),
        { status: 403, headers: { "content-type": "application/json" } },
      );
    };
  }

  test("API errors are shown with status and message, and the token is redacted", async () => {
    const cf = makeCf(TOKEN, echoingFetch([]));
    const err = await cf("GET", "/accounts").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CliError);
    const msg = (err as Error).message;
    expect(msg).toContain("status 403");
    expect(msg).toContain("bad token [redacted]");
    expect(msg).not.toContain(TOKEN);
  });

  test("the token goes only in the Authorization header, never in the URL or body", async () => {
    const calls: { url: string; init?: RequestInit }[] = [];
    const ok: Fetch = async (url, init) => {
      calls.push({ url, init });
      return new Response(JSON.stringify({ success: true, result: [] }), { status: 200 });
    };
    await makeCf(TOKEN, ok)("POST", `/accounts/${ACC}/d1/database`, { name: "cfs" });
    const [c] = calls;
    expect(c?.url).not.toContain(TOKEN);
    expect(JSON.stringify(c?.init?.body ?? "")).not.toContain(TOKEN);
    const headers = c?.init?.headers as Record<string, string>;
    expect(headers.authorization).toBe(`Bearer ${TOKEN}`);
  });

  test("an error from an unreachable API does not include the token", async () => {
    const down: Fetch = async () => {
      throw new Error(`socket for ${TOKEN}`);
    };
    const err = await makeCf(TOKEN, down)("GET", "/accounts").catch((e: unknown) => e);
    expect((err as Error).message).not.toContain(TOKEN);
    expect((err as Error).message).toContain("Cannot reach the Cloudflare API");
  });

  test("a whole run prints nothing that contains the token when the API fails midway", async () => {
    const lines: string[] = [];
    const cf = makeCf(TOKEN, echoingFetch([]));
    const err = await runDeploy(runOpts(), {
      cf,
      interactive: false,
      ask: async () => "",
      log: (l) => lines.push(l),
    }).catch((e: unknown) => e);
    expect((err as Error).message).not.toContain(TOKEN);
    expect(lines.join("\n")).not.toContain(TOKEN);
  });

  test("no spawned process gets the token in its argv, and the process title and logs stay clean", async () => {
    // A real .tgz bundle, so deploy takes its only subprocess path (tar).
    const src = join(dir, "src");
    for (const [name, bytes] of makeBundle().files) {
      mkdirSync(dirname(join(src, name)), { recursive: true });
      writeFileSync(join(src, name), bytes);
    }
    const tgz = join(dir, "worker-bundle.tgz");
    const made = childProcess.spawnSync("tar", ["-czf", tgz, "-C", src, "."]);
    expect(made.status).toBe(0);

    const argvs: string[][] = [];
    const sync = spyOn(childProcess, "spawnSync");
    const real = sync.getMockImplementation();
    sync.mockImplementation(((cmd: string, args?: readonly string[], ...rest: unknown[]) => {
      argvs.push([cmd, ...(args ?? [])]);
      return (real as (...a: unknown[]) => unknown)(cmd, args, ...rest);
    }) as never);
    const bunSpawn = spyOn(Bun, "spawn");
    const bunSpawnSync = spyOn(Bun, "spawnSync");
    const logs: string[] = [];
    const log = spyOn(console, "log").mockImplementation((...a: unknown[]) => {
      logs.push(a.join(" "));
    });
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({ success: false, errors: [{ code: 10000, message: `bad ${TOKEN}` }] }),
        { status: 403 },
      )) as unknown as typeof fetch;
    const prevToken = process.env.CLOUDFLARE_API_TOKEN;
    process.env.CLOUDFLARE_API_TOKEN = TOKEN;
    let err: unknown;
    try {
      try {
        await deploy.deploy?.run(["--bundle", tgz, "--admin", "a@example.com"]);
      } catch (e) {
        err = e;
      }
    } finally {
      globalThis.fetch = realFetch;
      if (prevToken === undefined) delete process.env.CLOUDFLARE_API_TOKEN;
      else process.env.CLOUDFLARE_API_TOKEN = prevToken;
      log.mockRestore();
      sync.mockRestore();
    }
    // Only argv is checked. The env may hold the token; that is the intended channel.
    const argvOf = (c: unknown[]): string[] => {
      const first = c[0] as string[] | { cmd: string[] };
      return Array.isArray(first) ? first : first.cmd;
    };
    const spawned = [
      ...argvs,
      ...bunSpawn.mock.calls.map(argvOf),
      ...bunSpawnSync.mock.calls.map(argvOf),
    ];
    bunSpawn.mockRestore();
    bunSpawnSync.mockRestore();

    expect(err).toBeInstanceOf(CliError); // the run reached the API and failed there
    expect(argvs.some((a) => a[0] === "tar")).toBe(true); // the spy sees the subprocess
    expect(spawned.flat().some((arg) => arg.includes(TOKEN))).toBe(false);
    expect(process.argv.join(" ")).not.toContain(TOKEN);
    expect(process.title).not.toContain(TOKEN);
    expect((err as Error).message).not.toContain(TOKEN);
    expect(logs.join("\n")).not.toContain(TOKEN);
  });

  test("redact replaces every secret it is given", () => {
    expect(redact(`a ${TOKEN} b ${TOKEN}`, TOKEN, undefined)).toBe("a [redacted] b [redacted]");
  });
});

describe("assets and inputs", () => {
  test("the asset hash is the first 32 hex of BLAKE3(base64 contents + extension)", () => {
    const bytes = enc("abc");
    const h = assetHash("index.html", bytes);
    expect(h).toHaveLength(32);
    // base64("abc") is "YWJj"; the extension "html" is appended before BLAKE3.
    expect(h).toBe(bytesToHex(blake3(enc("YWJjhtml"))).slice(0, 32));
    expect(assetHash("index.html", bytes)).toBe(assetHash("index.html", bytes));
    expect(assetHash("index.html", enc("abd"))).not.toBe(h);
  });

  test("content types carry a charset for text", () => {
    expect(contentType("index.html")).toBe("text/html; charset=utf-8");
    expect(contentType("app.js")).toBe("application/javascript");
    expect(contentType("font.woff2")).toBe("font/woff2");
    expect(contentType("unknown.bin")).toBe("application/octet-stream");
  });

  test("domains, Worker names and emails are checked", () => {
    expect(checkDomain("Vault.Example.com")).toBe("vault.example.com");
    expect(() => checkDomain("https://vault.example.com")).toThrow(CliError);
    expect(() => checkDomain("vault.example.com/x")).toThrow(CliError);
    expect(checkWorkerName("cfs-prod")).toBe("cfs-prod");
    expect(() => checkWorkerName("CFS_Prod")).toThrow(CliError);
    expect(checkEmail(" Admin@Example.com ")).toBe("admin@example.com");
    expect(() => checkEmail("not-an-email")).toThrow(CliError);
  });

  test("setProjectHost creates the file, and refuses a file that is not a JSON object", () => {
    setProjectHost(projectPath, "https://vault.example.com");
    expect(JSON.parse(readFileSync(projectPath, "utf8"))).toEqual({
      host: "https://vault.example.com",
    });
    writeFileSync(projectPath, "[]");
    expect(() => setProjectHost(projectPath, "https://x.example.com")).toThrow(/JSON object/);
  });
});
