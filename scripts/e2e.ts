#!/usr/bin/env bun
// ADR 26: end-to-end script. Boots `wrangler dev` for apps/api on a random port with a fresh local
// D1 (in a temp dir), then drives the real CLI (apps/cli/src/index.ts) through the flows in the ADR.
//
// Cloudflare Access cannot run locally, so the first admin session is a token seeded straight into
// D1; it approves the device code like a browser sign-in would. Everyone else signs in the same way.
//
// Never logs tokens, kit contents, private keys, secret values or the vault password. Stops at the
// first failing step, exits non-zero, and removes the dev server and temp dirs on every exit path.

import { createHash, randomBytes } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { generateKeyPair, lockPrivateKey } from "@cfs/core";

const ROOT = resolve(import.meta.dir, "..");
const API_DIR = join(ROOT, "apps/api");
const CLI = join(ROOT, "apps/cli/src/index.ts");
const WRANGLER = join(API_DIR, "node_modules/.bin/wrangler");
const ADMIN_EMAIL = "admin@e2e.test";
const BOB_EMAIL = "bob@e2e.test";
const APP_NAME = "ci-bot";
const GROUP = "team";
const CODE_RE = /\b([ABCDEFGHJKMNPQRSTUVWXYZ23456789]{4}-[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{4})\b/;

class StepFailure extends Error {
  constructor(
    readonly n: string,
    readonly title: string,
    detail: string,
  ) {
    super(detail);
  }
}

interface Res {
  code: number;
  stdout: string;
  stderr: string;
}

interface Person {
  name: string;
  configDir: string;
  password: string;
  /** Stand-in for an Access sign-in: approves the device code. */
  seedToken: string;
  identityId: string;
}

// ---------------------------------------------------------------- run state

let base = "";
let work = "";
let persist = "";
let cfgPath = "";
let logPath = "";
let port = 0;
let HOST = "";
let wrangler: Bun.Subprocess | undefined;
let cleaned: Promise<void> | undefined;
const people: Record<"admin" | "bob", Person> = {} as Record<"admin" | "bob", Person>;
let appConfigDir = "";
let kitPath = "";

// ---------------------------------------------------------------- small helpers

function expect(cond: unknown, message: string): asserts cond {
  if (!cond) throw new Error(message);
}

const sha256 = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");
const newId = () => randomBytes(12).toString("base64url");
const newToken = (prefix: string) => `${prefix}_${randomBytes(32).toString("base64url")}`;
const nowSec = () => Math.floor(Date.now() / 1000);
const lastLine = (s: string) =>
  s
    .trim()
    .split("\n")
    .filter((l) => l.trim())
    .slice(-3)
    .join(" | ")
    .slice(0, 400);

/** The parent environment without any CFS_* variables, so a developer's own settings cannot leak in. */
function cleanEnv(extra: Record<string, string> = {}): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined && !k.startsWith("CFS_")) env[k] = v;
  }
  return { ...env, WRANGLER_SEND_METRICS: "false", CI: "true", ...extra };
}

/**
 * Environment for wrangler. XDG_CONFIG_HOME points wrangler's global config and dev registry into
 * the run's temp dir. Otherwise other wrangler sessions on this machine share them, and a stale or
 * foreign dev registry entry may break a run. One run failed that way after a rebase and did not
 * fail again once this was set; the cause is not confirmed.
 */
function wranglerEnv(): Record<string, string> {
  return cleanEnv({ XDG_CONFIG_HOME: join(base, "xdg") });
}

function cliEnv(configDir: string, extra: Record<string, string> = {}): Record<string, string> {
  // CFS_UNLOCK_STORE=file keeps the unlocked key out of the real OS keychain.
  return cleanEnv({ CFS_CONFIG_DIR: configDir, CFS_UNLOCK_STORE: "file", ...extra });
}

async function collect(proc: Bun.Subprocess): Promise<Res> {
  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout as ReadableStream).text(),
    new Response(proc.stderr as ReadableStream).text(),
  ]);
  return { code: await proc.exited, stdout, stderr };
}

/** Runs the real CLI as one person (or as a bare config dir). stdin, when given, is piped in. */
async function cli(
  p: { configDir: string },
  args: string[],
  opts: { env?: Record<string, string>; stdin?: string } = {},
): Promise<Res> {
  const proc = Bun.spawn([process.execPath, CLI, ...args], {
    cwd: work,
    env: cliEnv(p.configDir, opts.env),
    stdin: opts.stdin === undefined ? "ignore" : new Blob([opts.stdin]),
    stdout: "pipe",
    stderr: "pipe",
  });
  return collect(proc);
}

async function api(
  method: string,
  path: string,
  token: string | undefined,
  body?: unknown,
): Promise<{ status: number; body: any }> {
  const r = await fetch(`${HOST}/api/v1${path}`, {
    method,
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: r.status, body: await r.json().catch(() => null) };
}

async function runTool(args: string[]): Promise<Res> {
  const proc = Bun.spawn(args, {
    cwd: API_DIR,
    env: wranglerEnv(),
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
  return collect(proc);
}

/** Runs a SQL statement against the local D1 that the dev server uses. */
async function d1(sql: string): Promise<void> {
  const r = await runTool([
    WRANGLER,
    "d1",
    "execute",
    "cfs",
    "--local",
    "--config",
    cfgPath,
    "--persist-to",
    persist,
    "--command",
    sql,
  ]);
  if (r.code !== 0) throw new Error(`local D1 write failed: ${lastLine(r.stderr || r.stdout)}`);
}

/** Inserts a live session for an identity. Only the token hash is stored, as in production. */
async function seedSession(identityId: string, token: string): Promise<void> {
  const at = nowSec();
  await d1(
    `INSERT INTO session (token_hash, identity_id, kind, device, created_at, expires_at) VALUES ('${sha256(token)}', '${identityId}', 'cli', 'e2e', ${at}, ${at + 3600})`,
  );
}

/** Reads the token the CLI saved for a person (never printed). */
function savedToken(configDir: string): string {
  const s = JSON.parse(readFileSync(join(configDir, "session.json"), "utf8")) as { token: string };
  return s.token;
}

/**
 * Writes the wrangler config for this run. Returns a note for the step log. It is the real
 * apps/api/wrangler.jsonc (so its compatibility flags are tested too), minus the web assets and triggers.
 */
function writeE2eConfig(): string {
  const src = parseJsonc(readFileSync(join(API_DIR, "wrangler.jsonc"), "utf8")) as Record<
    string,
    any
  >;
  const cfg: Record<string, unknown> = {
    ...src,
    main: join(API_DIR, "src/index.ts"),
  };
  // Only the API is under test here. The web assets are not needed, so the config drops them.
  for (const k of ["assets", "triggers", "r2_buckets"]) delete cfg[k];
  cfg.d1_databases = (src.d1_databases as Record<string, unknown>[]).map((d) => ({
    ...d,
    database_id: "e2e-local",
    migrations_dir: join(API_DIR, "migrations"),
  }));
  writeFileSync(cfgPath, `${JSON.stringify(cfg, null, 2)}\n`);
  return "apps/api/wrangler.jsonc without assets";
}

/** wrangler.jsonc is JSONC: strip comments outside strings and trailing commas. */
function parseJsonc(text: string): unknown {
  let out = "";
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] as string;
    const next = text[i + 1];
    if (inString) {
      out += ch;
      if (ch === "\\") {
        out += next ?? "";
        i++;
      } else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
    } else if (ch === "/" && next === "/") {
      while (i < text.length && text[i] !== "\n") i++;
    } else if (ch === "/" && next === "*") {
      const end = text.indexOf("*/", i + 2);
      i = end < 0 ? text.length : end + 1;
    } else out += ch;
  }
  return JSON.parse(out.replace(/,(\s*[}\]])/g, "$1"));
}

async function freePort(): Promise<number> {
  const s = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response("") });
  const p = s.port as number;
  s.stop(true);
  return p;
}

function wranglerTail(): string {
  try {
    return lastLine(readFileSync(logPath, "utf8").split("\n").slice(-12).join("\n"));
  } catch {
    return "";
  }
}

/** Waits until the dev server answers /api/health, or fails if it exits first. */
async function waitForHealth(timeoutMs: number): Promise<void> {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    if (wrangler?.exitCode !== null && wrangler?.exitCode !== undefined)
      throw new Error(`wrangler dev exited early: ${wranglerTail()}`);
    try {
      const r = await fetch(`${HOST}/api/health`);
      if (r.ok) return;
    } catch {
      // not listening yet
    }
    await Bun.sleep(500);
  }
  throw new Error(`wrangler dev did not answer on ${HOST} in time: ${wranglerTail()}`);
}

/** Starts wrangler dev on the run port with the run's D1, and waits until it answers. */
async function startDev(): Promise<void> {
  wrangler = Bun.spawn(
    [
      WRANGLER,
      "dev",
      "--config",
      cfgPath,
      "--ip",
      "127.0.0.1",
      "--port",
      String(port),
      "--inspector-port",
      String(await freePort()),
      "--persist-to",
      persist,
    ],
    {
      cwd: API_DIR,
      env: wranglerEnv(),
      stdin: "ignore",
      stdout: openSync(logPath, "a"),
      stderr: openSync(logPath, "a"),
    },
  );
  await waitForHealth(120_000);
}

/** Stops the dev server: SIGINT, then SIGKILL if it has not exited within 10 seconds. */
async function stopDev(): Promise<void> {
  if (!wrangler || wrangler.exitCode !== null) return;
  wrangler.kill("SIGINT");
  await Promise.race([wrangler.exited, Bun.sleep(10_000)]);
  if (wrangler.exitCode === null) wrangler.kill("SIGKILL");
  await wrangler.exited;
}

/**
 * The device-code login (ADR 11) for one person: `cfs login` prints a code, the person's seeded
 * session approves it over HTTP, then the CLI polls, saves the token and exits.
 */
async function deviceLogin(p: Person): Promise<void> {
  const proc = Bun.spawn([process.execPath, CLI, "login", "--host", HOST], {
    cwd: work,
    env: cliEnv(p.configDir),
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
  const stderrDone = new Response(proc.stderr as ReadableStream).text();
  const reader = (proc.stdout as ReadableStream<Uint8Array>).getReader();
  const decoder = new TextDecoder();
  let seen = "";
  let approved = false;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    seen += decoder.decode(value, { stream: true });
    const m = seen.match(CODE_RE);
    if (m && !approved) {
      approved = true;
      const r = await api("POST", "/cli/approve", p.seedToken, { userCode: m[1] });
      if (r.status !== 200) {
        proc.kill();
        throw new Error(`approving the login code was refused (status ${r.status})`);
      }
    }
  }
  const code = await proc.exited;
  const stderr = await stderrDone;
  expect(code === 0, `cfs login exited ${code}: ${lastLine(stderr)}`);
  expect(seen.includes("Signed in"), "cfs login did not report a sign-in");
}

async function setupVault(token: string, password: string): Promise<void> {
  // The key pair is made here, as the web app would. The private key leaves only locked with the password.
  const pair = await generateKeyPair();
  const lockedKey = await lockPrivateKey(pair.privateKey, password);
  const r = await api("POST", "/vault", token, { publicKey: pair.publicKey, lockedKey });
  expect(r.status === 200, `vault setup was refused (status ${r.status})`);
}

async function identityIdByName(name: string): Promise<string> {
  const r = await api("GET", "/identities", people.admin.seedToken);
  expect(r.status === 200, `could not list people (status ${r.status})`);
  const found = (r.body as { id: string; name: string }[]).find((i) => i.name === name);
  expect(found, `${name} is not in the directory`);
  return found.id;
}

async function policyFor(identityId: string, name: string, rules: unknown[]): Promise<void> {
  const created = await api("POST", "/policies", people.admin.seedToken, { name, rules });
  expect(created.status === 201, `could not create policy ${name} (status ${created.status})`);
  const r = await api("POST", `/policies/${created.body.id}/assign`, people.admin.seedToken, {
    identityId,
  });
  expect(r.status < 300, `could not assign policy ${name} (status ${r.status})`);
}

// ---------------------------------------------------------------- steps

let stepNo = 0;
async function step(title: string, fn: () => Promise<string | void>): Promise<void> {
  stepNo += 1;
  const n = String(stepNo).padStart(2, "0");
  const t0 = performance.now();
  try {
    const detail = await fn();
    const ms = Math.round(performance.now() - t0);
    console.log(`[${n}] ok      ${title} (${ms} ms)${detail ? `: ${detail}` : ""}`);
  } catch (e) {
    console.log(`[${n}] FAILED  ${title}`);
    throw new StepFailure(n, title, e instanceof Error ? e.message : String(e));
  }
}

async function run(): Promise<void> {
  const adminPw = randomBytes(18).toString("base64url");
  const bobPw = randomBytes(18).toString("base64url");
  const secretValue = `e2e-${randomBytes(12).toString("hex")}`;
  const rotatedValue = `after-rotation-${randomBytes(6).toString("hex")}`;
  const backupPass = randomBytes(18).toString("base64url");
  const adminConfig = join(work, "admin-config");
  const bobConfig = join(work, "bob-config");
  appConfigDir = join(work, "app-config");
  kitPath = join(work, `${APP_NAME}.kit`);
  const backupPath = join(work, "e2e.cfsbackup");
  people.admin = {
    name: ADMIN_EMAIL,
    configDir: adminConfig,
    password: adminPw,
    seedToken: "",
    identityId: "",
  };
  people.bob = {
    name: BOB_EMAIL,
    configDir: bobConfig,
    password: bobPw,
    seedToken: "",
    identityId: "",
  };

  await step("boot: write the wrangler config (API only, temp paths)", async () => {
    return writeE2eConfig();
  });

  await step("boot: apply migrations to a fresh local D1", async () => {
    const r = await runTool([
      WRANGLER,
      "d1",
      "migrations",
      "apply",
      "cfs",
      "--local",
      "--config",
      cfgPath,
      "--persist-to",
      persist,
    ]);
    expect(r.code === 0, `migrations failed: ${lastLine(r.stderr || r.stdout)}`);
    const applied = new Set(r.stdout.match(/\d{4}_[\w-]+\.sql/g) ?? []).size;
    return `${applied} migration file(s) applied`;
  });

  await step("boot: start wrangler dev on a random port", async () => {
    await startDev();
    const health = await fetch(`${HOST}/api/health`).then((r) => r.json() as Promise<any>);
    expect(health.ok === true, "health check did not report ok");
    return `${HOST}, protocol ${health.protocol}`;
  });

  await step(
    "auth: seed the admin identity and a session in D1 (stand-in for Access)",
    async () => {
      const id = newId();
      people.admin.identityId = id;
      people.admin.seedToken = newToken("cfs");
      await d1(
        `INSERT INTO identity (id, kind, name, role, created_at) VALUES ('${id}', 'user', '${ADMIN_EMAIL}', 'admin', ${nowSec()})`,
      );
      await seedSession(id, people.admin.seedToken);
      return `${ADMIN_EMAIL}, admin`;
    },
  );

  await step("login: device code approved with the seeded admin session", async () => {
    await deviceLogin(people.admin);
    const who = await cli(people.admin, ["whoami"]);
    expect(who.code === 0, `whoami failed: ${lastLine(who.stderr)}`);
    expect(
      who.stdout.includes(`${ADMIN_EMAIL} (user, admin)`) && who.stdout.includes("vault locked"),
      "whoami did not show the admin, locked",
    );
    return "session saved, vault locked";
  });

  await step("vault: set up the admin vault over the API (@cfs/core keys)", async () => {
    await setupVault(savedToken(adminConfig), adminPw);
    return "public key set, private key locked with the vault password";
  });

  await step("unlock: cfs unlock with the vault password", async () => {
    const r = await cli(people.admin, ["unlock", "--ttl", "1h"], {
      env: { CFS_PASSWORD: adminPw },
    });
    expect(r.code === 0, `unlock failed: ${lastLine(r.stderr)}`);
    expect(r.stdout.includes("Unlocked until"), "unlock did not confirm");
    return "unlocked for 1h";
  });

  await step(`group: create "${GROUP}" with the admin as the only member`, async () => {
    const r = await cli(people.admin, ["group", "create", GROUP]);
    expect(r.code === 0, `group create failed: ${lastLine(r.stderr)}`);
    const list = await cli(people.admin, ["group", "list"]);
    expect(list.stdout.includes(`${GROUP}\tkey version 1`), "group list does not show the group");
    return "key version 1";
  });

  const SECRET = `${GROUP}/dev`;
  await step(`secrets: set ${SECRET} from a .env on stdin, then get it back`, async () => {
    const set = await cli(people.admin, ["set", SECRET], {
      stdin: `API_KEY=${secretValue}\nPORT=8080\n`,
    });
    expect(set.code === 0, `set failed: ${lastLine(set.stderr)}`);
    expect(set.stdout.includes("as version 1"), "set did not save version 1");
    const got = await cli(people.admin, ["get", SECRET, "API_KEY"]);
    expect(got.code === 0, `get failed: ${lastLine(got.stderr)}`);
    expect(got.stdout.trim() === secretValue, "get returned a different value");
    return "2 values, version 1 (values not shown)";
  });

  await step(`run: ${SECRET} values reach the child environment`, async () => {
    const ok = await cli(
      people.admin,
      ["run", SECRET, "--", "sh", "-c", 'test "$API_KEY" = "$E2E_EXPECT" && test "$PORT" = 8080'],
      { env: { E2E_EXPECT: secretValue } },
    );
    expect(ok.code === 0, `child did not see the values (exit ${ok.code})`);
    const bad = await cli(people.admin, ["run", SECRET, "--", "sh", "-c", "exit 7"]);
    expect(bad.code === 7, `child exit code was not passed through (got ${bad.code})`);
    return "child saw both values, exit code 7 passed through";
  });

  await step(`members: invite ${BOB_EMAIL}, sign in and set up the vault`, async () => {
    const inv = await api("POST", "/invites", people.admin.seedToken, { email: BOB_EMAIL });
    expect(inv.status === 201, `invite refused (status ${inv.status})`);
    const id = await identityIdByName(BOB_EMAIL);
    people.bob.identityId = id;
    people.bob.seedToken = newToken("cfs");
    await seedSession(id, people.bob.seedToken);
    await deviceLogin(people.bob);
    await setupVault(savedToken(bobConfig), bobPw);
    const unlock = await cli(people.bob, ["unlock"], { env: { CFS_PASSWORD: bobPw } });
    expect(unlock.code === 0, `bob unlock failed: ${lastLine(unlock.stderr)}`);
    return `${BOB_EMAIL} invited, signed in, vault unlocked`;
  });

  await step(`group: add ${BOB_EMAIL} to "${GROUP}"`, async () => {
    const r = await cli(people.admin, ["group", "add-member", GROUP, BOB_EMAIL]);
    expect(r.code === 0, `add-member failed: ${lastLine(r.stderr)}`);
    return undefined;
  });

  await step(`policy: ${BOB_EMAIL} may read ${GROUP}/* (admin API)`, async () => {
    await policyFor(people.bob.identityId, "team-read", [{ path: `${GROUP}/*`, caps: ["read"] }]);
    const got = await cli(people.bob, ["get", SECRET, "API_KEY"]);
    expect(got.code === 0, `bob could not read after add: ${lastLine(got.stderr)}`);
    expect(got.stdout.trim() === secretValue, "bob read a different value");
    return "bob reads the current version";
  });

  await step(`apps: create ${APP_NAME} with a kit file and add it to "${GROUP}"`, async () => {
    const r = await cli(people.admin, ["app", "create", APP_NAME, "--out", kitPath]);
    expect(r.code === 0, `app create failed: ${lastLine(r.stderr)}`);
    expect((statSync(kitPath).mode & 0o777) === 0o600, "kit file is not owner-only");
    const add = await cli(people.admin, ["group", "add-member", GROUP, APP_NAME]);
    expect(add.code === 0, `app add-member failed: ${lastLine(add.stderr)}`);
    return "kit written 0600 (contents not shown)";
  });

  const kitEnv = () => ({ CFS_KIT: readFileSync(kitPath, "utf8").trim() });

  await step(
    `apps: the kit is denied ${SECRET} before any read policy (default deny)`,
    async () => {
      const r = await cli({ configDir: appConfigDir }, ["get", SECRET, "API_KEY"], {
        env: kitEnv(),
      });
      expect(r.code !== 0, "the kit read a secret with no policy");
      expect(r.stdout.trim() !== secretValue, "the kit returned the value without a policy");
      expect(r.stderr.includes("Not allowed"), `unexpected refusal: ${lastLine(r.stderr)}`);
      return "refused: Not allowed";
    },
  );

  await step(`apps: give ${APP_NAME} read on ${GROUP}/* and read with CFS_KIT`, async () => {
    const appId = await identityIdByName(APP_NAME);
    await policyFor(appId, "team-app-read", [{ path: `${GROUP}/*`, caps: ["read"] }]);
    const r = await cli({ configDir: appConfigDir }, ["get", SECRET, "API_KEY"], {
      env: kitEnv(),
    });
    expect(r.code === 0, `kit read failed: ${lastLine(r.stderr)}`);
    expect(r.stdout.trim() === secretValue, "the kit read a different value");
    return "app reads the current version";
  });

  await step(`rotate: remove ${BOB_EMAIL}; the next version is unreadable to bob`, async () => {
    const rm = await cli(people.admin, ["group", "remove-member", GROUP, BOB_EMAIL]);
    expect(rm.code === 0, `remove-member failed: ${lastLine(rm.stderr)}`);
    expect(rm.stdout.includes("re-encrypted under key version 2"), "rotation did not finish");
    const set = await cli(people.admin, ["set", SECRET], {
      stdin: `ROTATED=${rotatedValue}\n`,
    });
    expect(set.code === 0, `set after rotation failed: ${lastLine(set.stderr)}`);
    const app = await cli({ configDir: appConfigDir }, ["get", SECRET, "ROTATED"], {
      env: kitEnv(),
    });
    expect(app.code === 0 && app.stdout.trim() === rotatedValue, "the app lost access in rotation");
    const bob = await cli(people.bob, ["get", SECRET, "ROTATED"]);
    expect(bob.code !== 0, "bob opened a version written after removal");
    expect(bob.stdout.trim() !== rotatedValue, "bob received the new value");
    expect(
      bob.stderr.includes(`not in the "${GROUP}" group`),
      `unexpected: ${lastLine(bob.stderr)}`,
    );
    return "bob refused with 'not in the group'; the app still reads";
  });

  await step(`requests: ${BOB_EMAIL} asks for ${SECRET}, admin approves, bob reads`, async () => {
    const req = await cli(people.bob, ["request", SECRET, "--reason", "e2e check", "--for", "30m"]);
    expect(req.code === 0, `request failed: ${lastLine(req.stderr)}`);
    const id = req.stdout.match(/Request (\S+) sent/)?.[1];
    expect(id, "request did not return an id");
    const pending = await cli(people.admin, ["requests"]);
    expect(
      pending.stdout.includes(id) && pending.stdout.includes("pending"),
      "request not pending",
    );
    const ok = await cli(people.admin, ["approve", id]);
    expect(ok.code === 0, `approve failed: ${lastLine(ok.stderr)}`);
    const read = await cli(people.bob, ["get", SECRET, "ROTATED"]);
    expect(
      read.code === 0 && read.stdout.trim() === rotatedValue,
      "bob cannot read after approval",
    );
    return "approved for 30m, bob reads the current version";
  });

  await step("audit: cfs audit verify (hash chain)", async () => {
    const r = await cli(people.admin, ["audit", "verify"]);
    expect(r.code === 0, `audit verify failed: ${lastLine(r.stdout)}`);
    expect(r.stdout.includes("ok:"), "audit verify did not report ok");
    const rows = r.stdout.match(/(\d+) rows checked/)?.[1];
    return `${rows ?? "?"} rows checked`;
  });

  await step("backup: download a passphrase-sealed backup", async () => {
    const r = await cli(
      people.admin,
      ["backup", "--out", backupPath, "--passphrase-env", "CFS_BACKUP_PASS"],
      {
        env: { CFS_BACKUP_PASS: backupPass },
      },
    );
    expect(r.code === 0, `backup failed: ${lastLine(r.stderr)}`);
    const head = readFileSync(backupPath).subarray(0, 8).toString("utf8");
    expect(head === "CFSSEAL1", "the backup is not sealed");
    return `${statSync(backupPath).size} bytes, sealed`;
  });

  await step("restore: restore the backup onto this server", async () => {
    const r = await cli(
      people.admin,
      [
        "restore",
        backupPath,
        "--passphrase-env",
        "CFS_BACKUP_PASS",
        "--confirm-host",
        `127.0.0.1:${port}`,
      ],
      { env: { CFS_BACKUP_PASS: backupPass } },
    );
    expect(r.code === 0, `restore failed: ${lastLine(r.stderr)}`);
    expect(r.stdout.includes("Restored at"), "restore did not confirm");
    // Restoring ends every session (ADR 23), so the CLI's token is dead. Everyone signs in again: the
    // seeded approver is re-seeded, then the admin runs the device login again.
    await seedSession(people.admin.identityId, people.admin.seedToken);
    await deviceLogin(people.admin);
    return "sessions ended by design; the admin signed in again";
  });

  await step("restore: the data is back (secret, group, app kit)", async () => {
    const adminRead = await cli(people.admin, ["get", SECRET, "ROTATED"]);
    expect(
      adminRead.code === 0 && adminRead.stdout.trim() === rotatedValue,
      "admin cannot read after restore",
    );
    const app = await cli({ configDir: appConfigDir }, ["get", SECRET, "API_KEY"], {
      env: kitEnv(),
    });
    expect(app.code === 0 && app.stdout.trim() === secretValue, "the app kit fails after restore");
    return "admin reads; app kit signs in again and reads";
  });
}

async function cleanup(): Promise<void> {
  cleaned ??= (async () => {
    await stopDev();
    if (base) rmSync(base, { recursive: true, force: true });
  })();
  return cleaned;
}

async function main(): Promise<number> {
  base = mkdtempSync(join(tmpdir(), "cfs-e2e-"));
  work = join(base, "work");
  persist = join(base, "d1");
  cfgPath = join(base, "wrangler.e2e.json");
  logPath = join(base, "wrangler.log");
  mkdirSync(work);
  mkdirSync(persist);
  port = await freePort();
  HOST = `http://127.0.0.1:${port}`;
  console.log(`cfs e2e (ADR 26): ${HOST}, temp dir ${base}`);

  process.once("SIGINT", () => {
    void cleanup().finally(() => process.exit(130));
  });
  process.once("SIGTERM", () => {
    void cleanup().finally(() => process.exit(143));
  });

  try {
    await run();
    console.log(`\ne2e passed: ${stepNo} steps`);
    return 0;
  } catch (e) {
    if (e instanceof StepFailure) {
      console.error(`\ne2e FAILED at step ${e.n}: ${e.title}\n  ${e.message}`);
    } else {
      console.error(`\ne2e FAILED: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (wrangler && wrangler.exitCode === null) console.error(`  wrangler log: ${wranglerTail()}`);
    return 1;
  } finally {
    await cleanup();
  }
}

process.exitCode = await main();
