import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, relative, sep } from "node:path";
import { type BundleManifest, PROTOCOL_VERSION, parseManifest } from "@cfs/core";
import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { flag } from "../args.ts";
import { CliError, normalizeHost, readJsonFile, resolveHost, secureUrl } from "../config.ts";
import { ask, confirm } from "../prompt.ts";
import type { Fetch } from "../server.ts";
import type { Commands } from "./types.ts";

// ADR 25: `cfs init` writes .cfs.json, `cfs upgrade` replaces this binary after a checksum
// check, `cfs deploy` installs the Worker bundle into the user's Cloudflare account.

export const RELEASES = "https://github.com/JuniYadi/cf-secret-remote/releases";

// ---------------------------------------------------------------- init

const PROJECT_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/** Writes a minimal .cfs.json. Refuses to replace one unless `overwrite` is set. */
export function writeProjectFile(
  path: string,
  data: { host: string; project: string },
  overwrite = false,
): void {
  const host = normalizeHost(data.host);
  if (!PROJECT_NAME.test(data.project))
    throw new CliError(`"${data.project}" is not a valid project name. Use letters, digits, . _ -`);
  if (existsSync(path) && !overwrite) throw new CliError(`${path} already exists.`);
  writeFileSync(path, `${JSON.stringify({ host, project: data.project }, null, 2)}\n`);
}

async function init(args: string[], hostFlag?: string) {
  const path = join(process.cwd(), ".cfs.json");
  const interactive = Boolean(process.stdin.isTTY);
  const exists = existsSync(path);
  if (exists && !interactive)
    throw new CliError(`${path} already exists. Delete it first, or run cfs init in a terminal.`);
  if (exists && !(await confirm(`${path} exists. Replace it? (y/N) `)))
    throw new CliError("Left .cfs.json unchanged.");

  const suggested = resolveHost()?.host;
  let host = hostFlag ?? process.env.CFS_HOST ?? "";
  if (!host) {
    if (!interactive) throw new CliError("No server. Pass --host https://your-server.");
    host = await ask(`Server address${suggested ? ` [${suggested}]` : ""}: `, suggested ?? "");
  }
  let project = flag(args, "--project") ?? "";
  if (!project) {
    if (!interactive) throw new CliError("No project. Pass --project <name>.");
    const fallback = basename(process.cwd());
    project = await ask(`Project name [${fallback}]: `, fallback);
  }
  writeProjectFile(path, { host, project }, exists);
  console.log(`Wrote ${path}. Next: cfs login`);
}

// ---------------------------------------------------------------- upgrade

/** The release asset for this machine, e.g. cfs-darwin-arm64. Matches the release workflow. */
export function assetName(
  platform: string = process.platform,
  arch: string = process.arch,
): string {
  const os = { darwin: "darwin", linux: "linux", win32: "windows" }[platform];
  const cpu = arch === "arm64" || arch === "x64" ? arch : undefined;
  const supported =
    (os === "darwin" && (cpu === "arm64" || cpu === "x64")) ||
    (os === "linux" && (cpu === "arm64" || cpu === "x64")) ||
    (os === "windows" && cpu === "x64");
  if (!os || !cpu || !supported)
    throw new CliError(`There is no cfs release for ${platform} ${arch}.`);
  return `cfs-${os}-${cpu}${os === "windows" ? ".exe" : ""}`;
}

/** Parses `sha256sum` output: "<hex>  <name>" per line. Returns name to hex digest. */
export function parseChecksums(text: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of text.split(/\r?\n/)) {
    const m = /^([0-9a-fA-F]{64})\s+\*?(\S+)$/.exec(line.trim());
    if (m) out.set(m[2] as string, (m[1] as string).toLowerCase());
  }
  return out;
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function download(f: Fetch, url: string, what: string): Promise<Uint8Array> {
  let r: Response;
  try {
    r = await f(url);
  } catch {
    throw new CliError(`Could not download the ${what} from ${url}. Nothing was changed.`);
  }
  if (!r.ok)
    throw new CliError(`Could not download the ${what} (status ${r.status}). Nothing was changed.`);
  return new Uint8Array(await r.arrayBuffer());
}

export interface UpgradeOptions {
  /** Directory URL that holds the asset and SHA256SUMS. */
  baseUrl: string;
  asset: string;
  /** The file to replace. */
  exePath: string;
  fetch?: Fetch;
}

/**
 * Downloads the asset, checks it against SHA256SUMS, then swaps it in. Any failure before
 * the swap leaves the existing binary untouched.
 */
export async function upgradeBinary(o: UpgradeOptions): Promise<void> {
  const f = o.fetch ?? fetch;
  const base = o.baseUrl.replace(/\/+$/, "");
  const sums = new TextDecoder().decode(await download(f, `${base}/SHA256SUMS`, "checksum list"));
  const expected = parseChecksums(sums).get(o.asset);
  if (!expected)
    throw new CliError(`SHA256SUMS has no entry for ${o.asset}. Upgrade aborted, nothing changed.`);
  const bytes = await download(f, `${base}/${o.asset}`, "binary");
  const actual = await sha256Hex(bytes);
  if (actual !== expected)
    throw new CliError(
      `Checksum mismatch for ${o.asset} (expected ${expected}, got ${actual}). Upgrade aborted, nothing changed.`,
    );
  const tmp = `${o.exePath}.new`;
  writeFileSync(tmp, bytes, { mode: 0o755 });
  chmodSync(tmp, 0o755);
  renameSync(tmp, o.exePath);
}

async function upgrade(args: string[]) {
  if (process.platform === "win32")
    throw new CliError(
      `cfs upgrade cannot replace a running file on Windows yet. Download cfs.exe from ${RELEASES}.`,
    );
  const version = flag(args, "--version");
  if (version && !/^v?\d+\.\d+\.\d+/.test(version))
    throw new CliError(`"${version}" is not a version. Use a form such as v0.2.0.`);
  const exe = process.execPath;
  if (!basename(exe).startsWith("cfs"))
    throw new CliError(
      `cfs upgrade replaces the compiled cfs binary, not ${basename(exe)}. Download a release from ${RELEASES}.`,
    );
  const tag = version ? (version.startsWith("v") ? version : `v${version}`) : undefined;
  const baseUrl = secureUrl(
    process.env.CFS_RELEASE_URL ??
      (tag ? `${RELEASES}/download/${tag}` : `${RELEASES}/latest/download`),
  ).href.replace(/\/+$/, "");
  const asset = assetName();
  console.log(`Downloading ${asset}${tag ? ` ${tag}` : " (latest)"}...`);
  await upgradeBinary({ baseUrl, asset, exePath: exe });
  console.log(`Upgraded ${exe}. Run: cfs --version`);
}

// ---------------------------------------------------------------- deploy (ADR 25)

export const CF_API = "https://api.cloudflare.com/client/v4";
export const TOKEN_ENV = "CLOUDFLARE_API_TOKEN";
const BUNDLE_NAME = "worker-bundle.tgz";
const MIGRATIONS_TABLE = "_cfs_migrations";
const API_BYPASS = "/api/v1/*";
const HEALTH_PATH = "/api/health";
const DEFAULT_WORKER = "cfs";

/**
 * Calls the Cloudflare API and returns the unwrapped `result`. `opts.bearer` replaces the API
 * token for one call (asset uploads use their own JWT). Throws CliError; never includes a token.
 */
export type Cf = (
  method: string,
  path: string,
  body?: unknown,
  opts?: { bearer?: string },
) => Promise<unknown>;

interface CfEnvelope {
  success?: boolean;
  result?: unknown;
  errors?: { code?: number; message?: string }[];
}

/** Replaces each secret in `text` with [redacted]. Used on every API error message. */
export function redact(text: string, ...secrets: (string | undefined)[]): string {
  let out = text;
  for (const s of secrets) if (s) out = out.split(s).join("[redacted]");
  return out;
}

/** The real client. The token only ever goes into the Authorization header. */
export function makeCf(token: string, f: Fetch = fetch): Cf {
  return async (method, path, body, opts) => {
    const headers: Record<string, string> = {
      authorization: `Bearer ${opts?.bearer ?? token}`,
    };
    let payload: BodyInit | undefined;
    if (body instanceof FormData) payload = body;
    else if (body !== undefined) {
      headers["content-type"] = "application/json";
      payload = JSON.stringify(body);
    }
    let r: Response;
    try {
      r = await f(`${CF_API}${path}`, { method, headers, body: payload });
    } catch {
      throw new CliError(
        `Cannot reach the Cloudflare API (${method} ${path}). Check your network.`,
      );
    }
    const json = (await r.json().catch(() => undefined)) as CfEnvelope | undefined;
    if (!r.ok || json?.success !== true) {
      const why =
        (json?.errors ?? []).map((e) => e.message ?? `code ${e.code ?? "unknown"}`).join("; ") ||
        "no details";
      throw new CliError(
        `Cloudflare API ${method} ${path} failed (status ${r.status}): ${redact(why, token, opts?.bearer)}`,
      );
    }
    return json.result;
  };
}

// ---------------------------------------------------------------- bundle

export interface Bundle {
  manifest: BundleManifest;
  /** Every file in the bundle, keyed by relative path, including manifest.json. */
  files: Map<string, Uint8Array>;
}

/**
 * Checks a bundle before anything is sent to Cloudflare: same protocol, every listed file present
 * with the listed hash, no unlisted files, and the entries the deploy needs exist.
 */
export async function verifyBundle(bundle: Bundle): Promise<void> {
  const { manifest, files } = bundle;
  if (manifest.protocol !== PROTOCOL_VERSION)
    throw new CliError(
      `The bundle speaks protocol ${manifest.protocol}, but this cfs speaks ${PROTOCOL_VERSION}. Use a bundle and cfs with the same protocol. Nothing was deployed.`,
    );
  for (const [path, want] of Object.entries(manifest.files)) {
    const bytes = files.get(path);
    if (!bytes) throw new CliError(`The bundle is missing ${path}. Nothing was deployed.`);
    if ((await sha256Hex(bytes)) !== want)
      throw new CliError(`${path} does not match its hash in the manifest. Nothing was deployed.`);
  }
  for (const path of files.keys())
    if (path !== "manifest.json" && !(path in manifest.files))
      throw new CliError(`The bundle has an unlisted file ${path}. Nothing was deployed.`);
  if (!(manifest.main in manifest.files))
    throw new CliError(`The bundle has no Worker entry ${manifest.main}. Nothing was deployed.`);
  for (const m of manifest.migrations) {
    if (!/^[A-Za-z0-9_.-]+\.sql$/.test(m))
      throw new CliError(`Migration name "${m}" is not allowed. Nothing was deployed.`);
    if (!(`migrations/${m}` in manifest.files))
      throw new CliError(`The bundle has no file for migration ${m}. Nothing was deployed.`);
  }
}

/** Reads every file under dir. Symbolic links are refused rather than followed. */
function readTree(
  dir: string,
  base = dir,
  out = new Map<string, Uint8Array>(),
): Map<string, Uint8Array> {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const st = lstatSync(full);
    if (st.isSymbolicLink())
      throw new CliError(`The bundle contains a symbolic link (${name}). Nothing was deployed.`);
    if (st.isDirectory()) readTree(full, base, out);
    else out.set(relative(base, full).split(sep).join("/"), new Uint8Array(readFileSync(full)));
  }
  return out;
}

/** Loads a bundle from a folder or a worker-bundle.tgz, then verifies it. */
export async function loadBundle(path: string): Promise<Bundle> {
  let dir = path;
  let unpacked: string | undefined;
  if (!existsSync(path)) throw new CliError(`No bundle at ${path}. Nothing was deployed.`);
  try {
    if (lstatSync(path).isFile()) {
      unpacked = mkdtempSync(join(tmpdir(), "cfs-bundle-"));
      const r = spawnSync("tar", ["-xzf", path, "-C", unpacked], { encoding: "utf8" });
      if (r.status !== 0) throw new CliError(`Could not unpack ${path}. Nothing was deployed.`);
      dir = unpacked;
    }
    const files = readTree(dir);
    const raw = files.get("manifest.json");
    if (!raw) throw new CliError(`${path} has no manifest.json. Nothing was deployed.`);
    let manifest: BundleManifest;
    try {
      manifest = parseManifest(JSON.parse(new TextDecoder().decode(raw)));
    } catch (e) {
      throw new CliError(
        `${path}: ${e instanceof Error ? e.message : String(e)} Nothing was deployed.`,
      );
    }
    const bundle = { manifest, files };
    await verifyBundle(bundle);
    return bundle;
  } finally {
    if (unpacked) rmSync(unpacked, { recursive: true, force: true });
  }
}

/** Downloads worker-bundle.tgz from a release and checks it against SHA256SUMS. Returns its folder. */
async function downloadBundle(f: Fetch, tag: string | undefined): Promise<string> {
  const base = secureUrl(
    process.env.CFS_RELEASE_URL ??
      (tag ? `${RELEASES}/download/${tag}` : `${RELEASES}/latest/download`),
  ).href.replace(/\/+$/, "");
  const sums = parseChecksums(
    new TextDecoder().decode(await download(f, `${base}/SHA256SUMS`, "checksum list")),
  );
  const want = sums.get(BUNDLE_NAME);
  if (!want)
    throw new CliError(`SHA256SUMS has no entry for ${BUNDLE_NAME}. Nothing was deployed.`);
  const bytes = await download(f, `${base}/${BUNDLE_NAME}`, "Worker bundle");
  if ((await sha256Hex(bytes)) !== want)
    throw new CliError(`Checksum mismatch for ${BUNDLE_NAME}. Nothing was deployed.`);
  const dir = mkdtempSync(join(tmpdir(), "cfs-release-"));
  writeFileSync(join(dir, BUNDLE_NAME), bytes);
  return dir;
}

const CONTENT_TYPES: Record<string, string> = {
  html: "text/html",
  js: "application/javascript",
  mjs: "application/javascript",
  css: "text/css",
  json: "application/json",
  map: "application/json",
  txt: "text/plain",
  svg: "image/svg+xml",
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  gif: "image/gif",
  webp: "image/webp",
  ico: "image/x-icon",
  woff: "font/woff",
  woff2: "font/woff2",
  wasm: "application/wasm",
  xml: "application/xml",
};

export function contentType(rel: string): string {
  const ext = rel.includes(".") ? (rel.split(".").pop() ?? "").toLowerCase() : "";
  const t = CONTENT_TYPES[ext] ?? "application/octet-stream";
  return t.startsWith("text/") ? `${t}; charset=utf-8` : t;
}

/**
 * The hash Cloudflare uses to name an asset: BLAKE3 of the base64 contents followed by the
 * extension, first 32 hex characters. The same scheme as `wrangler deploy`, so uploads match.
 */
export function assetHash(rel: string, bytes: Uint8Array): string {
  const ext = rel.includes(".") ? (rel.split(".").pop() ?? "") : "";
  const b64 = Buffer.from(bytes).toString("base64");
  return bytesToHex(blake3(new TextEncoder().encode(`${b64}${ext}`))).slice(0, 32);
}

// ---------------------------------------------------------------- inputs

export interface DeployRun {
  /** Worker name, also the D1 database name. */
  name: string;
  domain?: string;
  account?: string;
  admin?: string;
  dryRun: boolean;
  /** Loaded bundle. Absent only in a dry run that did not read one. */
  bundle?: Bundle;
  /** Where the bundle comes from, for the plan. */
  bundleSource: string;
  projectPath: string;
}

export interface DeployDeps {
  /** Absent in a dry run, which makes no calls. */
  cf?: Cf;
  interactive: boolean;
  ask(question: string): Promise<string>;
  log(line: string): void;
}

const HOSTNAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const WORKER_NAME = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const EMAIL = /^[^\s@/]+@[^\s@/]+\.[^\s@/]+$/;

export function checkDomain(d: string): string {
  const v = d.trim().toLowerCase();
  if (!HOSTNAME.test(v))
    throw new CliError(`"${d}" is not a domain. Use the bare host, e.g. vault.example.com`);
  return v;
}

export function checkWorkerName(n: string): string {
  if (!WORKER_NAME.test(n))
    throw new CliError(`"${n}" is not a Worker name. Use lowercase letters, digits and dashes.`);
  return n;
}

export function checkEmail(e: string): string {
  const v = e.trim().toLowerCase();
  if (!EMAIL.test(v)) throw new CliError(`"${e}" is not an email address.`);
  return v;
}

// ---------------------------------------------------------------- plan

/** The steps a real run takes, in order. Pure: makes no calls. */
export function deployPlan(run: DeployRun): string[] {
  const b = run.bundle;
  const admin = run.admin ?? "the email you give (--admin or a prompt)";
  const host = run.domain ? `https://${run.domain}` : "a workers.dev address";
  const lines = [
    `Deploy Worker "${run.name}" to ${host}`,
    b
      ? `Bundle: ${b.manifest.version}, protocol ${b.manifest.protocol}, ${b.manifest.migrations.length} migrations (${run.bundleSource})`
      : `Bundle: ${run.bundleSource}`,
    `Account: ${run.account ?? `CLOUDFLARE_ACCOUNT_ID, or the only account on the token`}`,
    `1. D1 database "${run.name}": create it if missing`,
    `2. Migrations: apply the ones not yet in ${MIGRATIONS_TABLE}, in order (forward only)`,
  ];
  if (run.domain)
    lines.push(
      `3. Access: protect https://${run.domain} (allow ${admin}); bypass ${run.domain}${API_BYPASS} and ${run.domain}${HEALTH_PATH}`,
    );
  else
    lines.push(
      "3. Access: skipped (no --domain). The web UI is then not behind Cloudflare Access.",
    );
  lines.push(
    `4. Upload Worker "${run.name}" with its static assets, D1 binding DB, and BOOTSTRAP_ADMIN_EMAIL = ${admin}`,
    `5. Cron schedules from wrangler.jsonc (the daily audit checkpoint)`,
    run.domain
      ? `6. Custom domain ${run.domain} on the Worker`
      : `6. Enable the workers.dev route for "${run.name}"`,
    `7. Write the host to ${run.projectPath}`,
  );
  return lines;
}

// ---------------------------------------------------------------- steps

const d1Path = (a: string, uuid: string) => `/accounts/${a}/d1/database/${uuid}/query`;

async function resolveAccount(cf: Cf, given: string | undefined): Promise<string> {
  if (given) return given;
  const accounts = (await cf("GET", "/accounts")) as { id: string }[];
  if (accounts.length === 1 && accounts[0]) return accounts[0].id;
  if (accounts.length === 0)
    throw new CliError("The token has no Cloudflare account. Check its permissions.");
  throw new CliError(
    "The token can reach several accounts. Pass --account <id> or set CLOUDFLARE_ACCOUNT_ID.",
  );
}

async function ensureDatabase(cf: Cf, a: string, name: string): Promise<string> {
  const list = (await cf("GET", `/accounts/${a}/d1/database?per_page=100`)) as {
    uuid: string;
    name: string;
  }[];
  const found = list.find((d) => d.name === name);
  if (found) return found.uuid;
  return ((await cf("POST", `/accounts/${a}/d1/database`, { name })) as { uuid: string }).uuid;
}

/**
 * Applies the bundle's migrations that the database has not recorded, in order. Each migration
 * and its record go in one query, so a migration is recorded only if it ran. Returns the names
 * applied this time (empty on a re-run).
 */
export async function applyMigrations(
  cf: Cf,
  a: string,
  uuid: string,
  bundle: Bundle,
  log: (line: string) => void,
): Promise<string[]> {
  const q = async (sql: string): Promise<Record<string, unknown>[]> => {
    const r = (await cf("POST", d1Path(a, uuid), { sql })) as {
      results?: Record<string, unknown>[];
    }[];
    return r[0]?.results ?? [];
  };
  await q(
    `CREATE TABLE IF NOT EXISTS ${MIGRATIONS_TABLE} (name TEXT PRIMARY KEY, sha256 TEXT NOT NULL, applied_at INTEGER NOT NULL);`,
  );
  const applied = new Map(
    (await q(`SELECT name, sha256 FROM ${MIGRATIONS_TABLE};`)).map((r) => [
      String(r.name),
      String(r.sha256),
    ]),
  );
  const { manifest } = bundle;
  const listed = manifest.migrations;
  for (const name of applied.keys())
    if (!listed.includes(name))
      throw new CliError(
        `The database has migration ${name}, which this bundle does not have. Deploy with a newer bundle. Nothing was changed.`,
      );
  for (const name of listed) {
    const have = applied.get(name);
    if (have !== undefined && have !== manifest.files[`migrations/${name}`])
      throw new CliError(
        `Migration ${name} changed after it was applied. Migrations are forward only: add a new migration instead. Nothing was changed.`,
      );
  }
  const pending = listed.filter((n) => !applied.has(n));
  const first = listed.indexOf(pending[0] ?? "");
  if (pending.length > 0 && listed.slice(first).some((n) => applied.has(n)))
    throw new CliError("Migrations are out of order in the database. Nothing was changed.");

  const done: string[] = [];
  for (const name of pending) {
    const sha = manifest.files[`migrations/${name}`] as string;
    const sql = new TextDecoder().decode(bundle.files.get(`migrations/${name}`));
    await q(
      `${sql}\nINSERT INTO ${MIGRATIONS_TABLE} (name, sha256, applied_at) VALUES ('${name}', '${sha}', ${Math.floor(Date.now() / 1000)});`,
    );
    log(`Applied migration ${name}`);
    done.push(name);
  }
  return done;
}

export interface AccessApp {
  id: string;
  domain: string;
  aud?: string;
}
export interface AccessInfo {
  teamDomain: string;
  aud: string;
}

/** Creates or updates one Access application for `domain`, found by its domain. */
async function putAccessApp(
  cf: Cf,
  a: string,
  existing: AccessApp[],
  domain: string,
  policy: Record<string, unknown>,
): Promise<AccessApp> {
  const body = {
    name: `cfs ${domain}`,
    domain,
    type: "self_hosted",
    session_duration: "24h",
    policies: [policy],
  };
  const found = existing.find((x) => x.domain === domain);
  if (found) return (await cf("PUT", `/accounts/${a}/access/apps/${found.id}`, body)) as AccessApp;
  return (await cf("POST", `/accounts/${a}/access/apps`, body)) as AccessApp;
}

/**
 * ADR 25 and ADR 4: the UI and /cli/login sit behind Access for the admin; /api/v1/* and the
 * health check bypass it (the Worker checks cfs tokens itself). Returns the team domain and the
 * UI application's audience, which the Worker needs to check Access JWTs.
 */
export async function ensureAccess(
  cf: Cf,
  a: string,
  domain: string,
  admin: string,
): Promise<AccessInfo> {
  const org = (await cf("GET", `/accounts/${a}/access/organizations`)) as { auth_domain?: string };
  if (!org.auth_domain)
    throw new CliError(
      "This account has no Cloudflare Access team. Set up Zero Trust first, or deploy without --domain.",
    );
  const apps = (await cf("GET", `/accounts/${a}/access/apps?per_page=100`)) as AccessApp[];
  const ui = await putAccessApp(cf, a, apps, domain, {
    name: "cfs admin",
    decision: "allow",
    include: [{ email: { email: admin } }],
  });
  const bypass = { name: "cfs bypass", decision: "bypass", include: [{ everyone: {} }] };
  for (const path of [`${domain}${API_BYPASS}`, `${domain}${HEALTH_PATH}`]) {
    await putAccessApp(cf, a, apps, path, bypass);
  }
  if (!ui.aud)
    throw new CliError(
      "Cloudflare Access did not return an audience for the app. Nothing else was changed.",
    );
  return { teamDomain: org.auth_domain, aud: ui.aud };
}

/** Uploads the bundle's web assets with Cloudflare's upload session. Returns the completion JWT. */
export async function uploadAssets(
  cf: Cf,
  a: string,
  name: string,
  bundle: Bundle,
): Promise<string> {
  const entries = [...bundle.files.keys()]
    .filter((p) => p.startsWith("assets/"))
    .sort()
    .map((p) => {
      const rel = p.slice("assets/".length);
      const bytes = bundle.files.get(p) as Uint8Array;
      return { rel, bytes, hash: assetHash(rel, bytes) };
    });
  const manifest: Record<string, { hash: string; size: number }> = {};
  for (const e of entries) manifest[`/${e.rel}`] = { hash: e.hash, size: e.bytes.length };
  const session = (await cf(
    "POST",
    `/accounts/${a}/workers/scripts/${name}/assets-upload-session`,
    {
      manifest,
    },
  )) as { jwt?: string; buckets?: string[][] };
  let jwt = session.jwt ?? "";
  const buckets = (session.buckets ?? []).filter((b) => b.length > 0);
  if (buckets.length === 0) {
    if (!jwt) throw new CliError("Cloudflare returned no asset completion token. Try again.");
    return jwt;
  }
  const byHash = new Map(entries.map((e) => [e.hash, e]));
  for (const bucket of buckets) {
    const form = new FormData();
    for (const hash of bucket) {
      const e = byHash.get(hash);
      if (!e)
        throw new CliError(
          "Cloudflare asked for an asset that is not in the bundle. Nothing was deployed.",
        );
      form.append(
        hash,
        new File([Buffer.from(e.bytes).toString("base64")], hash, { type: contentType(e.rel) }),
        hash,
      );
    }
    const res = (await cf("POST", `/accounts/${a}/workers/assets/upload?base64=true`, form, {
      bearer: jwt,
    })) as { jwt?: string } | null;
    if (res?.jwt) jwt = res.jwt;
  }
  return jwt;
}

export interface WorkerBindings {
  databaseId: string;
  admin: string;
  access?: AccessInfo;
  assetsJwt: string;
}

/** Uploads the Worker module with its bindings, vars, and the assets completion token. */
export async function uploadWorker(
  cf: Cf,
  a: string,
  name: string,
  bundle: Bundle,
  b: WorkerBindings,
): Promise<void> {
  const m = bundle.manifest;
  const fixed: Record<string, string> = {
    ...m.vars,
    BOOTSTRAP_ADMIN_EMAIL: b.admin,
    ACCESS_TEAM_DOMAIN: b.access?.teamDomain ?? "",
    ACCESS_AUD: b.access?.aud ?? "",
  };
  const metadata = {
    main_module: basename(m.main),
    compatibility_date: m.compatibility_date,
    bindings: [
      { type: "d1", name: "DB", id: b.databaseId },
      { type: "assets", name: "ASSETS" },
      ...Object.entries(fixed).map(([k, v]) => ({ type: "plain_text", name: k, text: v })),
    ],
    assets: {
      jwt: b.assetsJwt,
      config: {
        not_found_handling: m.assets.not_found_handling,
        run_worker_first: m.assets.run_worker_first,
      },
    },
    observability: { enabled: true },
  };
  const form = new FormData();
  form.append(
    "metadata",
    new Blob([JSON.stringify(metadata)], { type: "application/json" }),
    "metadata.json",
  );
  const code = bundle.files.get(m.main) as Uint8Array;
  form.append(
    "index.js",
    new File([code as BlobPart], basename(m.main), { type: "application/javascript+module" }),
  );
  await cf("PUT", `/accounts/${a}/workers/scripts/${name}`, form);
}

/** Finds the zone that holds `hostname`, trying the name and then each parent. */
async function findZone(cf: Cf, a: string, hostname: string): Promise<string> {
  const labels = hostname.split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    const candidate = labels.slice(i).join(".");
    const zones = (await cf("GET", `/zones?name=${candidate}&account.id=${a}`)) as { id: string }[];
    if (zones[0]) return zones[0].id;
  }
  throw new CliError(
    `No zone for ${hostname} in this account. Add the domain to Cloudflare first.`,
  );
}

/** Writes host into .cfs.json, keeping any other keys. The file is not secret. */
export function setProjectHost(path: string, host: string): void {
  const existing = existsSync(path) ? readJsonFile(path) : {};
  if (typeof existing !== "object" || existing === null || Array.isArray(existing))
    throw new CliError(`${path} must be a JSON object.`);
  writeFileSync(path, `${JSON.stringify({ ...existing, host }, null, 2)}\n`);
}

/** The whole deploy. Idempotent: a second run finds what the first created and changes only what differs. */
export async function runDeploy(run: DeployRun, deps: DeployDeps): Promise<string | undefined> {
  if (run.dryRun) {
    for (const line of deployPlan(run)) deps.log(line);
    deps.log(
      "Dry run: no calls were made and nothing changed. Run again without --dry-run to deploy.",
    );
    return undefined;
  }
  const cf = deps.cf;
  const bundle = run.bundle;
  if (!cf || !bundle)
    throw new CliError("Internal error: deploy needs a Cloudflare client and a bundle.");

  let admin = run.admin;
  if (!admin) {
    if (!deps.interactive) throw new CliError("No admin email. Pass --admin you@example.com.");
    admin = await deps.ask("Admin email (becomes BOOTSTRAP_ADMIN_EMAIL): ");
  }
  admin = checkEmail(admin);

  const a = await resolveAccount(cf, run.account);
  deps.log(`Account ${a}`);
  // Read-only checks first, so a bad domain changes nothing in the account.
  const zone = run.domain ? await findZone(cf, a, run.domain) : undefined;
  const uuid = await ensureDatabase(cf, a, run.name);
  deps.log(`D1 database "${run.name}" ready`);
  const applied = await applyMigrations(cf, a, uuid, bundle, deps.log);
  deps.log(
    applied.length === 0 ? "Migrations up to date" : `${applied.length} migration(s) applied`,
  );

  let access: AccessInfo | undefined;
  if (run.domain) {
    access = await ensureAccess(cf, a, run.domain, admin);
    deps.log(`Access protects https://${run.domain}`);
  } else deps.log("Access not configured (no --domain)");

  const assetsJwt = await uploadAssets(cf, a, run.name, bundle);
  await uploadWorker(cf, a, run.name, bundle, { databaseId: uuid, admin, access, assetsJwt });
  deps.log(`Worker "${run.name}" uploaded`);

  await cf(
    "PUT",
    `/accounts/${a}/workers/scripts/${run.name}/schedules`,
    bundle.manifest.crons.map((cron) => ({ cron })),
  );

  let host: string;
  if (run.domain) {
    await cf("POST", `/accounts/${a}/workers/scripts/${run.name}/domains/changeset`, [
      { hostname: run.domain, zone_id: zone, enabled: true, previews_enabled: false },
    ]);
    host = `https://${run.domain}`;
  } else {
    const sub = (await cf("GET", `/accounts/${a}/workers/subdomain`)) as { subdomain: string };
    await cf("POST", `/accounts/${a}/workers/scripts/${run.name}/subdomain`, {
      enabled: true,
      previews_enabled: false,
    });
    host = `https://${run.name}.${sub.subdomain}.workers.dev`;
  }
  setProjectHost(run.projectPath, host);

  deps.log("");
  deps.log(`Deployed ${bundle.manifest.version} to ${host}.`);
  deps.log("First run:");
  deps.log(
    `  1. Open ${host} and sign in as ${admin}. The first sign-in with BOOTSTRAP_ADMIN_EMAIL becomes admin.`,
  );
  deps.log(`  2. Run: cfs login --host ${host}, then set your vault password.`);
  if (run.domain)
    deps.log(
      `  3. To let others sign in, add them to the "cfs admin" Access policy in the Cloudflare dashboard, then invite them.`,
    );
  else
    deps.log(
      "  3. Without --domain the web UI is not behind Cloudflare Access. Add a domain, or protect it yourself.",
    );
  deps.log("Run this command again to upgrade. Migrations are forward only.");
  return host;
}

// ---------------------------------------------------------------- deploy command

function takeBool(args: string[], name: string): boolean {
  const i = args.indexOf(name);
  if (i < 0) return false;
  args.splice(i, 1);
  return true;
}

async function deployCommand(args: string[]): Promise<void> {
  const dryRun = takeBool(args, "--dry-run");
  const domain = flag(args, "--domain");
  const account = flag(args, "--account") ?? process.env.CLOUDFLARE_ACCOUNT_ID;
  const name = flag(args, "--name") ?? DEFAULT_WORKER;
  const admin = flag(args, "--admin");
  const bundlePath = flag(args, "--bundle");
  const version = flag(args, "--version");
  if (args.length > 0) throw new CliError(`Unknown option ${args[0]}. See: cfs help`);
  if (version && !/^v?\d+\.\d+\.\d+/.test(version))
    throw new CliError(`"${version}" is not a version. Use a form such as v0.2.0.`);
  const tag = version ? (version.startsWith("v") ? version : `v${version}`) : undefined;
  const run: DeployRun = {
    name: checkWorkerName(name),
    domain: domain ? checkDomain(domain) : undefined,
    account: account?.trim() || undefined,
    admin,
    dryRun,
    bundleSource: bundlePath ?? (tag ? `release ${tag}` : "latest release"),
    projectPath: join(process.cwd(), ".cfs.json"),
  };
  if (account && !/^[0-9a-f]{32}$/i.test(account))
    throw new CliError(
      "The account id is 32 hex characters. Find it on the Cloudflare dashboard home page.",
    );

  const token = process.env[TOKEN_ENV];
  if (!dryRun && !token)
    throw new CliError(
      `Set ${TOKEN_ENV} to a Cloudflare API token. It is read from the environment only and is never printed.`,
    );

  const deps: DeployDeps = {
    interactive: Boolean(process.stdin.isTTY),
    ask,
    log: (line) => console.log(line),
    cf: dryRun || !token ? undefined : makeCf(token),
  };

  let unpacked: string | undefined;
  try {
    if (bundlePath) run.bundle = await loadBundle(bundlePath);
    else if (!dryRun) {
      unpacked = await downloadBundle(fetch, tag);
      run.bundle = await loadBundle(join(unpacked, BUNDLE_NAME));
    }
    await runDeploy(run, deps);
  } finally {
    if (unpacked) rmSync(unpacked, { recursive: true, force: true });
  }
}

export const deploy: Commands = {
  deploy: {
    help: "cfs deploy [--domain d] [--account id] [--admin email] [--name w] [--bundle f] [--dry-run]",
    run: (a) => deployCommand(a),
  },
  init: {
    help: "cfs init [--host <url>] [--project <name>]   write .cfs.json here",
    run: (a, h) => init(a, h),
  },
  upgrade: {
    help: "cfs upgrade [--version <tag>]        replace cfs with the latest release",
    run: (a) => upgrade(a),
  },
};
