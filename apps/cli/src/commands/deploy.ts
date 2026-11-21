import { chmodSync, existsSync, renameSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { flag } from "../args.ts";
import { CliError, normalizeHost, resolveHost, secureUrl } from "../config.ts";
import { ask, confirm } from "../prompt.ts";
import type { Fetch } from "../server.ts";
import type { Commands } from "./types.ts";

// ADR 25: `cfs init` writes .cfs.json, `cfs upgrade` replaces this binary after a checksum
// check. `cfs deploy` belongs to the next issue and is not here.

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

export const deploy: Commands = {
  init: {
    help: "cfs init [--host <url>] [--project <name>]   write .cfs.json here",
    run: (a, h) => init(a, h),
  },
  upgrade: {
    help: "cfs upgrade [--version <tag>]        replace cfs with the latest release",
    run: (a) => upgrade(a),
  },
};
