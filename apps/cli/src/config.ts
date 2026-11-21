import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

// ADR 13 (host precedence, .cfs.json), ADR 12 (session file), ADR 25 (https only, trust,
// profiles, explicit envs, 0600 files). Nothing in this file prints or logs secrets.

export class CliError extends Error {}

export const configDir = (): string =>
  process.env.CFS_CONFIG_DIR ?? join(homedir(), ".config", "cfs");

/** Writes a JSON file that only the owner can read. */
export function writePrivate(path: string, data: unknown): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
}

/** Returns undefined when the file is missing. Throws when it exists but is not JSON. */
export function readJsonFile(path: string): unknown {
  if (!existsSync(path)) return undefined;
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new CliError(`${path} is not valid JSON. Fix it or delete it.`);
  }
}

// ---------------------------------------------------------------- URLs and hosts

const LOCAL_HOSTNAMES = new Set(["localhost", "127.0.0.1"]);

/** Parses a server URL. https only; http is allowed for localhost and 127.0.0.1 (development). */
export function secureUrl(input: string): URL {
  let u: URL;
  try {
    u = new URL(input.trim());
  } catch {
    throw new CliError(
      `"${input}" is not a URL. Use a full address such as https://vault.example.com`,
    );
  }
  const local = u.protocol === "http:" && LOCAL_HOSTNAMES.has(u.hostname);
  if (u.protocol !== "https:" && !local)
    throw new CliError(
      `"${input}" must start with https:// (http:// is allowed only for localhost and 127.0.0.1).`,
    );
  if (u.username || u.password)
    throw new CliError(`"${input}" must not contain a username or password.`);
  return u;
}

/** Normalises a server address to its origin, e.g. "https://vault.example.com/". */
export function normalizeHost(input: string): string {
  const u = secureUrl(input);
  if ((u.pathname !== "/" && u.pathname !== "") || u.search || u.hash)
    throw new CliError(`"${input}" must be the server address only, without a path.`);
  return u.origin;
}

// ---------------------------------------------------------------- user config and profiles

export interface UserConfig {
  defaultProfile?: string;
  profiles: Record<string, { host: string }>;
  /** Hosts this device has signed in to (or confirmed with the trust prompt). */
  trusted: string[];
}

const userConfigPath = () => join(configDir(), "config.json");

/** Reads ~/.config/cfs/config.json. A single `host` from earlier versions becomes profile "default". */
export function loadUserConfig(): UserConfig {
  const raw = (readJsonFile(userConfigPath()) ?? {}) as {
    defaultProfile?: string;
    profiles?: Record<string, { host: string }>;
    trusted?: string[];
    host?: string;
  };
  const cfg: UserConfig = {
    defaultProfile: raw.defaultProfile,
    profiles: { ...(raw.profiles ?? {}) },
    trusted: [...(raw.trusted ?? [])],
  };
  if (raw.host) {
    cfg.profiles.default ??= { host: raw.host };
    if (!cfg.trusted.includes(raw.host)) cfg.trusted.push(raw.host);
  }
  return cfg;
}

function saveUserConfig(cfg: UserConfig): void {
  writePrivate(userConfigPath(), cfg);
}

let selectedProfile: string | undefined;
/** Set from the global --profile flag. */
export function useProfile(name: string | undefined): void {
  selectedProfile = name || undefined;
}
export const currentProfile = (): string | undefined => selectedProfile;

export function isTrusted(host: string): boolean {
  return loadUserConfig().trusted.includes(host);
}

/** Records that this device may use the host without asking again. */
export function trustHost(host: string): void {
  const cfg = loadUserConfig();
  if (cfg.trusted.includes(host)) return;
  cfg.trusted.push(host);
  saveUserConfig(cfg);
}

/** Saves a named profile, makes it the default and trusts its host. */
export function saveProfile(name: string, host: string): void {
  const cfg = loadUserConfig();
  cfg.profiles[name] = { host };
  cfg.defaultProfile = name;
  if (!cfg.trusted.includes(host)) cfg.trusted.push(host);
  saveUserConfig(cfg);
}

// ---------------------------------------------------------------- .cfs.json

export interface ProjectFile {
  host?: string;
  project?: string;
  /** Default env for `cfs run` when --env is not given. */
  default?: string;
  /** Ordered secret lists per env; later entries override earlier ones. */
  envs?: Record<string, string[]>;
}

function parseProjectFile(raw: unknown, path: string): ProjectFile {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw))
    throw new CliError(`${path} must be a JSON object.`);
  const f = raw as Record<string, unknown>;
  const text = (key: string): string | undefined => {
    const v = f[key];
    if (v === undefined) return undefined;
    if (typeof v !== "string") throw new CliError(`${path}: "${key}" must be a string.`);
    return v;
  };
  const out: ProjectFile = {
    host: text("host"),
    project: text("project"),
    default: text("default"),
  };
  if (f.envs !== undefined) {
    if (typeof f.envs !== "object" || f.envs === null || Array.isArray(f.envs))
      throw new CliError(`${path}: "envs" must be an object of env name to secret list.`);
    out.envs = {};
    for (const [name, list] of Object.entries(f.envs)) {
      if (!Array.isArray(list) || !list.every((x) => typeof x === "string" && x.includes("/")))
        throw new CliError(
          `${path}: envs.${name} must be a list of secret paths such as "myapp/dev".`,
        );
      out.envs[name] = list as string[];
    }
  }
  return out;
}

/** Looks for .cfs.json in the folder and its parents, like git does. */
export function projectFile(cwd = process.cwd()): ProjectFile {
  let d = cwd;
  for (;;) {
    const p = join(d, ".cfs.json");
    if (existsSync(p)) return parseProjectFile(readJsonFile(p), p);
    const up = dirname(d);
    if (up === d) return {};
    d = up;
  }
}

/**
 * The secrets `cfs run` loads, in order. Explicit `envs` in .cfs.json win over the
 * minimal { project } form, which maps to <project>/<env>.
 */
export function runPaths(file: ProjectFile, flagEnv?: string): { env: string; paths: string[] } {
  const env = flagEnv ?? file.default ?? "dev";
  if (file.envs) {
    const list = file.envs[env];
    if (!list)
      throw new CliError(
        `No env "${env}" in .cfs.json. Defined: ${Object.keys(file.envs).join(", ") || "none"}.`,
      );
    if (list.length === 0) throw new CliError(`env "${env}" in .cfs.json lists no secrets.`);
    return { env, paths: [...list] };
  }
  if (!file.project)
    throw new CliError(
      "No secret given and no project in .cfs.json. Run: cfs init, or name a secret: cfs run <project>/<env> -- cmd",
    );
  return { env, paths: [`${file.project}/${env}`] };
}

/**
 * Opens every secret in order and merges the values; later secrets override earlier ones.
 * If one cannot be opened, nothing is returned and the error names that secret.
 */
export async function mergeSecrets(
  paths: string[],
  read: (path: string) => Promise<Record<string, string>>,
  env: string,
): Promise<Record<string, string>> {
  const merged: Record<string, string> = {};
  for (const path of paths) {
    let values: Record<string, string>;
    try {
      values = await read(path);
    } catch (e) {
      const why = e instanceof Error ? e.message : String(e);
      throw new CliError(
        `Could not load "${path}" for env "${env}" from .cfs.json: ${why} Nothing was loaded.`,
      );
    }
    Object.assign(merged, values);
  }
  return merged;
}

// ---------------------------------------------------------------- host resolution and trust

export type HostSource = "flag" | "env" | "project" | "profile";
export interface ResolvedHost {
  host: string;
  source: HostSource;
}

/**
 * Host precedence (ADR 13, ADR 25): --host flag, then CFS_HOST, then .cfs.json, then the
 * profile chosen with --profile (or the default profile). Every value must be https.
 */
export function resolveHost(
  flagHost?: string,
  opts: { cwd?: string; env?: Record<string, string | undefined> } = {},
): ResolvedHost | undefined {
  const env = opts.env ?? process.env;
  if (flagHost) return { host: normalizeHost(flagHost), source: "flag" };
  if (env.CFS_HOST) return { host: normalizeHost(env.CFS_HOST), source: "env" };
  const fromFile = projectFile(opts.cwd).host;
  if (fromFile) return { host: normalizeHost(fromFile), source: "project" };
  const cfg = loadUserConfig();
  const name = selectedProfile ?? cfg.defaultProfile ?? "default";
  const profile = cfg.profiles[name];
  if (!profile) {
    if (selectedProfile)
      throw new CliError(
        `No profile "${selectedProfile}". Run: cfs login --profile ${selectedProfile} --host https://your-server`,
      );
    return undefined;
  }
  return { host: normalizeHost(profile.host), source: "profile" };
}

export interface TrustDeps {
  /** False when there is no terminal to ask in. */
  interactive: boolean;
  confirm(question: string): Promise<boolean>;
  signIn(host: string): Promise<void>;
}

/**
 * A host from CFS_HOST or .cfs.json that this device never signed in to is not used until
 * the user answers "Sign in to <host>? (y/N)". A yes signs in and saves the host as trusted.
 * Flags and profiles are trusted already.
 */
export async function ensureTrusted(r: ResolvedHost, deps: TrustDeps): Promise<void> {
  if (r.source === "flag" || r.source === "profile" || isTrusted(r.host)) return;
  const where = r.source === "env" ? "CFS_HOST" : ".cfs.json";
  if (!deps.interactive)
    throw new CliError(
      `${r.host} (from ${where}) is not trusted on this device yet. Run in a terminal: cfs login --host ${r.host}`,
    );
  const yes = await deps.confirm(`Sign in to ${r.host}? (y/N) `);
  if (!yes) throw new CliError(`Not signing in to ${r.host}. Nothing was changed.`);
  await deps.signIn(r.host);
  trustHost(r.host);
}

// ---------------------------------------------------------------- session (ADR 12, 25)

export interface Session {
  host: string;
  token: string;
  expiresAt: number; // unix seconds
}

const sessionPath = () => join(configDir(), "session.json");

export function loadSession(now = Date.now()): Session | undefined {
  try {
    const s = readJsonFile(sessionPath()) as Session | undefined;
    return s && s.expiresAt > now / 1000 ? s : undefined;
  } catch {
    return undefined;
  }
}

/** Writes only host, token and expiry. The unlocked key is kept by the keychain module. */
export function saveSession(s: Session): void {
  writePrivate(sessionPath(), { host: s.host, token: s.token, expiresAt: s.expiresAt });
}
