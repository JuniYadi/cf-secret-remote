import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

// ADR 13 (host and project) and ADR 12 (local session state).
const dir = process.env.CFS_CONFIG_DIR ?? join(homedir(), ".config", "cfs");
const read = <T>(p: string): T | undefined => {
  try {
    return existsSync(p) ? (JSON.parse(readFileSync(p, "utf8")) as T) : undefined;
  } catch {
    return undefined;
  }
};

export interface ProjectFile {
  host?: string;
  project?: string;
}

/** Looks for .cfs.json in the current folder and its parents. */
export function projectFile(): ProjectFile {
  let d = process.cwd();
  for (;;) {
    const f = read<ProjectFile>(join(d, ".cfs.json"));
    if (f) return f;
    const up = dirname(d);
    if (up === d) return {};
    d = up;
  }
}

export function resolveHost(flag?: string): string | undefined {
  const h =
    flag ??
    process.env.CFS_HOST ??
    projectFile().host ??
    read<{ host?: string }>(join(dir, "config.json"))?.host;
  return h?.replace(/\/+$/, "");
}

export function saveHost(host: string): void {
  write(join(dir, "config.json"), { host });
}

export interface Session {
  host: string;
  token: string;
  expiresAt: number; // unix seconds
  privateKey?: string; // set by `cfs unlock`
}

const sessionPath = join(dir, "session.json");
export const loadSession = (): Session | undefined => {
  const s = read<Session>(sessionPath);
  return s && s.expiresAt > Date.now() / 1000 ? s : undefined;
};
export const saveSession = (s: Session): void => write(sessionPath, s);
export const clearSession = (): void => {
  const s = read<Session>(sessionPath);
  if (s) saveSession({ ...s, privateKey: undefined });
};

function write(path: string, data: unknown): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, JSON.stringify(data, null, 2), { mode: 0o600 });
  chmodSync(path, 0o600);
}
