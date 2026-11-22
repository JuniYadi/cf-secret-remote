import { join } from "node:path";
import { configDir, readJsonFile, writePrivate } from "./config.ts";

// ADR 25: the unlocked private key lives in the OS keychain (macOS `security`, Linux
// `secret-tool`), with a 0600 file as the fallback. The secret always goes through stdin,
// never through a command line, so it cannot be read from `ps`.

export interface SecretStore {
  readonly kind: string;
  get(account: string): Promise<string | undefined>;
  set(account: string, value: string): Promise<void>;
  delete(account: string): Promise<void>;
}

export interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}
/** Runs a program. `stdin`, when given, is written to the program's standard input. */
export type Runner = (argv: string[], stdin?: string) => Promise<RunResult>;

const SERVICE = "cfs";
const NOT_FOUND = /could not be found/i;

export const runProcess: Runner = async (argv, stdin) => {
  const proc = Bun.spawn(argv, {
    stdin: stdin === undefined ? "ignore" : new Blob([stdin]),
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  return { code, stdout, stderr };
};

/** macOS Keychain through `security`. The value goes in via `security -i` on stdin, hex encoded. */
export function macKeychain(run: Runner): SecretStore {
  const get = async (account: string): Promise<string | undefined> => {
    const r = await run(["security", "find-generic-password", "-s", SERVICE, "-a", account, "-w"]);
    if (r.code === 0) return r.stdout.replace(/\r?\n$/, "");
    if (NOT_FOUND.test(r.stderr)) return undefined;
    throw new Error("The macOS keychain could not be read.");
  };
  return {
    kind: "macos-keychain",
    get,
    async set(account, value) {
      const hex = Buffer.from(value, "utf8").toString("hex");
      await run(
        ["security", "-i"],
        `add-generic-password -U -s ${SERVICE} -a ${account} -X ${hex}\n`,
      );
      if ((await get(account)) !== value)
        throw new Error("The macOS keychain did not keep the value.");
    },
    async delete(account) {
      const r = await run(["security", "delete-generic-password", "-s", SERVICE, "-a", account]);
      if (r.code !== 0 && !NOT_FOUND.test(r.stderr))
        throw new Error("The macOS keychain could not delete the entry.");
    },
  };
}

/** Linux Secret Service through `secret-tool`. The value is written to stdin. */
export function secretTool(run: Runner): SecretStore {
  const attrs = (account: string) => ["service", SERVICE, "account", account];
  const get = async (account: string): Promise<string | undefined> => {
    const r = await run(["secret-tool", "lookup", ...attrs(account)]);
    return r.code === 0 ? r.stdout : undefined;
  };
  return {
    kind: "secret-tool",
    get,
    async set(account, value) {
      await run(["secret-tool", "store", "--label=cfs unlock", ...attrs(account)], value);
      if ((await get(account)) !== value)
        throw new Error("The Secret Service did not keep the value.");
    },
    async delete(account) {
      await run(["secret-tool", "clear", ...attrs(account)]);
    },
  };
}

/** A 0600 JSON file in the config folder. Used when no OS keychain is available. */
export function fileStore(
  path: () => string = () => join(configDir(), "unlock.json"),
): SecretStore {
  const load = (): Record<string, string> => {
    try {
      return (readJsonFile(path()) ?? {}) as Record<string, string>;
    } catch {
      return {};
    }
  };
  return {
    kind: "file",
    async get(account) {
      return load()[account];
    },
    async set(account, value) {
      writePrivate(path(), { ...load(), [account]: value });
    },
    async delete(account) {
      const all = load();
      if (!(account in all)) return;
      delete all[account];
      writePrivate(path(), all);
    },
  };
}

/** Uses the primary store, and the fallback when the primary fails. Never keeps two copies. */
export function withFallback(primary: SecretStore, fallback: SecretStore): SecretStore {
  return {
    kind: primary.kind,
    async get(account) {
      try {
        const v = await primary.get(account);
        if (v !== undefined) return v;
      } catch {
        // fall through to the fallback
      }
      return fallback.get(account);
    },
    async set(account, value) {
      try {
        await primary.set(account, value);
        await fallback.delete(account);
      } catch {
        await primary.delete(account).catch(() => undefined);
        await fallback.set(account, value);
      }
    },
    async delete(account) {
      await Promise.allSettled([primary.delete(account), fallback.delete(account)]);
    },
  };
}

export interface PickDeps {
  platform?: string;
  which?: (bin: string) => string | null | undefined;
  run?: Runner;
}

/** The best store on this machine. The 0600 file is used when no keychain tool exists. */
export function pickStore(deps: PickDeps = {}): SecretStore {
  const platform = deps.platform ?? process.platform;
  const which = deps.which ?? ((bin: string) => Bun.which(bin));
  const run = deps.run ?? runProcess;
  const file = fileStore();
  // ADR 26: CFS_UNLOCK_STORE=file keeps the end-to-end script away from the real OS keychain.
  if (process.env.CFS_UNLOCK_STORE === "file") return file;
  if (platform === "darwin" && which("security")) return withFallback(macKeychain(run), file);
  if (platform === "linux" && which("secret-tool")) return withFallback(secretTool(run), file);
  return file;
}

// ---------------------------------------------------------------- unlocked key with a TTL

export const DEFAULT_TTL = "24h";

/** "90s", "30m", "1h", "2d" or plain seconds. Returns seconds. */
export function parseTtl(text: string): number {
  const m = /^(\d+)([smhd]?)$/.exec(text.trim());
  if (!m) throw new Error(`--ttl "${text}" is not a duration. Use 90s, 30m, 1h or 2d.`);
  const n = Number(m[1]);
  if (n <= 0) throw new Error("--ttl must be longer than zero.");
  const unit = { "": 1, s: 1, m: 60, h: 3600, d: 86400 }[m[2] ?? ""] ?? 1;
  return n * unit;
}

/** One entry per server, so two hosts never share an unlocked key. */
export const unlockAccount = (host: string): string =>
  `unlock-${Buffer.from(host, "utf8").toString("hex")}`;

interface UnlockRecord {
  privateKey: string;
  expiresAt: number; // unix ms
}

/** Stores the unlocked private key for `ttlSeconds`. Returns the expiry time in unix ms. */
export async function saveUnlock(
  store: SecretStore,
  host: string,
  privateKey: string,
  ttlSeconds: number,
  now = Date.now(),
): Promise<number> {
  const expiresAt = now + ttlSeconds * 1000;
  const record: UnlockRecord = { privateKey, expiresAt };
  await store.set(unlockAccount(host), JSON.stringify(record));
  return expiresAt;
}

/** Returns the unlocked key while its TTL runs. Expired entries are deleted. */
export async function loadUnlock(
  store: SecretStore,
  host: string,
  now = Date.now(),
): Promise<string | undefined> {
  const account = unlockAccount(host);
  const raw = await store.get(account);
  if (raw === undefined) return undefined;
  let rec: Partial<UnlockRecord>;
  try {
    rec = JSON.parse(raw) as Partial<UnlockRecord>;
  } catch {
    await store.delete(account);
    return undefined;
  }
  if (typeof rec.privateKey !== "string" || typeof rec.expiresAt !== "number") {
    await store.delete(account);
    return undefined;
  }
  if (rec.expiresAt <= now) {
    await store.delete(account);
    return undefined;
  }
  return rec.privateKey;
}

export const clearUnlock = (store: SecretStore, host: string): Promise<void> =>
  store.delete(unlockAccount(host));
