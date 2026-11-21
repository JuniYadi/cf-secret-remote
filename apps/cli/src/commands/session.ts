import { unlockPrivateKey } from "@cfs/core";
import { flag } from "../args.ts";
import { CliError, connect } from "../client.ts";
import { currentProfile, loadSession, resolveHost, saveSession } from "../config.ts";
import { clearUnlock, DEFAULT_TTL, parseTtl, pickStore, saveUnlock } from "../keychain.ts";
import { askHidden } from "../prompt.ts";
import { signIn } from "../signin.ts";
import type { Commands } from "./types.ts";

async function login(hostFlag?: string) {
  const resolved = resolveHost(hostFlag);
  if (!resolved)
    throw new CliError("Which server? Run: cfs login --host https://secrets.example.com");
  // Signing in is what trusts the host, so any source is fine here.
  await signIn(resolved.host, currentProfile() ?? new URL(resolved.host).hostname);
}

async function unlock(hostFlag?: string, args: string[] = []) {
  const ttl = parseTtl(flag(args, "--ttl") ?? DEFAULT_TTL);
  const c = await connect(hostFlag);
  const me = await c.call<{ vaultReady: boolean; lockedKey: string | null }>("GET", "/whoami");
  if (!me.body.vaultReady || !me.body.lockedKey)
    throw new CliError(
      "Your vault is not set up yet. Open the web app and choose a vault password first.",
    );
  const pw = await askHidden("Vault password: ");
  let key: string;
  try {
    key = await unlockPrivateKey(me.body.lockedKey, pw);
  } catch {
    throw new CliError("That vault password did not work.");
  }
  const expiresAt = await saveUnlock(pickStore(), c.host, key, ttl);
  console.log(
    `Unlocked until ${new Date(expiresAt).toLocaleTimeString()}. Run cfs lock to end it sooner.`,
  );
}

export const session: Commands = {
  login: {
    help: "cfs login [--host <url>] [--profile <name>]   sign in with your browser",
    run: (_a, h) => login(h),
  },
  unlock: {
    help: "cfs unlock [--ttl 1h]               unlock your vault on this device",
    run: (a, h) => unlock(h, a),
  },
  lock: {
    help: "cfs lock                            forget the unlocked vault",
    run: async () => {
      const s = loadSession();
      if (s) {
        await clearUnlock(pickStore(), s.host);
        // Rewrites the session file without anything but host, token and expiry.
        saveSession(s);
      }
      console.log("Locked.");
    },
  },
  whoami: {
    help: "cfs whoami",
    run: async (_a, h) => {
      const c = await connect(h);
      const w = await c.call<{ name: string; kind: string; role: string }>("GET", "/whoami");
      const unlocked = c.privateKey !== undefined;
      console.log(
        `${w.body.name} (${w.body.kind}, ${w.body.role}) on ${c.host}${unlocked ? ", vault unlocked" : ", vault locked"}`,
      );
    },
  },
};
