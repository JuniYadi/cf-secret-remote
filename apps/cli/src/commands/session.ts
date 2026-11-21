import { unlockPrivateKey } from "@cfs/core";
import { flag } from "../args.ts";
import { anonymous, CliError, connect } from "../client.ts";
import { clearSession, loadSession, resolveHost, saveHost, saveSession } from "../config.ts";
import { askHidden } from "../prompt.ts";
import type { Commands } from "./types.ts";

async function login(args: string[]) {
  const host = resolveHost(flag(args, "--host"));
  if (!host) throw new CliError("Which server? Run: cfs login --host https://secrets.example.com");
  const api = anonymous(host);
  const start = await api.call<{
    deviceCode: string;
    userCode: string;
    expiresIn: number;
    interval: number;
  }>("POST", "/cli/start", { device: process.env.HOSTNAME ?? "cli" });
  if (start.status !== 200) throw new CliError("The server did not start a login.");
  console.log(`Open ${host}/cli/authorize and enter this code:\n\n    ${start.body.userCode}\n`);
  const until = Date.now() + start.body.expiresIn * 1000;
  while (Date.now() < until) {
    await Bun.sleep(start.body.interval * 1000);
    const p = await api.call<{ token?: string; expiresIn?: number }>("POST", "/cli/poll", {
      deviceCode: start.body.deviceCode,
    });
    if (p.status === 200 && p.body.token) {
      saveHost(host);
      saveSession({
        host,
        token: p.body.token,
        expiresAt: Math.floor(Date.now() / 1000) + (p.body.expiresIn ?? 3600),
      });
      console.log("Signed in. Next: cfs unlock");
      return;
    }
    if (p.status === 410) break;
  }
  throw new CliError("The code expired. Run cfs login again.");
}

async function unlock() {
  const c = await connect();
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
  const s = loadSession();
  if (!s) throw new CliError("Not signed in.");
  saveSession({ ...s, privateKey: key });
  console.log("Unlocked until your session ends.");
}

export const session: Commands = {
  login: {
    help: "cfs login [--host <url>]            sign in with your browser",
    run: (a, h) => login(h ? ["--host", h, ...a] : a),
  },
  unlock: {
    help: "cfs unlock                          unlock your vault on this device",
    run: () => unlock(),
  },
  lock: {
    help: "cfs lock                            forget the unlocked vault",
    run: () => {
      clearSession();
      console.log("Locked.");
    },
  },
  whoami: {
    help: "cfs whoami",
    run: async (_a, h) => {
      const c = await connect(h);
      const w = await c.call<{ name: string; kind: string; role: string }>("GET", "/whoami");
      console.log(
        `${w.body.name} (${w.body.kind}, ${w.body.role}) on ${c.host}${c.privateKey ? ", vault unlocked" : ", vault locked"}`,
      );
    },
  },
};
