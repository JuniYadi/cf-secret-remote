import { readFileSync, writeFileSync } from "node:fs";
import {
  fingerprintWords,
  generateKeyPair,
  lockPrivateKey,
  lockWithRecoveryKey,
  newRecoveryKey,
  normalizeWords,
  recoveryEntropy,
  recoveryPhrase,
  unlockPrivateKey,
  unlockWithRecoveryKey,
  unwrapGroupKey,
  wrapGroupKey,
} from "@cfs/core";
import { CliError, type Client, connect } from "../client.ts";
import { ask, askHidden } from "../prompt.ts";
import type { Commands } from "./types.ts";

// ADR 20: forgotten vault password (`cfs recover`, `cfs recover grant <id>`) and changing it (`cfs passwd`).
// The functions take a Client so tests can use a fake one. Passwords and keys are never printed.

export const MIN_PASSWORD_LENGTH = 8;

const failWith = (status: number, body: unknown, what: string): never => {
  const msg = (body as { error?: string } | null)?.error ?? `status ${status}`;
  if (status === 401) throw new CliError("Your session ended. Run: cfs login");
  if (status === 403) throw new CliError(`Not allowed: ${what}. ${msg}`);
  throw new CliError(`${what}: ${msg}`);
};

function checkNewPassword(pw: string, previous?: string) {
  if (pw.length < MIN_PASSWORD_LENGTH)
    throw new CliError(`The vault password needs at least ${MIN_PASSWORD_LENGTH} characters.`);
  if (previous !== undefined && pw === previous)
    throw new CliError("Choose a password that is different from the current one.");
}

/**
 * Step 2 of the forgot-password flow. Makes a new key pair, locks it with the new vault password and asks
 * the server for a request. `accessToken` is a Cloudflare Access token from a fresh login (the server
 * refuses anything older than 5 minutes). Returns the request id and the four words to read to an admin.
 */
export async function startRecovery(
  c: Client,
  accessToken: string | undefined,
  newPassword: string,
): Promise<{ id: string; words: string }> {
  if (!accessToken)
    throw new CliError(
      "Recovery needs a fresh browser sign-in. Get a token with: cloudflared access token -app=<your app URL>, then set CFS_ACCESS_TOKEN.",
    );
  checkNewPassword(newPassword);
  const kp = await generateKeyPair();
  const lockedKey = await lockPrivateKey(kp.privateKey, newPassword);
  const r = await c.call<{ id?: string; words?: string }>(
    "POST",
    "/recovery/request",
    { publicKey: kp.publicKey, lockedKey },
    { "Cf-Access-Jwt-Assertion": accessToken },
  );
  if (r.status !== 201 || !r.body.id || !r.body.words) failWith(r.status, r.body, "start recovery");
  // The cancel token is not printed: it is for the "Not me" link, which needs the email feature.
  return { id: r.body.id as string, words: r.body.words as string };
}

/**
 * Admin grant. Compares the typed words with the request's key locally first. The typed words are sent
 * either way, so a wrong code is counted on the server. Only when they match are the groups the admin
 * holds re-wrapped to the new key. Groups the admin does not hold are left for another admin.
 */
export async function grantRecovery(
  c: Client,
  id: string,
  typedWords: string,
): Promise<{ granted: string[]; notRewrapped: string[] }> {
  if (!c.privateKey) throw new CliError("Your vault is locked. Run: cfs unlock");
  const req = await c.call<{ publicKey: string; groups: string[] }>("GET", `/recovery/${id}`);
  if (req.status === 404) throw new CliError("No such recovery request.");
  if (req.status !== 200) failWith(req.status, req.body, "load request");

  const typed = normalizeWords(typedWords);
  const matches = typed === (await fingerprintWords(req.body.publicKey));
  const keys: { prefix: string; version: number; wrappedKey: string }[] = [];
  const notRewrapped: string[] = [];
  if (matches) {
    const me = await c.call<{ publicKey: string | null }>("GET", "/whoami");
    if (!me.body.publicKey) throw new CliError("Your vault is not set up.");
    for (const prefix of req.body.groups) {
      const k = await c.call<{ wrappedKey: string; version: number }>(
        "GET",
        `/keyrings/${prefix}/key`,
      );
      if (k.status !== 200) {
        notRewrapped.push(prefix);
        continue;
      }
      const groupKey = await unwrapGroupKey(
        k.body.wrappedKey,
        c.privateKey,
        me.body.publicKey,
        prefix,
        k.body.version,
      );
      keys.push({
        prefix,
        version: k.body.version,
        wrappedKey: await wrapGroupKey(groupKey, req.body.publicKey, prefix, k.body.version),
      });
    }
  }

  const r = await c.call<{ groups?: string[]; attemptsLeft?: number; locked?: boolean }>(
    "POST",
    `/recovery/${id}/grant`,
    { words: typed, keys },
  );
  if (r.status === 403 && !matches) {
    if (r.body.locked)
      throw new CliError(
        "Too many wrong codes. The request is locked; the person must start again.",
      );
    throw new CliError(`The four words do not match. ${r.body.attemptsLeft ?? 0} attempts left.`);
  }
  if (r.status !== 200) failWith(r.status, r.body, "grant recovery");
  return { granted: r.body.groups ?? [], notRewrapped };
}

/** Changes the vault password. The same private key is locked again with the new password. */
export async function changePassword(c: Client, oldPassword: string, newPassword: string) {
  checkNewPassword(newPassword, oldPassword);
  const me = await c.call<{ lockedKey: string | null }>("GET", "/whoami");
  if (!me.body.lockedKey)
    throw new CliError("Your vault is not set up yet. Open the web app first.");
  let privateKey: string;
  try {
    privateKey = await unlockPrivateKey(me.body.lockedKey, oldPassword);
  } catch {
    throw new CliError("That vault password did not work.");
  }
  const lockedKey = await lockPrivateKey(privateKey, newPassword);
  const r = await c.call("PUT", "/me/vault", { lockedKey });
  if (r.status !== 200) failWith(r.status, r.body, "change password");
}

async function recover(args: string[], hostFlag?: string) {
  if (args[0] === "grant") {
    const id = args[1];
    if (!id) throw new CliError("Usage: cfs recover grant <request id>");
    const c = await connect(hostFlag);
    const words = await ask("Four words from the person: ");
    const out = await grantRecovery(c, id, words);
    console.log(`Access given again for ${out.granted.length} group(s).`);
    if (out.notRewrapped.length)
      console.log(
        `Not re-wrapped (you are not in them): ${out.notRewrapped.join(", ")}. Another admin must grant those.`,
      );
    return;
  }
  const c = await connect(hostFlag);
  const pw = await askHidden("New vault password: ", "CFS_NEW_PASSWORD");
  const again = await askHidden("Repeat it: ", "CFS_NEW_PASSWORD");
  if (pw !== again) throw new CliError("The two passwords do not match.");
  const { id, words } = await startRecovery(c, process.env.CFS_ACCESS_TOKEN, pw);
  console.log(
    `Recovery started. Read these four words to an admin over a channel you trust:\n\n    ${words}\n\nRequest id: ${id}\nWhen the admin has granted access, sign in and run: cfs unlock`,
  );
}

async function passwd(hostFlag?: string) {
  const c = await connect(hostFlag);
  const oldPw = await askHidden("Current vault password: ");
  const newPw = await askHidden("New vault password: ", "CFS_NEW_PASSWORD");
  const again = await askHidden("Repeat the new password: ", "CFS_NEW_PASSWORD");
  if (newPw !== again) throw new CliError("The two new passwords do not match.");
  await changePassword(c, oldPw, newPw);
  console.log("Vault password changed. Your group access is unchanged.");
}

/** Stores the recovery phrase in a new owner-only file before replacing the server lock. */
export async function setRecoveryKey(c: Client, privateKey: string, file: string) {
  const entropy = newRecoveryKey();
  const phrase = await recoveryPhrase(entropy);
  const lockedKey = await lockWithRecoveryKey(privateKey, entropy);
  writeFileSync(file, `${phrase}\n`, { mode: 0o600, flag: "wx" });
  const r = await c.call("PUT", "/me/recovery", { lockedKey });
  if (r.status !== 200) failWith(r.status, r.body, "set recovery key");
}

export async function useRecoveryKey(c: Client, phrase: string, password: string, newFile: string) {
  checkNewPassword(password);
  const r = await c.call<{ lockedKey: string | null }>("GET", "/me/recovery");
  if (r.status !== 200) failWith(r.status, r.body, "load recovery key");
  if (!r.body.lockedKey) throw new CliError("No recovery key is set.");
  let privateKey: string;
  try {
    privateKey = await unlockWithRecoveryKey(r.body.lockedKey, await recoveryEntropy(phrase));
  } catch {
    throw new CliError("That recovery key did not work.");
  }
  const lockedKey = await lockPrivateKey(privateKey, password);
  // Save the replacement first; if changing the password fails, the new recovery key still works.
  await setRecoveryKey(c, privateKey, newFile);
  const saved = await c.call("PUT", "/me/vault", { lockedKey });
  if (saved.status !== 200) failWith(saved.status, saved.body, "change password");
}

export const recovery: Commands = {
  "recovery-key": {
    help: "cfs recovery-key set <new-file> | use <old-file> <new-file>",
    run: async (a, h) => {
      if (a[0] === "set" && a.length === 2 && a[1]) {
        const c = await connect(h);
        if (!c.privateKey) throw new CliError("Your vault is locked. Run: cfs unlock");
        await setRecoveryKey(c, c.privateKey, a[1]);
        console.log(`Recovery key saved to ${a[1]}. Store it securely.`);
      } else if (a[0] === "use" && a.length === 3 && a[1] && a[2]) {
        const phrase = readFileSync(a[1], "utf8");
        const pw = await askHidden("New vault password: ", "CFS_NEW_PASSWORD");
        const again = await askHidden("Repeat it: ", "CFS_NEW_PASSWORD");
        if (pw !== again) throw new CliError("The two passwords do not match.");
        await useRecoveryKey(await connect(h), phrase, pw, a[2]);
        console.log(
          `Password changed. Replacement recovery key saved to ${a[2]}. Store it securely.`,
        );
      } else
        throw new CliError("Usage: cfs recovery-key set <new-file> | use <old-file> <new-file>");
    },
  },
  recover: {
    help: "cfs recover                         forgot your vault password: start recovery\n  cfs recover grant <id>               (admin) give access again after the words are read",
    run: (a, h) => recover(a, h),
  },
  passwd: {
    help: "cfs passwd                          change your vault password",
    run: (_a, h) => passwd(h),
  },
};
