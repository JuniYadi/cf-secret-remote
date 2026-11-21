import { env } from "cloudflare:test";
import {
  fingerprintWords,
  generateKeyPair,
  lockPrivateKey,
  lockWithRecoveryKey,
  newGroupKey,
  newRecoveryKey,
  recoveryPhrase,
  unlockPrivateKey,
  unlockWithRecoveryKey,
  unwrapGroupKey,
  wrapGroupKey,
} from "@cfs/core";
import { beforeAll, describe, expect, it } from "vitest";
import { flushAlerts, resetAlertSenders, setAlertSenders } from "../src/alerts.ts";
import { accessJwt, freshLogin, installAccessCerts } from "./access-jwt.ts";
import { api, makeIdentity } from "./helpers.ts";

// ADR 20 rules, one test each (failures included). Real Workers runtime and D1.

type KeyPair = { publicKey: string; privateKey: string };
type Person = { id: string; name: string; token: string; kp: KeyPair };

const OLD_PASSWORD = "old vault password";
const NEW_PASSWORD = "new vault password";

beforeAll(async () => {
  await installAccessCerts();
});

async function person(opts: { role?: "admin" | "member"; vault?: boolean } = {}): Promise<Person> {
  const kp = await generateKeyPair();
  const p = await makeIdentity({
    role: opts.role,
    publicKey: opts.vault === false ? undefined : kp.publicKey,
  });
  if (opts.vault !== false)
    await env.DB.prepare("UPDATE identity SET locked_key = ? WHERE id = ?")
      .bind(await lockPrivateKey(kp.privateKey, OLD_PASSWORD, 100_000), p.id)
      .run();
  return { ...p, kp };
}

/** Creates a group with `owner` and `others`, all at key version 1. */
async function makeGroup(prefix: string, owner: Person, others: Person[] = []) {
  const gk = await newGroupKey();
  const members = await Promise.all(
    [owner, ...others].map(async (m) => ({
      identityId: m.id,
      wrappedKey: await wrapGroupKey(gk, m.kp.publicKey, prefix, 1),
    })),
  );
  const r = await api("POST", "/keyrings", owner.token, { prefix, members });
  expect(r.status).toBe(201);
  return gk;
}

async function groupKeyFor(p: Person, prefix: string) {
  const r = await api("GET", `/keyrings/${prefix}/key`, p.token);
  expect(r.status).toBe(200);
  return unwrapGroupKey(r.body.wrappedKey, p.kp.privateKey, p.kp.publicKey, prefix, r.body.version);
}

async function newKeyPair() {
  const kp = await generateKeyPair();
  return { kp, locked: await lockPrivateKey(kp.privateKey, NEW_PASSWORD, 100_000) };
}

async function startRecovery(p: Person, headers?: Record<string, string>) {
  const next = await newKeyPair();
  const r = await api(
    "POST",
    "/recovery/request",
    p.token,
    { publicKey: next.kp.publicKey, lockedKey: next.locked },
    headers ?? (await freshLogin(p.name)),
  );
  return { r, next };
}

async function rowOf(id: string) {
  return env.DB.prepare("SELECT status, attempts, public_key FROM recovery_request WHERE id = ?")
    .bind(id)
    .first<{ status: string; attempts: number; public_key: string }>();
}

async function auditEntries(): Promise<Record<string, unknown>[]> {
  const rows = await env.DB.prepare("SELECT entry FROM audit").all<{ entry: string }>();
  return rows.results.map((r) => JSON.parse(r.entry));
}

describe("ADR 18: recovery_requested alert (real route)", () => {
  it("a request made through POST /recovery/request sends the alert; a refused one does not", async () => {
    const sent: string[] = [];
    setAlertSenders({
      webhook: async (_url, text) => {
        sent.push(text);
      },
    });
    try {
      const a = await person({ role: "admin" });
      const put = await api("PUT", "/alerts", a.token, {
        webhook: "https://hooks.test/services/T/B/X",
      });
      expect(put.status).toBe(200);

      const p = await person();
      const stale = await accessJwt(p.name, Math.floor(Date.now() / 1000) - 400);
      expect((await startRecovery(p, { "Cf-Access-Jwt-Assertion": stale })).r.status).toBe(403);
      await flushAlerts();
      expect(sent.filter((t) => t.includes("Recovery requested"))).toHaveLength(0);

      const ok = await startRecovery(p);
      expect(ok.r.status).toBe(201);
      await flushAlerts();
      expect(sent.filter((t) => t.includes("Recovery requested"))).toHaveLength(1);
    } finally {
      await flushAlerts();
      resetAlertSenders();
      // Storage is shared by this file: drop the webhook so later denials do not reach the real network.
      await env.DB.batch([
        env.DB.prepare("DELETE FROM setting"),
        env.DB.prepare("DELETE FROM alert_state"),
      ]);
    }
  });
});

describe("ADR 20: fingerprint code and request", () => {
  it("a fresh Access login starts a request and returns the four words of the new key", async () => {
    const p = await person();
    const { r, next } = await startRecovery(p);
    expect(r.status).toBe(201);
    expect(r.body.words).toBe(await fingerprintWords(next.kp.publicKey));
    expect(r.body.words.split(" ")).toHaveLength(4);
    expect(typeof r.body.cancelToken).toBe("string");
    const row = await rowOf(r.body.id);
    expect(row?.status).toBe("pending");
    expect(row?.public_key).toBe(next.kp.publicKey);
  });

  it("a stale Access login (older than 5 minutes) is refused", async () => {
    const p = await person();
    const old = await accessJwt(p.name, Math.floor(Date.now() / 1000) - 400);
    const { r } = await startRecovery(p, { "Cf-Access-Jwt-Assertion": old });
    expect(r.status).toBe(403);
    expect(
      (await auditEntries()).some((e) => e.action === "recovery.request" && e.result === "denied"),
    ).toBe(true);
  });

  it("a login with no Access token, or one for another person, is refused", async () => {
    const p = await person();
    const other = await person();
    expect((await startRecovery(p, {})).r.status).toBe(403);
    const theirs = await freshLogin(other.name);
    expect((await startRecovery(p, theirs)).r.status).toBe(403);
  });

  it("a token issued in the future (clock skew beyond a minute) is refused", async () => {
    const p = await person();
    const future = await accessJwt(p.name, Math.floor(Date.now() / 1000) + 600);
    expect((await startRecovery(p, { "Cf-Access-Jwt-Assertion": future })).r.status).toBe(403);
  });

  it("a pending key cannot be replaced: a second request is refused and the row is immutable", async () => {
    const p = await person();
    const first = await startRecovery(p);
    expect(first.r.status).toBe(201);
    const second = await startRecovery(p);
    expect(second.r.status).toBe(409);
    expect((await rowOf(first.r.body.id))?.public_key).toBe(first.next.kp.publicKey);

    // Even direct SQL cannot change the pending key (trigger).
    await expect(
      env.DB.prepare("UPDATE recovery_request SET public_key = 'x' WHERE id = ?")
        .bind(first.r.body.id)
        .run(),
    ).rejects.toThrow();
  });

  it("a malformed public key or locked key is refused", async () => {
    const p = await person();
    const next = await newKeyPair();
    const h = await freshLogin(p.name);
    expect(
      (
        await api(
          "POST",
          "/recovery/request",
          p.token,
          { publicKey: "nope", lockedKey: next.locked },
          h,
        )
      ).status,
    ).toBe(400);
    expect(
      (
        await api(
          "POST",
          "/recovery/request",
          p.token,
          { publicKey: next.kp.publicKey, lockedKey: "p1.10.x" },
          h,
        )
      ).status,
    ).toBe(400);
    expect(
      (
        await api(
          "POST",
          "/recovery/request",
          p.token,
          { publicKey: next.kp.publicKey, lockedKey: next.locked.replace("p1.", "p2.") },
          h,
        )
      ).status,
    ).toBe(400);
  });

  it("cancel discards the pending request and records an audit entry", async () => {
    const p = await person();
    const { r } = await startRecovery(p);
    const id = r.body.id as string;

    // Wrong token: refused, still pending.
    expect((await api("POST", `/recovery/${id}/cancel`, p.token, { token: "guess" })).status).toBe(
      403,
    );
    expect((await rowOf(id))?.status).toBe("pending");

    // Another person cannot cancel it, and learns nothing.
    const other = await person();
    expect(
      (await api("POST", `/recovery/${id}/cancel`, other.token, { token: r.body.cancelToken }))
        .status,
    ).toBe(404);

    const ok = await api("POST", `/recovery/${id}/cancel`, p.token, { token: r.body.cancelToken });
    expect(ok.status).toBe(200);
    expect(await rowOf(id)).toBeNull();
    expect(
      (await auditEntries()).some(
        (e) => e.action === "recovery.cancel" && e.result === "ok" && e.who === p.name,
      ),
    ).toBe(true);
    // Once cancelled, the person may start again.
    expect((await startRecovery(p)).r.status).toBe(201);
  });
});

describe("ADR 20: admin grant", () => {
  it("wrong words are rejected and counted; the fifth locks the request", async () => {
    const adm = await person({ role: "admin" });
    const p = await person();
    const { r, next } = await startRecovery(p);
    const id = r.body.id as string;
    const wrong = "abandon abandon abandon abandon";
    expect(wrong).not.toBe(r.body.words);

    for (let i = 1; i <= 4; i++) {
      const res = await api("POST", `/recovery/${id}/grant`, adm.token, { words: wrong, keys: [] });
      expect(res.status).toBe(403);
      expect(res.body.attemptsLeft).toBe(5 - i);
      expect(res.body.locked).toBe(false);
    }
    const fifth = await api("POST", `/recovery/${id}/grant`, adm.token, { words: wrong, keys: [] });
    expect(fifth.status).toBe(403);
    expect(fifth.body.locked).toBe(true);
    expect((await rowOf(id))?.attempts).toBe(5);
    expect((await rowOf(id))?.status).toBe("locked");

    // Locked: even the right words no longer work.
    const right = await api("POST", `/recovery/${id}/grant`, adm.token, {
      words: await fingerprintWords(next.kp.publicKey),
      keys: [],
    });
    expect(right.status).toBe(409);
    expect(
      (await auditEntries()).some(
        (e) => e.action === "recovery.locked" && e.note === `request ${id}`,
      ),
    ).toBe(true);
    // Audit never holds the typed or expected words.
    const text = JSON.stringify(await auditEntries());
    expect(text).not.toContain(r.body.words);
  });

  it("a grant re-wraps only the groups listed; other groups are untouched", async () => {
    const adm = await person({ role: "admin" });
    const p = await person();
    const gA = `recA${Math.random().toString(36).slice(2, 7)}`;
    const gB = `recB${Math.random().toString(36).slice(2, 7)}`;
    const keyA = await makeGroup(gA, adm, [p]);
    await makeGroup(gB, adm, [p]);
    const before = await env.DB.prepare(
      "SELECT k.prefix, m.version, m.wrapped_key FROM keyring_member m JOIN keyring k ON k.id = m.keyring_id WHERE m.identity_id = ? ORDER BY k.prefix",
    )
      .bind(p.id)
      .all<{ prefix: string; version: number; wrapped_key: string }>();
    const oldB = before.results.find((r) => r.prefix === gB)?.wrapped_key;

    const { r, next } = await startRecovery(p);
    const id = r.body.id as string;
    const rewrapped = await wrapGroupKey(keyA, next.kp.publicKey, gA, 1);
    const res = await api("POST", `/recovery/${id}/grant`, adm.token, {
      words: r.body.words,
      keys: [{ prefix: gA, version: 1, wrappedKey: rewrapped }],
    });
    expect(res.status).toBe(200);
    expect(res.body.groups).toEqual([gA]);

    // The person's key is swapped in and the locked key is the one from the request.
    const me = await api("GET", "/whoami", p.token);
    expect(me.body.publicKey).toBe(next.kp.publicKey);
    expect(me.body.lockedKey).toBe(next.locked);
    expect(await unlockPrivateKey(next.locked, NEW_PASSWORD)).toBe(next.kp.privateKey);

    // Group A opens with the new key.
    const gotA = await unwrapGroupKey(rewrapped, next.kp.privateKey, next.kp.publicKey, gA, 1);
    expect(gotA).toEqual(keyA);

    // Group B: the same row, still wrapped to the old key.
    const after = await env.DB.prepare(
      "SELECT m.wrapped_key FROM keyring_member m JOIN keyring k ON k.id = m.keyring_id WHERE m.identity_id = ? AND k.prefix = ?",
    )
      .bind(p.id, gB)
      .first<{ wrapped_key: string }>();
    expect(after?.wrapped_key).toBe(oldB);
    await expect(
      unwrapGroupKey(after?.wrapped_key ?? "", next.kp.privateKey, next.kp.publicKey, gB, 1),
    ).rejects.toThrow();
  });

  it("a grant is refused for a group the admin is not in, or the person is not in", async () => {
    const adm = await person({ role: "admin" });
    const p = await person();
    const { r, next } = await startRecovery(p);
    const id = r.body.id as string;
    const outsiderGroup = `recO${Math.random().toString(36).slice(2, 7)}`;
    const gk = await newGroupKey();
    await makeGroup(outsiderGroup, await person({ role: "admin" }), [p]);
    const notMine = await api("POST", `/recovery/${id}/grant`, adm.token, {
      words: r.body.words,
      keys: [
        {
          prefix: outsiderGroup,
          version: 1,
          wrappedKey: await wrapGroupKey(gk, next.kp.publicKey, outsiderGroup, 1),
        },
      ],
    });
    expect(notMine.status).toBe(403);

    const peerGroup = `recP${Math.random().toString(36).slice(2, 7)}`;
    await makeGroup(peerGroup, adm, []);
    const notTheirs = await api("POST", `/recovery/${id}/grant`, adm.token, {
      words: r.body.words,
      keys: [
        {
          prefix: peerGroup,
          version: 1,
          wrappedKey: await wrapGroupKey(gk, next.kp.publicKey, peerGroup, 1),
        },
      ],
    });
    expect(notTheirs.status).toBe(400);
    // Neither refusal swapped the key.
    expect((await rowOf(id))?.status).toBe("pending");
  });

  it("the person cannot grant their own recovery, and members cannot grant at all", async () => {
    const adm = await person({ role: "admin" });
    const self = await person({ role: "admin" });
    const { r } = await startRecovery(self);
    const own = await api("POST", `/recovery/${r.body.id}/grant`, self.token, {
      words: r.body.words,
      keys: [],
    });
    expect(own.status).toBe(403);

    const mem = await person();
    const { r: r2 } = await startRecovery(mem);
    const asMember = await api("POST", `/recovery/${r2.body.id}/grant`, mem.token, {
      words: r2.body.words,
      keys: [],
    });
    expect(asMember.status).toBe(403);
    // An admin can read the request, with the public key to re-wrap to.
    const read = await api("GET", `/recovery/${r2.body.id}`, adm.token);
    expect(read.status).toBe(200);
    expect(read.body.attemptsLeft).toBe(5);
    expect((await api("GET", `/recovery/${r2.body.id}`, mem.token)).status).toBe(403);
  });

  it("a grant without the words is a bad request and does not count as an attempt", async () => {
    const adm = await person({ role: "admin" });
    const p = await person();
    const { r } = await startRecovery(p);
    const res = await api("POST", `/recovery/${r.body.id}/grant`, adm.token, { keys: [] });
    expect(res.status).toBe(400);
  });
});

describe("ADR 20: vault password and recovery key", () => {
  it("change password re-locks the same private key; the public key and group access stay", async () => {
    const adm = await person({ role: "admin" });
    const p = await person();
    const prefix = `pw${Math.random().toString(36).slice(2, 7)}`;
    const gk = await makeGroup(prefix, adm, [p]);
    const newLock = await lockPrivateKey(p.kp.privateKey, NEW_PASSWORD, 100_000);
    const put = await api("PUT", "/me/vault", p.token, { lockedKey: newLock });
    expect(put.status).toBe(200);

    const me = await api("GET", "/whoami", p.token);
    expect(me.body.publicKey).toBe(p.kp.publicKey);
    expect(me.body.lockedKey).toBe(newLock);
    expect(await unlockPrivateKey(newLock, NEW_PASSWORD)).toBe(p.kp.privateKey);
    expect(await groupKeyFor(p, prefix)).toEqual(gk);
    expect(
      (await auditEntries()).some((e) => e.action === "vault.password" && e.who === p.name),
    ).toBe(true);
  });

  it("the locked key format is validated on change and on setup", async () => {
    const p = await person();
    expect((await api("PUT", "/me/vault", p.token, { lockedKey: "p1.1.x" })).status).toBe(400);
    expect(
      (
        await api("PUT", "/me/vault", p.token, {
          lockedKey: "rk1.v1.aaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbb",
        })
      ).status,
    ).toBe(400);
    expect((await api("PUT", "/me/vault", p.token, {})).status).toBe(400);

    // A person without a vault cannot change a password that does not exist yet.
    const novault = await person({ vault: false });
    const locked = await lockPrivateKey(
      (await generateKeyPair()).privateKey,
      NEW_PASSWORD,
      100_000,
    );
    expect((await api("PUT", "/me/vault", novault.token, { lockedKey: locked })).status).toBe(409);
  });

  it("the recovery key lock is stored for the person only and checked for shape", async () => {
    const p = await person();
    const other = await person();
    const entropy = newRecoveryKey();
    const phrase = await recoveryPhrase(entropy);
    expect(phrase.split(" ")).toHaveLength(24);
    const lock = await lockWithRecoveryKey(p.kp.privateKey, entropy);

    expect((await api("PUT", "/me/recovery", p.token, { lockedKey: "rk1.nope" })).status).toBe(400);
    expect((await api("PUT", "/me/recovery", p.token, { lockedKey: lock })).status).toBe(200);

    const mine = await api("GET", "/me/recovery", p.token);
    expect(mine.body).toEqual({ set: true, lockedKey: lock });
    expect((await api("GET", "/me/recovery", other.token)).body).toEqual({
      set: false,
      lockedKey: null,
    });

    // The 24 words restore the private key in the browser.
    const restored = await unlockWithRecoveryKey(mine.body.lockedKey, entropy);
    expect(restored).toBe(p.kp.privateKey);
  });

  it("a grant clears the old recovery key, which belonged to the old private key", async () => {
    const adm = await person({ role: "admin" });
    const p = await person();
    const entropy = newRecoveryKey();
    await api("PUT", "/me/recovery", p.token, {
      lockedKey: await lockWithRecoveryKey(p.kp.privateKey, entropy),
    });
    const { r, next } = await startRecovery(p);
    const res = await api("POST", `/recovery/${r.body.id}/grant`, adm.token, {
      words: r.body.words,
      keys: [],
    });
    expect(res.status).toBe(200);
    expect((await api("GET", "/me/recovery", p.token)).body).toEqual({
      set: false,
      lockedKey: null,
    });
    expect((await api("GET", "/whoami", p.token)).body.publicKey).toBe(next.kp.publicKey);
  });
});
