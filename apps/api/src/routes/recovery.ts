import {
  b64uDecode,
  ConflictCode,
  fingerprintWords,
  isPrivateKeyLock,
  normalizeWords,
} from "@cfs/core";
import { type Context, Hono } from "hono";
import { accessJwtFrom, verifyAccessClaims } from "../access.ts";
import { RECOVERY_ACTION } from "../alerts.ts";
import { audit } from "../audit.ts";
import { requireAdmin } from "../auth.ts";
import { notifyRecovery, type RecoveryEvent } from "../recovery-notify.ts";
import {
  cancelRecovery,
  createRecovery,
  findCancellation,
  findPendingRecovery,
  findRecoveryGroup,
  findRecoveryMember,
  grantRecovery,
  listRecoveries,
  loadRequest,
  recordWrongCode,
  recoveryGroups,
} from "../repository/recovery.ts";
import type { AppEnv } from "../types.ts";
import { newId, newToken, now, sha256Hex } from "../util.ts";

// ADR 20. Forgotten vault password: a fresh Access login starts a request with a new key pair; an admin who
// holds the groups re-wraps them to the new key after the person's four words are typed. The server stores
// ciphertext, wrapped keys and public keys only.

/** The Access login must be this recent (seconds). */
export const FRESH_LOGIN_SECONDS = 300;
/** Wrong four-word codes allowed per request before it is locked. */
export const MAX_ATTEMPTS = 5;
const CLOCK_SKEW_SECONDS = 60;

const isStr = (v: unknown): v is string => typeof v === "string" && v.length > 0;

async function body<T>(c: Context<AppEnv>): Promise<Partial<T>> {
  return (await c.req.json<Partial<T>>().catch(() => ({}))) as Partial<T>;
}

/** The public key must be an ECDH P-256 SPKI key. */
async function validPublicKey(s: string): Promise<boolean> {
  try {
    await crypto.subtle.importKey(
      "spki",
      b64uDecode(s) as BufferSource,
      { name: "ECDH", namedCurve: "P-256" },
      true,
      [],
    );
    return true;
  } catch {
    return false;
  }
}

const ip = (c: Context<AppEnv>) => c.req.header("CF-Connecting-IP");

export const recovery = new Hono<AppEnv>();

// Start a request. Needs a fresh Access login for this same person (iat within 5 minutes).
// Returns the four words to read to an admin, and a cancel token for the "Not me" link.
recovery.post("/recovery/request", async (c) => {
  const db = c.env.DB;
  const who = c.get("who");
  const claims = await verifyAccessClaims(c.env, accessJwtFrom(c.req)?.jwt);
  const t = now();
  const fresh =
    claims !== null &&
    claims.email === who.name.toLowerCase() &&
    t - claims.iat <= FRESH_LOGIN_SECONDS &&
    claims.iat - t <= CLOCK_SKEW_SECONDS;
  if (!fresh || who.kind !== "user") {
    await audit(db, {
      who: who.name,
      actor: who,
      action: "recovery.request",
      result: "denied",
      ip: ip(c),
      note: "not a fresh login",
    });
    return c.json({ error: "sign in again, then start recovery" }, 403);
  }

  const b = await body<{ publicKey: string; lockedKey: string }>(c);
  if (!isStr(b.publicKey) || !(await validPublicKey(b.publicKey)) || !isPrivateKeyLock(b.lockedKey))
    return c.json({ error: "bad request" }, 400);

  const pending = await findPendingRecovery(db, who.id);
  if (pending)
    return c.json(
      {
        error: "a recovery request is already waiting for an admin",
        code: ConflictCode.recovery_pending,
      },
      409,
    );

  const id = newId();
  const cancelToken = newToken("cfsr");
  try {
    await createRecovery(db, id, who.id, b.publicKey, b.lockedKey, await sha256Hex(cancelToken), t);
  } catch {
    // The partial unique index stopped a second open request at the same moment.
    return c.json(
      {
        error: "a recovery request is already waiting for an admin",
        code: ConflictCode.recovery_pending,
      },
      409,
    );
  }
  // RECOVERY_ACTION is the exact name the ADR 18 "recovery_requested" alert watches.
  await audit(db, {
    who: who.name,
    actor: who,
    action: RECOVERY_ACTION,
    note: `request ${id}`,
    result: "ok",
    ip: ip(c),
  });
  emit(c, { kind: "requested", identityId: who.id, requestId: id });
  return c.json({ id, words: await fingerprintWords(b.publicKey), cancelToken }, 201);
});

// Admin: the pending requests, names and times only. The admin opens one to give access again (ADR 20).
recovery.get("/recovery", requireAdmin, async (c) => {
  const rows = await listRecoveries(c.env.DB);
  return c.json(rows.results);
});

// An admin reads a pending request: the new public key (to re-wrap to), the person's groups, and attempts left.
recovery.get("/recovery/:id", requireAdmin, async (c) => {
  const r = await loadRequest(c.env.DB, c.req.param("id"));
  if (!r) return c.json({ error: "no such request" }, 404);
  const groups = await recoveryGroups(c.env.DB, r.identity_id);
  return c.json({
    id: r.id,
    name: r.name,
    status: r.status,
    attemptsLeft: Math.max(0, MAX_ATTEMPTS - r.attempts),
    publicKey: r.public_key,
    groups: groups.results.map((g) => g.prefix),
  });
});

// Admin grant. Body: the four words the admin typed, and for each group the admin re-wrapped to the new key.
recovery.post("/recovery/:id/grant", requireAdmin, async (c) => {
  const db = c.env.DB;
  const who = c.get("who");
  const id = c.req.param("id");
  const b = await body<{
    words: string;
    keys: { prefix: string; version: number; wrappedKey: string }[];
  }>(c);
  if (!isStr(b.words)) return c.json({ error: "bad request" }, 400);

  const r = await loadRequest(c.env.DB, id);
  if (!r) return c.json({ error: "no such request" }, 404);
  if (r.status !== "pending")
    return c.json({ error: "this request is not open", code: ConflictCode.request_not_open }, 409);
  if (r.identity_id === who.id)
    return c.json({ error: "another admin must grant this recovery" }, 403);

  // The words are checked before anything else. Each wrong code is counted; the fifth locks the request.
  const expected = await fingerprintWords(r.public_key);
  if (normalizeWords(b.words) !== expected) {
    await recordWrongCode(db, MAX_ATTEMPTS, id);
    const after = await loadRequest(c.env.DB, id);
    const left = Math.max(0, MAX_ATTEMPTS - (after?.attempts ?? MAX_ATTEMPTS));
    const locked = after?.status === "locked";
    await audit(db, {
      who: who.name,
      actor: who,
      action: "recovery.grant",
      note: `request ${id}: wrong code, ${left} left`,
      result: "denied",
      ip: ip(c),
    });
    if (locked) {
      await audit(db, {
        who: who.name,
        actor: who,
        action: "recovery.locked",
        note: `request ${id}`,
        result: "denied",
        ip: ip(c),
      });
      emit(c, { kind: "locked", identityId: r.identity_id, requestId: id });
    }
    return c.json({ error: "the code does not match", attemptsLeft: left, locked }, 403);
  }

  const keys = Array.isArray(b.keys) ? b.keys : null;
  if (
    !keys ||
    keys.length > 100 ||
    keys.some(
      (k) =>
        !isStr(k?.prefix) ||
        !Number.isInteger(k.version) ||
        !isStr(k.wrappedKey) ||
        !k.wrappedKey.includes("."),
    ) ||
    new Set(keys.map((k) => k.prefix)).size !== keys.length
  )
    return c.json({ error: "bad request" }, 400);

  // Every listed group: active, at the current version, the admin holds it, and the person is in it now.
  // A group the person is not in (removed earlier) can never be re-granted through recovery.
  const plan: { keyringId: string; prefix: string; version: number; wrappedKey: string }[] = [];
  for (const k of keys) {
    const g = await findRecoveryGroup(db, k.prefix);
    if (!g) return c.json({ error: `no such group: ${k.prefix}` }, 404);
    if (g.status !== "active")
      return c.json(
        { error: `group is rotating: ${k.prefix}`, code: ConflictCode.group_rotating },
        409,
      );
    if (k.version !== g.version)
      return c.json(
        { error: "group changed, reload and retry", code: ConflictCode.group_changed },
        409,
      );
    const adminIn = await findRecoveryMember(db, g.id, who.id, g.version);
    if (!adminIn) return c.json({ error: `you are not in group: ${k.prefix}` }, 403);
    const personIn = await findRecoveryMember(db, g.id, r.identity_id, g.version);
    if (!personIn) return c.json({ error: `the person is not in group: ${k.prefix}` }, 400);
    plan.push({ keyringId: g.id, prefix: k.prefix, version: g.version, wrappedKey: k.wrappedKey });
  }

  // One batch. Every statement is conditioned on this request being granted by this admin, so a
  // concurrent request cannot leave the key swapped without its groups, or the reverse.
  await grantRecovery(db, who.id, now(), id, r.identity_id, plan);

  const done = await loadRequest(c.env.DB, id);
  if (done?.status !== "granted")
    return c.json(
      { error: "request changed, reload and retry", code: ConflictCode.request_changed },
      409,
    );
  await audit(db, {
    who: who.name,
    actor: who,
    action: "recovery.grant",
    note: `request ${id} for ${r.name}: ${plan.length} group(s) re-wrapped`,
    result: "ok",
    ip: ip(c),
  });
  emit(c, { kind: "granted", identityId: r.identity_id, requestId: id });
  return c.json({ ok: true, groups: plan.map((p) => p.prefix) });
});

// The person cancels a request from the "Not me" link. The token is random and only its hash is stored.
// Cancelling discards the pending key and the request row.
recovery.post("/recovery/:id/cancel", async (c) => {
  const db = c.env.DB;
  const who = c.get("who");
  const id = c.req.param("id");
  const b = await body<{ token: string }>(c);
  if (!isStr(b.token)) return c.json({ error: "bad request" }, 400);
  const r = await findCancellation(db, id);
  // Someone else's request looks the same as no request.
  if (!r || r.identity_id !== who.id) return c.json({ error: "no such request" }, 404);
  if (r.status !== "pending")
    return c.json({ error: "this request is not open", code: ConflictCode.request_not_open }, 409);
  if ((await sha256Hex(b.token)) !== r.cancel_hash) {
    await audit(db, {
      who: who.name,
      actor: who,
      action: "recovery.cancel",
      note: `request ${id}`,
      result: "denied",
      ip: ip(c),
    });
    return c.json({ error: "bad cancel link" }, 403);
  }
  await cancelRecovery(db, id);
  await audit(db, {
    who: who.name,
    actor: who,
    action: "recovery.cancel",
    note: `request ${id}`,
    result: "ok",
    ip: ip(c),
  });
  emit(c, { kind: "cancelled", identityId: who.id, requestId: id });
  return c.json({ ok: true });
});

function emit(c: Context<AppEnv>, event: RecoveryEvent) {
  try {
    notifyRecovery(c.env, event);
  } catch {
    // A notifier must never break a recovery step.
  }
}
