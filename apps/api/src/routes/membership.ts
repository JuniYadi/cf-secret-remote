import { ConflictCode, LOGIN_CIPHERTEXT_LIMIT } from "@cfs/core";
import { type Context, Hono } from "hono";
import { audit } from "../audit.ts";
import { requireAdmin } from "../auth.ts";
import { NAME_RE } from "../limits.ts";
import { prefixOf, validPath } from "../policy.ts";
import { findPerson } from "../repository/identity.ts";
import { type Group, loadGroup } from "../repository/keyrings.ts";
import * as membershipRepo from "../repository/membership.ts";
import type { AppEnv } from "../types.ts";
import { now } from "../util.ts";
import { ciphertextSize, validInput } from "./logins.ts";

// ADR 14. Membership and staged key rotation. The server only stores wrapped keys and ciphertext.
// Writes to a rotating group are refused with 409 in secrets.ts.

export const CHUNK_SIZE = 50;

export const countAdminsWithVault = membershipRepo.countAdminsWithVault;

/**
 * Loads the group and checks the caller holds its key at the current version.
 * Returns the group, or a response to send. A denial is audited.
 */
async function memberGate(
  c: Context<AppEnv>,
  prefix: string,
  action: string,
  adminMayPass = false,
): Promise<Group | Response> {
  const who = c.get("who");
  const db = c.env.DB;
  const group = await loadGroup(db, prefix);
  if (!group) return c.json({ error: "no such group" }, 404);
  if (adminMayPass && who.role === "admin") return group;
  const mine = await membershipRepo.findMembership(db, group.id, who.id, group.version, now());
  if (!mine) {
    await audit(db, {
      who: who.name,
      actor: who,
      action,
      path: prefix,
      result: "denied",
      ip: c.req.header("CF-Connecting-IP"),
    });
    return c.json({ error: "you are not in this group" }, 403);
  }
  return group;
}

const isStr = (v: unknown): v is string => typeof v === "string" && v.length > 0;

export const membership = new Hono<AppEnv>();

// Members of a group, at the current version. Any member or an admin may list.
membership.get("/keyrings/:prefix/members", async (c) => {
  const prefix = c.req.param("prefix");
  const g = await memberGate(c, prefix, "group.members.list", true);
  if (g instanceof Response) return g;
  const rows = await membershipRepo.listMembers(c.env.DB, g.id, g.version, now());
  return c.json(rows.results);
});

// Add member: the caller wraps the current group key to the new member's public key.
membership.post("/keyrings/:prefix/members", requireAdmin, async (c) => {
  const db = c.env.DB;
  const who = c.get("who");
  const prefix = c.req.param("prefix");
  const b = await c.req.json<{ identityId?: string; wrappedKey?: string }>();
  if (!isStr(b.identityId) || !isStr(b.wrappedKey)) return c.json({ error: "bad request" }, 400);
  const g = await memberGate(c, prefix, "group.member.add");
  if (g instanceof Response) return g;
  if (g.status !== "active")
    return c.json(
      { error: "group is rotating, try again later", code: ConflictCode.group_rotating },
      409,
    );

  const target = await membershipRepo.findTarget(db, b.identityId);
  if (!target) return c.json({ error: "unknown identity" }, 404);
  if (target.status !== "active")
    return c.json({ error: "identity is disabled", code: ConflictCode.identity_disabled }, 409);
  if (!target.publicKey)
    return c.json(
      { error: "this person has not set up a vault yet", code: ConflictCode.vault_required },
      409,
    );

  try {
    await membershipRepo.addMember(db, g.id, b.identityId, g.version, b.wrappedKey);
  } catch {
    return c.json({ error: "already in this group", code: ConflictCode.already_in_group }, 409);
  }
  await audit(db, {
    who: who.name,
    actor: who,
    action: "group.member.add",
    path: prefix,
    version: g.version,
    note: target.name,
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ ok: true }, 201);
});

// Rotation step 1. Ends the removed member's access at once and marks the group rotating.
// `members` must be exactly the remaining members, each with the new group key wrapped to them.
membership.post("/keyrings/:prefix/rotate/start", requireAdmin, async (c) => {
  const db = c.env.DB;
  const who = c.get("who");
  const prefix = c.req.param("prefix");
  const b = await c.req.json<{
    removeIdentityId?: string;
    members?: { identityId?: string; wrappedKey?: string }[];
  }>();
  if (
    !isStr(b.removeIdentityId) ||
    !Array.isArray(b.members) ||
    b.members.length === 0 ||
    b.members.some((m) => !isStr(m?.identityId) || !isStr(m?.wrappedKey))
  )
    return c.json({ error: "bad request" }, 400);
  const removeId = b.removeIdentityId;
  const members = b.members as { identityId: string; wrappedKey: string }[];

  const g = await memberGate(c, prefix, "group.rotate.start");
  if (g instanceof Response) return g;
  if (g.status !== "active")
    return c.json({ error: "group is already rotating", code: ConflictCode.group_rotating }, 409);

  // The rotating admin needs the old key until commit, so it must stay a member.
  if (removeId === who.id)
    return c.json({ error: "you cannot remove yourself from the group" }, 400);

  const current = await membershipRepo.currentMembers(db, g.id, g.version, now());
  const ids = current.results.map((r) => r.id);
  // A person who is no longer in the group (an earlier attempt removed them, then was aborted) can be
  // removed again: start is idempotent, so a failed rotation can always be retried. An unknown id is refused.
  if (!ids.includes(removeId)) {
    const known = await membershipRepo.knownIdentity(db, removeId);
    if (!known) return c.json({ error: "no such person" }, 404);
  }
  const remaining = ids.filter((i) => i !== removeId).sort();
  const given = members.map((m) => m.identityId).sort();
  if (given.length !== remaining.length || given.some((id, i) => id !== remaining[i]))
    return c.json({ error: "members must be exactly the remaining members" }, 400);

  const removed = await membershipRepo.removedIdentity(db, removeId);
  const next = g.version + 1;
  try {
    const started = await membershipRepo.startRotation(db, g.id, members, next, removeId);
    if (!started[0]?.meta.changes)
      return c.json(
        { error: "group changed, reload and retry", code: ConflictCode.group_changed },
        409,
      );
  } catch {
    return c.json(
      { error: "group changed, reload and retry", code: ConflictCode.group_changed },
      409,
    );
  }
  const live = await membershipRepo.liveSecrets(db, g.id);
  await audit(db, {
    who: who.name,
    actor: who,
    action: "group.rotate.start",
    path: prefix,
    version: next,
    note: `removed ${removed?.name ?? removeId}`,
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ version: next, secrets: live?.n ?? 0 });
});

// Current ciphertext, including deleted items, for a rotating admin who holds the group key.
membership.get("/keyrings/:prefix/rotate/logins", requireAdmin, async (c) => {
  const g = await memberGate(c, c.req.param("prefix"), "group.rotate.logins");
  if (g instanceof Response) return g;
  if (g.status !== "rotating")
    return c.json({ error: "group is not rotating", code: ConflictCode.group_not_rotating }, 409);
  const rows = await membershipRepo.rotationLogins(c.env.DB, g.id);
  return c.json(rows.results.map((r) => ({ ...r, fps: JSON.parse(r.fps) })));
});

// Rotation step 2. Stages re-encrypted current versions at the new keyring version, at most 50 per call.
membership.post("/keyrings/:prefix/rotate/chunk", requireAdmin, async (c) => {
  const db = c.env.DB;
  const who = c.get("who");
  const prefix = c.req.param("prefix");
  const b = await c.req.json<{
    keyringVersion?: number;
    logins?: {
      id: string;
      version: number;
      wrappedDek: string;
      ciphertext: string;
      fps: unknown;
    }[];
    secrets?: {
      path?: string;
      names?: string[];
      wrappedDek?: string;
      ciphertext?: string;
      version?: number;
    }[];
  }>();
  if (
    (b.secrets !== undefined && !Array.isArray(b.secrets)) ||
    (b.logins !== undefined && !Array.isArray(b.logins))
  )
    return c.json({ error: "bad request" }, 400);
  const loginItems = b.logins ?? [];
  b.secrets ??= [];
  if (
    b.secrets.length + loginItems.length === 0 ||
    b.secrets.length + loginItems.length > CHUNK_SIZE
  )
    return c.json({ error: `send 1 to ${CHUNK_SIZE} items per chunk` }, 400);
  if (!Number.isInteger(b.keyringVersion)) return c.json({ error: "bad request" }, 400);
  const seen = new Set<string>();
  for (const s of b.secrets) {
    if (
      !isStr(s?.path) ||
      !validPath(s.path) ||
      prefixOf(s.path) !== prefix ||
      seen.has(s.path) ||
      !Array.isArray(s.names) ||
      !s.names.every((n) => typeof n === "string" && NAME_RE.test(n)) ||
      !isStr(s.wrappedDek) ||
      !isStr(s.ciphertext) ||
      !s.ciphertext.startsWith("v1.") ||
      !Number.isInteger(s.version)
    )
      return c.json({ error: "bad request" }, 400);
    seen.add(s.path);
  }
  const secrets = b.secrets as {
    path: string;
    names: string[];
    wrappedDek: string;
    ciphertext: string;
    version: number;
  }[];

  const g = await memberGate(c, prefix, "group.rotate.chunk");
  if (g instanceof Response) return g;
  if (g.status !== "rotating")
    return c.json({ error: "group is not rotating", code: ConflictCode.group_not_rotating }, 409);
  const next = g.version + 1;
  if (b.keyringVersion !== next)
    return c.json({ error: "keyringVersion must be the new version" }, 400);

  const loginIds = new Set<string>();
  for (const l of loginItems) {
    if (
      !l ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(l.id) ||
      loginIds.has(l.id) ||
      !validInput({ ...l, keyringId: g.id, keyringVersion: next })
    )
      return c.json({ error: "bad request" }, 400);
    const size = ciphertextSize(l.ciphertext);
    if (size === null) return c.json({ error: "bad ciphertext" }, 400);
    if (size > LOGIN_CIPHERTEXT_LIMIT) return c.json({ error: "too large" }, 413);
    loginIds.add(l.id);
    const row = await membershipRepo.loginCurrent(db, l.id, g.id);
    if (!row || l.version !== row.current + 1)
      return c.json(
        { error: "login or version changed", code: ConflictCode.login_or_version_changed },
        409,
      );
  }

  const rows: { secretId: string; version: number }[] = [];
  for (const s of secrets) {
    const row = await membershipRepo.secretCurrent(db, s.path, g.id);
    if (!row || row.deletedAt)
      return c.json(
        {
          error: "secret is not live in this group",
          code: ConflictCode.secret_not_live,
          path: s.path,
        },
        409,
      );
    if (s.version !== row.current + 1)
      return c.json(
        {
          error: "version changed, reload and retry",
          code: ConflictCode.version_conflict,
          path: s.path,
        },
        409,
      );
    rows.push({ secretId: row.id, version: s.version });
  }

  try {
    await membershipRepo.stageRotation(db, secrets, rows, loginItems, g.id, next, who.id);
  } catch {
    return c.json(
      { error: "group changed, reload and retry", code: ConflictCode.group_changed },
      409,
    );
  }
  for (const s of secrets)
    await audit(db, {
      who: who.name,
      actor: who,
      action: "secret.rotate",
      path: s.path,
      version: s.version,
      result: "ok",
      ip: c.req.header("CF-Connecting-IP"),
    });
  return c.json({ staged: secrets.length + loginItems.length });
});

// Rotation step 3. Refused unless every live secret has a version at the new keyring version.
// The checks are repeated inside the batch, so a chunk that lands in between cannot slip past.
membership.post("/keyrings/:prefix/rotate/commit", requireAdmin, async (c) => {
  const db = c.env.DB;
  const who = c.get("who");
  const prefix = c.req.param("prefix");
  const g = await memberGate(c, prefix, "group.rotate.commit");
  if (g instanceof Response) return g;
  if (g.status !== "rotating")
    return c.json({ error: "group is not rotating", code: ConflictCode.group_not_rotating }, 409);
  const next = g.version + 1;

  const missing = await membershipRepo.missingSecrets(db, g.id, next);
  if (missing.results.length)
    return c.json(
      {
        error: "some secrets have no new version yet",
        code: ConflictCode.rotation_secrets_missing,
        missing: missing.results.map((r) => r.path),
      },
      409,
    );

  const missingLogins = await membershipRepo.missingLogins(db, g.id, next);
  if (missingLogins.results.length)
    return c.json(
      {
        error: "some logins have no new version yet",
        code: ConflictCode.rotation_logins_missing,
        missing: missingLogins.results.map((r) => r.id),
      },
      409,
    );

  try {
    await membershipRepo.commitRotation(db, g.id, next);
  } catch {
    return c.json(
      { error: "group changed, reload and retry", code: ConflictCode.group_changed },
      409,
    );
  }
  const after = await loadGroup(db, prefix);
  if (after?.version !== next || after.status !== "active")
    return c.json(
      { error: "group changed, reload and retry", code: ConflictCode.group_changed },
      409,
    );
  await audit(db, {
    who: who.name,
    actor: who,
    action: "group.rotate.commit",
    path: prefix,
    version: next,
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ version: next, status: "active" });
});

// Abort: discards staged rows. Current versions and the old keyring version stay as they were.
membership.post("/keyrings/:prefix/rotate/abort", requireAdmin, async (c) => {
  const db = c.env.DB;
  const who = c.get("who");
  const prefix = c.req.param("prefix");
  const g = await memberGate(c, prefix, "group.rotate.abort");
  if (g instanceof Response) return g;
  if (g.status !== "rotating")
    return c.json({ error: "group is not rotating", code: ConflictCode.group_not_rotating }, 409);
  const next = g.version + 1;
  try {
    await membershipRepo.abortRotation(db, g.id, next);
  } catch {
    return c.json(
      { error: "group changed, reload and retry", code: ConflictCode.group_changed },
      409,
    );
  }
  await audit(db, {
    who: who.name,
    actor: who,
    action: "group.rotate.abort",
    path: prefix,
    version: g.version,
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ version: g.version, status: "active" });
});

// Identity admin: disable or enable, and change role. Disabling ends all sessions.
membership.patch("/identities/:id", requireAdmin, async (c) => {
  const db = c.env.DB;
  const who = c.get("who");
  const id = c.req.param("id");
  const b = await c.req.json<{ status?: string; role?: string }>();
  if (
    (b.status === undefined && b.role === undefined) ||
    (b.status !== undefined && b.status !== "active" && b.status !== "disabled") ||
    (b.role !== undefined && b.role !== "admin" && b.role !== "member")
  )
    return c.json({ error: "bad request" }, 400);
  const t = await findPerson(db, id);
  if (!t) return c.json({ error: "unknown identity" }, 404);

  const role = b.role ?? t.role;
  const status = b.status ?? t.status;
  const counts = (r: string, s: string) =>
    t.kind === "user" && r === "admin" && s === "active" && !!t.publicKey;
  // ADR 20: never leave fewer than two admins holding a vault.
  if (
    counts(t.role, t.status) &&
    !counts(role, status) &&
    (await countAdminsWithVault(db, t.id)) < 2
  )
    return c.json(
      { error: "at least two admins must hold a vault", code: ConflictCode.two_admins_required },
      409,
    );

  await membershipRepo.updateIdentity(db, role, status, t.id);

  const ip = c.req.header("CF-Connecting-IP");
  if (status !== t.status)
    await audit(db, {
      who: who.name,
      actor: who,
      action: status === "disabled" ? "identity.disable" : "identity.enable",
      note: t.name,
      result: "ok",
      ip,
    });
  if (role !== t.role)
    await audit(db, {
      who: who.name,
      actor: who,
      action: "identity.role",
      note: `${t.name}: ${t.role} -> ${role}`,
      result: "ok",
      ip,
    });
  return c.json({ id: t.id, role, status });
});
