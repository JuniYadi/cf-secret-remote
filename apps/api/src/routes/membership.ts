import { type Context, Hono } from "hono";
import { audit } from "../audit.ts";
import { requireAdmin } from "../auth.ts";
import { NAME_RE } from "../limits.ts";
import { prefixOf, validPath } from "../policy.ts";
import type { AppEnv } from "../types.ts";
import { now } from "../util.ts";

// ADR 14. Membership and staged key rotation. The server only stores wrapped keys and ciphertext.
// Writes to a rotating group are refused with 409 in secrets.ts.

export const CHUNK_SIZE = 50;

interface Group {
  id: string;
  version: number;
  status: "active" | "rotating";
}

/**
 * Two-admin guard (ADR 20): active user admins that hold a vault, not counting `exceptId`.
 * Callers refuse a demotion or disable of an admin when this is below 2.
 */
export async function countAdminsWithVault(db: D1Database, exceptId?: string): Promise<number> {
  const row = await db
    .prepare(
      "SELECT COUNT(*) AS n FROM identity WHERE kind = 'user' AND role = 'admin' AND status = 'active' AND public_key IS NOT NULL AND id != ?",
    )
    .bind(exceptId ?? "")
    .first<{ n: number }>();
  return row?.n ?? 0;
}

const loadGroup = (db: D1Database, prefix: string) =>
  db
    .prepare("SELECT id, version, status FROM keyring WHERE prefix = ?")
    .bind(prefix)
    .first<Group>();

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
  const mine = await db
    .prepare(
      "SELECT 1 AS ok FROM keyring_member WHERE keyring_id = ? AND identity_id = ? AND version = ?",
    )
    .bind(group.id, who.id, group.version)
    .first();
  if (!mine) {
    await audit(db, {
      who: who.name,
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
  const rows = await c.env.DB.prepare(
    `SELECT i.id AS identityId, i.name, i.role, i.status FROM keyring_member m
     JOIN identity i ON i.id = m.identity_id
     WHERE m.keyring_id = ? AND m.version = ? ORDER BY i.name`,
  )
    .bind(g.id, g.version)
    .all();
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
  if (g.status !== "active") return c.json({ error: "group is rotating, try again later" }, 409);

  const target = await db
    .prepare("SELECT name, public_key AS publicKey, status FROM identity WHERE id = ?")
    .bind(b.identityId)
    .first<{ name: string; publicKey: string | null; status: string }>();
  if (!target) return c.json({ error: "unknown identity" }, 404);
  if (target.status !== "active") return c.json({ error: "identity is disabled" }, 409);
  if (!target.publicKey) return c.json({ error: "this person has not set up a vault yet" }, 409);

  try {
    await db
      .prepare(
        "INSERT INTO keyring_member (keyring_id, identity_id, version, wrapped_key) VALUES (?, ?, ?, ?)",
      )
      .bind(g.id, b.identityId, g.version, b.wrappedKey)
      .run();
  } catch {
    return c.json({ error: "already in this group" }, 409);
  }
  await audit(db, {
    who: who.name,
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
  if (g.status !== "active") return c.json({ error: "group is already rotating" }, 409);
  // The rotating admin needs the old key until commit, so it must stay a member.
  if (removeId === who.id)
    return c.json({ error: "you cannot remove yourself from the group" }, 400);

  const current = await db
    .prepare("SELECT identity_id AS id FROM keyring_member WHERE keyring_id = ? AND version = ?")
    .bind(g.id, g.version)
    .all<{ id: string }>();
  const ids = current.results.map((r) => r.id);
  if (!ids.includes(removeId)) return c.json({ error: "not in this group" }, 404);
  const remaining = ids.filter((i) => i !== removeId).sort();
  const given = members.map((m) => m.identityId).sort();
  if (given.length !== remaining.length || given.some((id, i) => id !== remaining[i]))
    return c.json({ error: "members must be exactly the remaining members" }, 400);

  const removed = await db
    .prepare("SELECT name FROM identity WHERE id = ?")
    .bind(removeId)
    .first<{ name: string }>();
  const next = g.version + 1;
  try {
    await db.batch([
      db
        .prepare("UPDATE keyring SET status = 'rotating' WHERE id = ? AND status = 'active'")
        .bind(g.id),
      db
        .prepare("DELETE FROM keyring_member WHERE keyring_id = ? AND identity_id = ?")
        .bind(g.id, removeId),
      ...members.map((m) =>
        db
          .prepare(
            "INSERT INTO keyring_member_staged (keyring_id, identity_id, version, wrapped_key) VALUES (?, ?, ?, ?)",
          )
          .bind(g.id, m.identityId, next, m.wrappedKey),
      ),
    ]);
  } catch {
    return c.json({ error: "group changed, reload and retry" }, 409);
  }
  const live = await db
    .prepare("SELECT COUNT(*) AS n FROM secret WHERE keyring_id = ? AND deleted_at IS NULL")
    .bind(g.id)
    .first<{ n: number }>();
  await audit(db, {
    who: who.name,
    action: "group.rotate.start",
    path: prefix,
    version: next,
    note: `removed ${removed?.name ?? removeId}`,
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ version: next, secrets: live?.n ?? 0 });
});

// Rotation step 2. Stages re-encrypted current versions at the new keyring version, at most 50 per call.
membership.post("/keyrings/:prefix/rotate/chunk", requireAdmin, async (c) => {
  const db = c.env.DB;
  const who = c.get("who");
  const prefix = c.req.param("prefix");
  const b = await c.req.json<{
    keyringVersion?: number;
    secrets?: {
      path?: string;
      names?: string[];
      wrappedDek?: string;
      ciphertext?: string;
      version?: number;
    }[];
  }>();
  if (!Array.isArray(b.secrets) || b.secrets.length === 0 || b.secrets.length > CHUNK_SIZE)
    return c.json({ error: `send 1 to ${CHUNK_SIZE} secrets per chunk` }, 400);
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
  if (g.status !== "rotating") return c.json({ error: "group is not rotating" }, 409);
  const next = g.version + 1;
  if (b.keyringVersion !== next)
    return c.json({ error: "keyringVersion must be the new version" }, 400);

  const rows: { secretId: string; version: number }[] = [];
  for (const s of secrets) {
    const row = await db
      .prepare(
        "SELECT id, current, deleted_at AS deletedAt FROM secret WHERE path = ? AND keyring_id = ?",
      )
      .bind(s.path, g.id)
      .first<{ id: string; current: number; deletedAt: number | null }>();
    if (!row || row.deletedAt)
      return c.json({ error: "secret is not live in this group", path: s.path }, 409);
    if (s.version !== row.current + 1)
      return c.json({ error: "version changed, reload and retry", path: s.path }, 409);
    rows.push({ secretId: row.id, version: s.version });
  }

  try {
    await db.batch(
      secrets.flatMap((s, i) => {
        const r = rows[i] as { secretId: string; version: number };
        return [
          // A retried chunk replaces its own staged rows.
          db
            .prepare(
              "DELETE FROM secret_version WHERE secret_id = ? AND version = ? AND keyring_version = ?",
            )
            .bind(r.secretId, r.version, next),
          db
            .prepare(
              "INSERT INTO secret_version (secret_id, version, keyring_version, names, wrapped_dek, ciphertext, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(
              r.secretId,
              r.version,
              next,
              JSON.stringify(s.names),
              s.wrappedDek,
              s.ciphertext,
              who.id,
              now(),
            ),
        ];
      }),
    );
  } catch {
    return c.json({ error: "group changed, reload and retry" }, 409);
  }
  for (const s of secrets)
    await audit(db, {
      who: who.name,
      action: "secret.rotate",
      path: s.path,
      version: s.version,
      result: "ok",
      ip: c.req.header("CF-Connecting-IP"),
    });
  return c.json({ staged: secrets.length });
});

// Rotation step 3. Refused unless every live secret has a version at the new keyring version.
// The checks are repeated inside the batch, so a chunk that lands in between cannot slip past.
membership.post("/keyrings/:prefix/rotate/commit", requireAdmin, async (c) => {
  const db = c.env.DB;
  const who = c.get("who");
  const prefix = c.req.param("prefix");
  const g = await memberGate(c, prefix, "group.rotate.commit");
  if (g instanceof Response) return g;
  if (g.status !== "rotating") return c.json({ error: "group is not rotating" }, 409);
  const next = g.version + 1;

  const missing = await db
    .prepare(
      `SELECT s.path FROM secret s WHERE s.keyring_id = ? AND s.deleted_at IS NULL
       AND NOT EXISTS (SELECT 1 FROM secret_version v WHERE v.secret_id = s.id AND v.keyring_version = ?)
       ORDER BY s.path`,
    )
    .bind(g.id, next)
    .all<{ path: string }>();
  if (missing.results.length)
    return c.json(
      {
        error: "some secrets have no new version yet",
        missing: missing.results.map((r) => r.path),
      },
      409,
    );

  try {
    await db.batch([
      db
        .prepare(
          `UPDATE keyring SET version = ?, status = 'active' WHERE id = ? AND status = 'rotating'
           AND NOT EXISTS (SELECT 1 FROM secret s WHERE s.keyring_id = ? AND s.deleted_at IS NULL
             AND NOT EXISTS (SELECT 1 FROM secret_version v WHERE v.secret_id = s.id AND v.keyring_version = ?))`,
        )
        .bind(next, g.id, g.id, next),
      // The statements below only apply if the keyring flip above happened.
      db
        .prepare(
          `UPDATE secret SET current = current + 1 WHERE keyring_id = ? AND deleted_at IS NULL
           AND EXISTS (SELECT 1 FROM secret_version v WHERE v.secret_id = secret.id AND v.keyring_version = ?)
           AND EXISTS (SELECT 1 FROM keyring WHERE id = ? AND version = ?)`,
        )
        .bind(g.id, next, g.id, next),
      db
        .prepare(
          `INSERT INTO keyring_member (keyring_id, identity_id, version, wrapped_key)
           SELECT keyring_id, identity_id, version, wrapped_key FROM keyring_member_staged
           WHERE keyring_id = ? AND version = ? AND EXISTS (SELECT 1 FROM keyring WHERE id = ? AND version = ?)`,
        )
        .bind(g.id, next, g.id, next),
      db
        .prepare(
          "DELETE FROM keyring_member_staged WHERE keyring_id = ? AND EXISTS (SELECT 1 FROM keyring WHERE id = ? AND version = ?)",
        )
        .bind(g.id, g.id, next),
    ]);
  } catch {
    return c.json({ error: "group changed, reload and retry" }, 409);
  }
  const after = await loadGroup(db, prefix);
  if (after?.version !== next || after.status !== "active")
    return c.json({ error: "group changed, reload and retry" }, 409);
  await audit(db, {
    who: who.name,
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
  if (g.status !== "rotating") return c.json({ error: "group is not rotating" }, 409);
  const next = g.version + 1;
  try {
    await db.batch([
      db
        .prepare(
          "DELETE FROM secret_version WHERE keyring_version = ? AND secret_id IN (SELECT id FROM secret WHERE keyring_id = ?)",
        )
        .bind(next, g.id),
      db.prepare("DELETE FROM keyring_member_staged WHERE keyring_id = ?").bind(g.id),
      db
        .prepare("UPDATE keyring SET status = 'active' WHERE id = ? AND status = 'rotating'")
        .bind(g.id),
    ]);
  } catch {
    return c.json({ error: "group changed, reload and retry" }, 409);
  }
  await audit(db, {
    who: who.name,
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
  const t = await db
    .prepare(
      "SELECT id, kind, name, role, status, public_key AS publicKey FROM identity WHERE id = ?",
    )
    .bind(id)
    .first<{
      id: string;
      kind: string;
      name: string;
      role: string;
      status: string;
      publicKey: string | null;
    }>();
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
    return c.json({ error: "at least two admins must hold a vault" }, 409);

  const statements = [
    db.prepare("UPDATE identity SET role = ?, status = ? WHERE id = ?").bind(role, status, t.id),
  ];
  if (status === "disabled")
    statements.push(db.prepare("DELETE FROM session WHERE identity_id = ?").bind(t.id));
  await db.batch(statements);

  const ip = c.req.header("CF-Connecting-IP");
  if (status !== t.status)
    await audit(db, {
      who: who.name,
      action: status === "disabled" ? "identity.disable" : "identity.enable",
      note: t.name,
      result: "ok",
      ip,
    });
  if (role !== t.role)
    await audit(db, {
      who: who.name,
      action: "identity.role",
      note: `${t.name}: ${t.role} -> ${role}`,
      result: "ok",
      ip,
    });
  return c.json({ id: t.id, role, status });
});
