import { b64uDecode, LOGIN_CIPHERTEXT_LIMIT } from "@cfs/core";
import { Hono } from "hono";
import { audit } from "../audit.ts";
import type { AppEnv } from "../types.ts";
import { now, sha256Hex } from "../util.ts";
import { RESTORE_WINDOW } from "./versions.ts";

export const logins = new Hono<AppEnv>();
const idOk = (id: unknown): id is string =>
  typeof id === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(id);
const fields = ["name", "url", "environment", "role", "username", "password", "totp", "notes"];
type Input = {
  id?: unknown;
  keyringId?: unknown;
  keyringVersion?: unknown;
  version?: unknown;
  wrappedDek?: unknown;
  ciphertext?: unknown;
  fps?: unknown;
};
export function validInput(b: Input): boolean {
  if (
    !idOk(b.keyringId) ||
    !Number.isSafeInteger(b.keyringVersion) ||
    (b.keyringVersion as number) < 1 ||
    !Number.isSafeInteger(b.version) ||
    (b.version as number) < 1 ||
    typeof b.wrappedDek !== "string" ||
    !b.wrappedDek ||
    typeof b.ciphertext !== "string"
  )
    return false;
  if (
    !b.fps ||
    typeof b.fps !== "object" ||
    Array.isArray(b.fps) ||
    Object.keys(b.fps).length !== fields.length ||
    fields.some(
      (f) =>
        typeof (b.fps as Record<string, unknown>)[f] !== "string" ||
        !/^[0-9a-f]{16}$/.test((b.fps as Record<string, string>)[f] ?? ""),
    )
  )
    return false;
  return true;
}
export function ciphertextSize(value: string): number | null {
  const parts = value.split(".");
  if (
    parts.length !== 3 ||
    parts[0] !== "v1" ||
    !parts[1] ||
    !parts[2] ||
    !/^[A-Za-z0-9_-]+$/.test(parts[1]) ||
    !/^[A-Za-z0-9_-]+$/.test(parts[2])
  )
    return null;
  try {
    return b64uDecode(parts[2]).length;
  } catch {
    return null;
  }
}
async function member(db: D1Database, keyringId: string, identityId: string) {
  return db
    .prepare(
      `SELECT k.version, k.status FROM keyring k JOIN keyring_member m ON m.keyring_id = k.id AND m.version = k.version WHERE k.id = ? AND m.identity_id = ? AND (m.expires_at IS NULL OR m.expires_at > ?)`,
    )
    .bind(keyringId, identityId, now())
    .first<{ version: number; status: string }>();
}
async function item(db: D1Database, id: string, identityId: string, deleted = false) {
  return db
    .prepare(
      `SELECT l.id, l.keyring_id AS keyringId, l.current, l.created_at AS createdAt, l.deleted_at AS deletedAt FROM login l JOIN keyring k ON k.id = l.keyring_id JOIN keyring_member m ON m.keyring_id = k.id AND m.version = k.version WHERE l.id = ? AND m.identity_id = ? AND (m.expires_at IS NULL OR m.expires_at > ?) AND l.deleted_at IS ${deleted ? "NOT NULL" : "NULL"}`,
    )
    .bind(id, identityId, now())
    .first<{
      id: string;
      keyringId: string;
      current: number;
      createdAt: number;
      deletedAt: number | null;
    }>();
}
const selectVersion = `SELECT v.version, v.keyring_id AS keyringId, v.keyring_version AS keyringVersion, v.wrapped_dek AS wrappedDek, v.ciphertext, v.fps, v.created_at AS updatedAt, length(v.ciphertext) AS size FROM login_version v`;
logins.get("/logins", async (c) => {
  const snapshot = await c.env.DB.prepare(
    `SELECT l.id, l.created_at AS createdAt, v.version, v.keyring_id AS keyringId, v.keyring_version AS keyringVersion, v.wrapped_dek AS wrappedDek, v.ciphertext, v.fps, v.created_at AS updatedAt, length(v.ciphertext) AS size FROM login l JOIN login_version v ON v.login_id = l.id AND v.version = l.current JOIN keyring k ON k.id = l.keyring_id JOIN keyring_member m ON m.keyring_id = k.id AND m.version = k.version WHERE m.identity_id = ? AND (m.expires_at IS NULL OR m.expires_at > ?) AND l.deleted_at IS NULL ORDER BY l.id`,
  )
    .bind(c.get("who").id, now())
    .all<{ fps: string }>();
  const body = JSON.stringify(snapshot.results.map((r) => ({ ...r, fps: JSON.parse(r.fps) })));
  const etag = `"${await sha256Hex(body)}"`;
  c.header("ETag", etag);
  if (
    c.req
      .header("If-None-Match")
      ?.split(",")
      .some((v) => v.trim() === etag || v.trim() === "*")
  )
    return c.body(null, 304);
  return c.body(body, 200, { "Content-Type": "application/json" });
});
logins.get("/logins/:id/versions", async (c) => {
  const l = await item(c.env.DB, c.req.param("id"), c.get("who").id);
  if (!l) return c.json({ error: "not found" }, 404);
  const rows = await c.env.DB.prepare(
    `SELECT v.version, v.keyring_id AS keyringId, v.keyring_version AS keyringVersion, v.fps, v.created_at AS createdAt FROM login_version v JOIN keyring_member m ON m.keyring_id = v.keyring_id AND m.identity_id = ? AND m.version = v.keyring_version WHERE v.login_id = ? AND (m.expires_at IS NULL OR m.expires_at > ?) ORDER BY v.version DESC`,
  )
    .bind(c.get("who").id, l.id, now())
    .all<{ fps: string }>();
  return c.json(rows.results.map((r) => ({ ...r, fps: JSON.parse(r.fps) })));
});
logins.get("/logins/:id/versions/:version", async (c) => {
  const l = await item(c.env.DB, c.req.param("id"), c.get("who").id);
  const version = Number(c.req.param("version"));
  if (!l || !Number.isSafeInteger(version) || version < 1)
    return c.json({ error: "not found" }, 404);
  const row = await c.env.DB.prepare(
    `${selectVersion} JOIN keyring_member m ON m.keyring_id = v.keyring_id AND m.version = v.keyring_version AND m.identity_id = ? WHERE v.login_id = ? AND v.version = ? AND (m.expires_at IS NULL OR m.expires_at > ?)`,
  )
    .bind(c.get("who").id, l.id, version, now())
    .first<{ fps: string }>();
  return row
    ? c.json({ ...row, id: l.id, createdAt: l.createdAt, fps: JSON.parse(row.fps) })
    : c.json({ error: "not found" }, 404);
});
logins.get("/logins/:id", async (c) => {
  const l = await item(c.env.DB, c.req.param("id"), c.get("who").id);
  if (!l) return c.json({ error: "not found" }, 404);
  const row = await c.env.DB.prepare(`${selectVersion} WHERE v.login_id = ? AND v.version = ?`)
    .bind(l.id, l.current)
    .first<{ fps: string }>();
  return row
    ? c.json({ ...row, id: l.id, createdAt: l.createdAt, fps: JSON.parse(row.fps) })
    : c.json({ error: "not found" }, 404);
});
async function write(
  c: import("hono").Context<AppEnv>,
  mode: "create" | "update" | "move" | "restore",
) {
  const b = await c.req.json<Input>().catch(() => ({}) as Input);
  if (!b || !validInput(b) || (mode === "create" && !idOk(b.id)))
    return c.json({ error: "bad request" }, 400);
  const size = ciphertextSize(b.ciphertext as string);
  if (size === null) return c.json({ error: "bad ciphertext" }, 400);
  if (size > LOGIN_CIPHERTEXT_LIMIT) return c.json({ error: "too large" }, 413);
  const who = c.get("who");
  const id = mode === "create" ? (b.id as string) : (c.req.param("id") as string);
  const old = mode === "create" ? null : await item(c.env.DB, id, who.id);
  if (mode !== "create" && !old) return c.json({ error: "not found" }, 404);
  if (old && (await member(c.env.DB, old.keyringId, who.id))?.status !== "active")
    return c.json({ error: "keyring rotating" }, 409);
  if (old && mode !== "move" && old.keyringId !== b.keyringId)
    return c.json({ error: "wrong keyring" }, 400);
  if (old && mode === "move" && old.keyringId === b.keyringId)
    return c.json({ error: "same keyring" }, 400);
  const group = await member(c.env.DB, b.keyringId as string, who.id);
  if (!group) return c.json({ error: "not found" }, 404);
  if (group.status !== "active" || group.version !== b.keyringVersion)
    return c.json({ error: "keyring changed or rotating" }, 409);
  const version = (old?.current ?? 0) + 1;
  if (b.version !== version) return c.json({ error: "version changed, reload and retry" }, 409);
  if (mode === "restore") {
    const target = Number(c.req.param("version"));
    const source = await c.env.DB.prepare(
      `SELECT 1 FROM login_version v JOIN keyring_member m ON m.keyring_id = v.keyring_id AND m.version = v.keyring_version WHERE v.login_id = ? AND v.version = ? AND m.identity_id = ? AND (m.expires_at IS NULL OR m.expires_at > ?)`,
    )
      .bind(id, target, who.id, now())
      .first();
    if (!source) return c.json({ error: "not found" }, 404);
  }
  if (
    mode === "create" &&
    (await c.env.DB.prepare("SELECT 1 FROM login WHERE id = ?").bind(id).first())
  )
    return c.json({ error: "already exists" }, 409);
  const written = await c.env.DB.batch([
    old
      ? c.env.DB.prepare(
          "UPDATE login SET current = ?, keyring_id = ? WHERE id = ? AND current = ? AND deleted_at IS NULL AND EXISTS (SELECT 1 FROM keyring WHERE id = ? AND version = ? AND status = 'active')",
        ).bind(version, b.keyringId, id, old.current, b.keyringId, b.keyringVersion)
      : c.env.DB.prepare(
          "INSERT INTO login (id, keyring_id, current, created_at) SELECT ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM keyring WHERE id = ? AND version = ? AND status = 'active')",
        ).bind(id, b.keyringId, version, now(), b.keyringId, b.keyringVersion),
    c.env.DB.prepare(
      "INSERT INTO login_version (login_id, version, keyring_id, keyring_version, wrapped_dek, ciphertext, fps, created_by, created_at) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM login WHERE id = ? AND current = ? AND keyring_id = ? AND deleted_at IS NULL)",
    ).bind(
      id,
      version,
      b.keyringId,
      b.keyringVersion,
      b.wrappedDek,
      b.ciphertext,
      JSON.stringify(b.fps),
      who.id,
      now(),
      id,
      version,
      b.keyringId,
    ),
  ]);
  if (!written[0]?.meta.changes) return c.json({ error: "keyring or version changed" }, 409);
  await audit(c.env.DB, {
    who: who.name,
    action: `login.${mode}`,
    path: id,
    version,
    result: "ok",
  });
  return c.json({ id, version }, mode === "create" ? 201 : 200);
}
logins.post("/logins", (c) => write(c, "create"));
logins.put("/logins/:id", (c) => write(c, "update"));
logins.post("/logins/:id/move", (c) => write(c, "move"));
logins.post("/logins/:id/versions/:version/restore", (c) => write(c, "restore"));
logins.delete("/logins/:id", async (c) => {
  const l = await item(c.env.DB, c.req.param("id"), c.get("who").id);
  if (!l) return c.json({ error: "not found" }, 404);
  await c.env.DB.prepare("UPDATE login SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL")
    .bind(now(), l.id)
    .run();
  await audit(c.env.DB, {
    who: c.get("who").name,
    action: "login.delete",
    path: l.id,
    version: l.current,
    result: "ok",
  });
  return c.json({ ok: true });
});
logins.post("/logins/:id/undelete", async (c) => {
  const l = await item(c.env.DB, c.req.param("id"), c.get("who").id, true);
  if (!l) return c.json({ error: "not found" }, 404);
  if (now() - (l.deletedAt as number) > RESTORE_WINDOW)
    return c.json({ error: "too old to restore" }, 410);
  await c.env.DB.prepare("UPDATE login SET deleted_at = NULL WHERE id = ?").bind(l.id).run();
  return c.json({ ok: true });
});

for (const action of ["reveal", "fill"] as const) {
  logins.post(`/logins/:id/${action}`, async (c) => {
    const body = await c.req.json<{ field?: unknown; purpose?: unknown }>().catch(() => null);
    if (
      !body ||
      typeof body !== "object" ||
      Array.isArray(body) ||
      Object.keys(body).some((k) => k !== "field" && k !== "purpose") ||
      (body.field !== undefined &&
        (typeof body.field !== "string" || !fields.includes(body.field))) ||
      (body.purpose !== undefined &&
        (typeof body.purpose !== "string" || body.purpose.length > 500))
    )
      return c.json({ error: "bad request" }, 400);
    const l = await item(c.env.DB, c.req.param("id"), c.get("who").id);
    if (!l) return c.json({ error: "not found" }, 404);
    await audit(c.env.DB, {
      who: c.get("who").name,
      action: `login.${action}`,
      path: l.id,
      version: l.current,
      result: "ok",
      ...(body.purpose !== undefined ? { purpose: body.purpose as string } : {}),
    });
    return c.json({ ok: true });
  });
}

/** Purge Login versions once their 30-day restore window has expired. */
export async function purgeDeletedLogins(db: D1Database, at: number = now()): Promise<void> {
  await db.batch([
    db
      .prepare(
        "DELETE FROM login_version WHERE login_id IN (SELECT id FROM login WHERE deleted_at IS NOT NULL AND deleted_at < ?)",
      )
      .bind(at - RESTORE_WINDOW),
    db
      .prepare("DELETE FROM login WHERE deleted_at IS NOT NULL AND deleted_at < ?")
      .bind(at - RESTORE_WINDOW),
  ]);
}
