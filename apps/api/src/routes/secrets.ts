import { Hono } from "hono";
import { audit } from "../audit.ts";
import { NAME_RE } from "../limits.ts";
import { type Cap, can, prefixOf, type Rule, validPath } from "../policy.ts";
import type { AppEnv, Who } from "../types.ts";
import { newId, now } from "../util.ts";

export const secrets = new Hono<AppEnv>();

async function rulesFor(db: D1Database, who: Who): Promise<Rule[]> {
  if (who.role === "admin")
    return [{ path: "*", caps: ["create", "read", "update", "delete", "list"] }];
  const rows = await db
    .prepare(
      `SELECT p.rules FROM identity_policy ip JOIN policy p ON p.id = ip.policy_id
       WHERE ip.identity_id = ? AND (ip.expires_at IS NULL OR ip.expires_at > ?)`,
    )
    .bind(who.id, now())
    .all<{ rules: string }>();
  return rows.results.flatMap((r) => JSON.parse(r.rules) as Rule[]);
}

async function check(
  c: {
    env: { DB: D1Database };
    get: (k: "who") => Who;
    req: { header: (n: string) => string | undefined };
  },
  path: string,
  cap: Cap,
): Promise<boolean> {
  const who = c.get("who");
  const ok = can(await rulesFor(c.env.DB, who), path, cap);
  if (!ok)
    await audit(c.env.DB, {
      who: who.name,
      action: `secret.${cap}`,
      path,
      result: "denied",
      ip: c.req.header("CF-Connecting-IP"),
    });
  return ok;
}

// List: names only, filtered by the caller's list permission. Never values.
secrets.get("/secrets", async (c) => {
  const who = c.get("who");
  const rules = await rulesFor(c.env.DB, who);
  const rows = await c.env.DB.prepare(
    `SELECT s.path, s.current AS version, v.names, v.created_at AS updatedAt
     FROM secret s JOIN secret_version v ON v.secret_id = s.id AND v.version = s.current
     WHERE s.deleted_at IS NULL ORDER BY s.path`,
  ).all<{ path: string; version: number; names: string; updatedAt: number }>();
  return c.json(
    rows.results
      .filter((r) => can(rules, r.path, "list"))
      .map((r) => ({ ...r, names: JSON.parse(r.names) as string[] })),
  );
});

// Read: returns ciphertext and the wrapped DEK. The caller still needs the group key to open it. Logged as a fetch.
secrets.get("/secret", async (c) => {
  const path = c.req.query("path") ?? "";
  if (!validPath(path)) return c.json({ error: "bad path" }, 400);
  if (!(await check(c, path, "read"))) return c.json({ error: "denied" }, 403);
  const want = c.req.query("version");
  const row = await c.env.DB.prepare(
    `SELECT v.version, v.keyring_version AS keyringVersion, v.names, v.wrapped_dek AS wrappedDek, v.ciphertext, v.created_at AS createdAt
     FROM secret s JOIN secret_version v ON v.secret_id = s.id AND v.version = COALESCE(?, s.current)
     WHERE s.path = ? AND s.deleted_at IS NULL`,
  )
    .bind(want ? Number(want) : null, path)
    .first<{ version: number; names: string }>();
  if (!row) return c.json({ error: "not found" }, 404);
  const who = c.get("who");
  await audit(c.env.DB, {
    who: who.name,
    action: "secret.read",
    path,
    version: row.version,
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ ...row, names: JSON.parse(row.names) });
});

// Write: the client sends an already-encrypted version. The server cannot read or validate the values.
secrets.put("/secret", async (c) => {
  const who = c.get("who");
  const b = await c.req.json<{
    path?: string;
    names?: string[];
    wrappedDek?: string;
    ciphertext?: string;
    keyringVersion?: number;
    version?: number;
  }>();
  const { path, names, wrappedDek, ciphertext, keyringVersion } = b;
  if (
    !path ||
    !validPath(path) ||
    !Array.isArray(names) ||
    !wrappedDek ||
    !ciphertext ||
    !ciphertext.startsWith("v1.") ||
    !keyringVersion
  ) {
    return c.json({ error: "bad request" }, 400);
  }
  if (names.some((n) => typeof n !== "string" || !NAME_RE.test(n)))
    return c.json({ error: "bad name" }, 400);
  const keyring = await c.env.DB.prepare("SELECT id, version FROM keyring WHERE prefix = ?")
    .bind(prefixOf(path))
    .first<{ id: string; version: number }>();
  if (!keyring) return c.json({ error: "create the group first" }, 409);
  if (keyringVersion !== keyring.version)
    return c.json({ error: "group key changed, reload and retry" }, 409);

  const existing = await c.env.DB.prepare("SELECT id, current FROM secret WHERE path = ?")
    .bind(path)
    .first<{ id: string; current: number }>();
  const cap: Cap = existing ? "update" : "create";
  if (!(await check(c, path, cap))) return c.json({ error: "denied" }, 403);

  const id = existing?.id ?? newId();
  const version = (existing?.current ?? 0) + 1;
  // ADR 10: the client sealed for this exact version, so it must be the next one.
  if (b.version !== version)
    return c.json(
      { error: "version changed, reload and retry", current: existing?.current ?? 0 },
      409,
    );
  const stmts = [
    existing
      ? c.env.DB.prepare("UPDATE secret SET current = ?, deleted_at = NULL WHERE id = ?").bind(
          version,
          id,
        )
      : c.env.DB.prepare(
          "INSERT INTO secret (id, path, keyring_id, current, created_at) VALUES (?, ?, ?, ?, ?)",
        ).bind(id, path, keyring.id, version, now()),
    c.env.DB.prepare(
      "INSERT INTO secret_version (secret_id, version, keyring_version, names, wrapped_dek, ciphertext, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    ).bind(
      id,
      version,
      keyringVersion,
      JSON.stringify(names),
      wrappedDek,
      ciphertext,
      who.id,
      now(),
    ),
  ];
  await c.env.DB.batch(stmts);
  await audit(c.env.DB, {
    who: who.name,
    action: "secret.write",
    path,
    version,
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ path, version }, existing ? 200 : 201);
});

secrets.delete("/secret", async (c) => {
  const path = c.req.query("path") ?? "";
  if (!validPath(path)) return c.json({ error: "bad path" }, 400);
  if (!(await check(c, path, "delete"))) return c.json({ error: "denied" }, 403);
  const res = await c.env.DB.prepare(
    "UPDATE secret SET deleted_at = ? WHERE path = ? AND deleted_at IS NULL",
  )
    .bind(now(), path)
    .run();
  if (!res.meta.changes) return c.json({ error: "not found" }, 404);
  await audit(c.env.DB, {
    who: c.get("who").name,
    action: "secret.delete",
    path,
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ ok: true });
});

// Version history: metadata only, with who and when.
secrets.get("/secret/versions", async (c) => {
  const path = c.req.query("path") ?? "";
  if (!(await check(c, path, "list"))) return c.json({ error: "denied" }, 403);
  const rows = await c.env.DB.prepare(
    `SELECT v.version, v.names, v.created_at AS createdAt, i.name AS createdBy
     FROM secret s JOIN secret_version v ON v.secret_id = s.id JOIN identity i ON i.id = v.created_by
     WHERE s.path = ? ORDER BY v.version DESC`,
  )
    .bind(path)
    .all<{ names: string }>();
  return c.json(rows.results.map((r) => ({ ...r, names: JSON.parse(r.names) })));
});
