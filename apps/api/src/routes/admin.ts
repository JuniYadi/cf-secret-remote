import { GENESIS, verifyChain } from "@cfs/core";
import { Hono } from "hono";
import { audit } from "../audit.ts";
import { requireAdmin } from "../auth.ts";
import { prefixOf } from "../policy.ts";
import type { AppEnv } from "../types.ts";
import { newId, newToken, now, sha256Hex } from "../util.ts";

export const admin = new Hono<AppEnv>();
admin.use("/policies/*", requireAdmin);
admin.use("/policies", requireAdmin);
admin.use("/apps", requireAdmin);
admin.use("/audit/*", requireAdmin);
admin.use("/audit", requireAdmin);

admin.get("/policies", async (c) =>
  c.json(
    (
      await c.env.DB.prepare("SELECT id, name, rules FROM policy ORDER BY name").all<{
        rules: string;
      }>()
    ).results.map((p) => ({ ...p, rules: JSON.parse(p.rules) })),
  ),
);

admin.post("/policies", async (c) => {
  const b = await c.req.json<{ name?: string; rules?: { path: string; caps: string[] }[] }>();
  const caps = ["create", "read", "update", "delete", "list"];
  if (
    !b.name ||
    !Array.isArray(b.rules) ||
    b.rules.some((r) => !r.path || !r.caps?.every((x) => caps.includes(x)))
  )
    return c.json({ error: "bad request" }, 400);
  const id = newId();
  try {
    await c.env.DB.prepare("INSERT INTO policy (id, name, rules) VALUES (?, ?, ?)")
      .bind(id, b.name, JSON.stringify(b.rules))
      .run();
  } catch {
    return c.json({ error: "name already used" }, 409);
  }
  await audit(c.env.DB, {
    who: c.get("who").name,
    action: "policy.create",
    note: b.name,
    result: "ok",
  });
  return c.json({ id }, 201);
});

admin.post("/policies/:id/assign", async (c) => {
  const b = await c.req.json<{ identityId?: string; expiresAt?: number }>();
  if (!b.identityId) return c.json({ error: "bad request" }, 400);
  await c.env.DB.prepare(
    "INSERT OR REPLACE INTO identity_policy (identity_id, policy_id, expires_at) VALUES (?, ?, ?)",
  )
    .bind(b.identityId, c.req.param("id"), b.expiresAt ?? null)
    .run();
  await audit(c.env.DB, {
    who: c.get("who").name,
    action: "policy.assign",
    note: `${c.req.param("id")} -> ${b.identityId}`,
    result: "ok",
  });
  return c.json({ ok: true });
});

// New app/bot. The browser makes its key pair and puts the private key in the kit; only the public key comes here.
// secret_id is returned once and stored as a hash.
admin.post("/apps", async (c) => {
  const b = await c.req.json<{
    name?: string;
    publicKey?: string;
    tokenTtl?: number;
    maxUses?: number;
    cidr?: string;
  }>();
  if (!b.name || !b.publicKey) return c.json({ error: "bad request" }, 400);
  const id = newId();
  const roleId = newId();
  const secretId = newToken("cfssid");
  try {
    await c.env.DB.batch([
      c.env.DB.prepare(
        "INSERT INTO identity (id, kind, name, role, public_key, created_at) VALUES (?, 'app', ?, 'member', ?, ?)",
      ).bind(id, b.name, b.publicKey, now()),
      c.env.DB.prepare(
        "INSERT INTO app_role (identity_id, role_id, secret_hash, token_ttl, max_uses, cidr) VALUES (?, ?, ?, ?, ?, ?)",
      ).bind(
        id,
        roleId,
        await sha256Hex(secretId),
        b.tokenTtl ?? 3600,
        b.maxUses ?? null,
        b.cidr ?? null,
      ),
    ]);
  } catch {
    return c.json({ error: "name already used" }, 409);
  }
  await audit(c.env.DB, {
    who: c.get("who").name,
    action: "app.create",
    note: b.name,
    result: "ok",
  });
  return c.json({ id, roleId, secretId }, 201);
});

admin.get("/audit", async (c) => {
  const q = c.req.query();
  const rows = await c.env.DB.prepare(
    "SELECT seq, entry, hash FROM audit ORDER BY seq DESC LIMIT ?",
  )
    .bind(Math.min(Number(q.limit) || 100, 500))
    .all<{ seq: number; entry: string; hash: string }>();
  return c.json(rows.results.map((r) => ({ seq: r.seq, hash: r.hash, ...JSON.parse(r.entry) })));
});

// Re-checks the whole chain; also what the daily head hash is taken from.
admin.get("/audit/verify", async (c) => {
  const rows = await c.env.DB.prepare("SELECT entry, hash FROM audit ORDER BY seq").all<{
    entry: string;
    hash: string;
  }>();
  const bad = await verifyChain(
    rows.results.map((r) => ({ entry: JSON.parse(r.entry), hash: r.hash })),
    GENESIS,
  );
  return c.json({
    ok: bad === -1,
    rows: rows.results.length,
    firstBad: bad === -1 ? null : bad,
    head: rows.results.at(-1)?.hash ?? GENESIS,
  });
});

void prefixOf;
