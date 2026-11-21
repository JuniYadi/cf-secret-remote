import { GENESIS, verifyChain } from "@cfs/core";
import { Hono } from "hono";
import { audit } from "../audit.ts";
import { requireAdmin } from "../auth.ts";
import { prefixOf } from "../policy.ts";
import type { AppEnv } from "../types.ts";
import { newId } from "../util.ts";

export const admin = new Hono<AppEnv>();
admin.use("/policies/*", requireAdmin);
admin.use("/policies", requireAdmin);
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

admin.get("/audit", async (c) => {
  const q = c.req.query();
  const rows = await c.env.DB.prepare(
    "SELECT seq, entry, hash FROM audit ORDER BY seq DESC LIMIT ?",
  )
    .bind(Math.min(Number(q.limit) || 100, 500))
    .all<{ seq: number; entry: string; hash: string }>();
  return c.json(rows.results.map((r) => ({ seq: r.seq, hash: r.hash, ...JSON.parse(r.entry) })));
});

// Re-checks the chain from audit_base (or genesis if nothing was pruned), then each stored checkpoint (ADR 19).
// firstBad is the index into the rows after the base; firstBadSeq is that row's seq.
admin.get("/audit/verify", async (c) => {
  const db = c.env.DB;
  const base = await db
    .prepare("SELECT seq, hash FROM audit_base WHERE id = 1")
    .first<{ seq: number; hash: string }>();
  const start = base?.hash ?? GENESIS;
  const rows = await db
    .prepare("SELECT seq, entry, hash FROM audit ORDER BY seq")
    .all<{ seq: number; entry: string; hash: string }>();
  const bad = await verifyChain(
    rows.results.map((r) => ({ entry: JSON.parse(r.entry), hash: r.hash })),
    start,
  );
  const bySeq = new Map(rows.results.map((r) => [r.seq, r.hash]));
  const cps = await db
    .prepare("SELECT day, seq, head FROM checkpoint ORDER BY day")
    .all<{ day: string; seq: number; head: string }>();
  const checkpoints = {
    stored: cps.results.length,
    verified: 0,
    pruned: 0,
    mismatched: [] as string[],
  };
  for (const cp of cps.results) {
    if (cp.seq === 0) {
      // Taken on an empty chain.
      if (cp.head === GENESIS && !base) checkpoints.verified++;
      else if (cp.head === GENESIS) checkpoints.pruned++;
      else checkpoints.mismatched.push(cp.day);
    } else if (base && cp.seq === base.seq) {
      if (cp.head === base.hash) checkpoints.verified++;
      else checkpoints.mismatched.push(cp.day);
    } else if (base && cp.seq < base.seq) {
      checkpoints.pruned++; // the row is gone by design; retention wrote this checkpoint first
    } else if (bySeq.get(cp.seq) === cp.head) {
      checkpoints.verified++;
    } else {
      checkpoints.mismatched.push(cp.day); // row missing or rewritten since the checkpoint
    }
  }
  const chainOk = bad === -1;
  return c.json({
    ok: chainOk && checkpoints.mismatched.length === 0,
    rows: rows.results.length,
    firstBad: chainOk ? null : bad,
    firstBadSeq: chainOk ? null : (rows.results[bad]?.seq ?? null),
    head: rows.results.at(-1)?.hash ?? start,
    base: base ? { seq: base.seq, hash: base.hash } : null,
    checkpoints,
  });
});

void prefixOf;
