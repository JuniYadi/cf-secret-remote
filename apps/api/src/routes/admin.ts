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

// ADR 6 / ADR 24 (Activity). Filters are optional and combine with AND:
//   who (exact), action (exact), path (exact, or a prefix when it ends with *), result (ok|denied|error),
//   from and to (unix seconds, from inclusive, to exclusive), before (a seq: only older rows, for paging).
const AUDIT_RESULTS = ["ok", "denied", "error"];
const AUDIT_TEXT_MAX = 200;

const wholeNumber = (v: string | undefined): number | null | undefined => {
  if (v === undefined || v === "") return undefined;
  return /^\d+$/.test(v) ? Number(v) : null;
};

admin.get("/audit", async (c) => {
  const q = c.req.query();
  const where: string[] = [];
  const binds: (string | number)[] = [];
  const text = (name: string): string | undefined => {
    const v = q[name];
    return v === undefined || v === "" ? undefined : v;
  };

  const who = text("who");
  if (who !== undefined) {
    if (who.length > AUDIT_TEXT_MAX) return c.json({ error: "who is too long" }, 400);
    where.push("who = ?");
    binds.push(who);
  }
  const action = text("action");
  if (action !== undefined) {
    if (action.length > AUDIT_TEXT_MAX) return c.json({ error: "action is too long" }, 400);
    where.push("json_extract(entry, '$.action') = ?");
    binds.push(action);
  }
  const path = text("path");
  if (path !== undefined) {
    if (path.length > AUDIT_TEXT_MAX) return c.json({ error: "path is too long" }, 400);
    if (path.endsWith("*")) {
      const prefix = path.slice(0, -1);
      where.push("substr(json_extract(entry, '$.path'), 1, length(?)) = ?");
      binds.push(prefix, prefix);
    } else {
      where.push("json_extract(entry, '$.path') = ?");
      binds.push(path);
    }
  }
  const result = text("result");
  if (result !== undefined) {
    if (!AUDIT_RESULTS.includes(result))
      return c.json({ error: "result must be ok, denied or error" }, 400);
    where.push("json_extract(entry, '$.result') = ?");
    binds.push(result);
  }
  const from = wholeNumber(q.from);
  const to = wholeNumber(q.to);
  const before = wholeNumber(q.before);
  if (from === null || to === null || before === null)
    return c.json({ error: "from, to and before must be whole numbers" }, 400);
  if (from !== undefined) {
    where.push("at >= ?");
    binds.push(from);
  }
  if (to !== undefined) {
    where.push("at < ?");
    binds.push(to);
  }
  if (before !== undefined) {
    where.push("seq < ?");
    binds.push(before);
  }

  const limit = Math.min(Number(q.limit) || 100, 500);
  const sql = `SELECT seq, entry, hash FROM audit${where.length ? ` WHERE ${where.join(" AND ")}` : ""} ORDER BY seq DESC LIMIT ?`;
  const rows = await c.env.DB.prepare(sql)
    .bind(...binds, limit)
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
