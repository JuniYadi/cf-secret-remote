import { GENESIS, verifyChain } from "@cfs/core";
import { Hono } from "hono";
import { audit } from "../audit.ts";
import { requireAdmin } from "../auth.ts";
import { prefixOf } from "../policy.ts";
import * as repo from "../repository/admin.ts";
import type { AppEnv } from "../types.ts";
import { newId, now } from "../util.ts";

export const admin = new Hono<AppEnv>();
admin.use("/policies/*", requireAdmin);
admin.use("/policies", requireAdmin);
admin.use("/audit/*", requireAdmin);
admin.use("/audit", requireAdmin);

// Each policy lists who holds it (identity id, name, kind, and expiry if any), so the web can show roles.
admin.get("/policies", async (c) => {
  const { policies, holders } = await repo.policies(c.env.DB);
  return c.json(
    policies.map((p) => ({
      id: p.id,
      name: p.name,
      rules: JSON.parse(p.rules),
      assignees: holders
        .filter((h) => h.policyId === p.id)
        .map(({ identityId, name, kind, expiresAt }) => ({ identityId, name, kind, expiresAt })),
    })),
  );
});

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
    await repo.createPolicy(c.env.DB, id, b.name, JSON.stringify(b.rules));
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
  await repo.assignPolicy(c.env.DB, b.identityId, c.req.param("id"), b.expiresAt ?? null);
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

type AuditFilter = { where: string[]; binds: (string | number)[] } | { error: string };

/** The shared WHERE for the listing and the CSV export. `kind` is user or app, matched by name against identity. */
function auditFilter(q: Record<string, string>): AuditFilter {
  const where: string[] = [];
  const binds: (string | number)[] = [];
  const text = (name: string): string | undefined => {
    const v = q[name];
    return v === undefined || v === "" ? undefined : v;
  };

  const who = text("who");
  if (who !== undefined) {
    if (who.length > AUDIT_TEXT_MAX) return { error: "who is too long" };
    where.push("who = ?");
    binds.push(who);
  }
  const action = text("action");
  if (action !== undefined) {
    if (action.length > AUDIT_TEXT_MAX) return { error: "action is too long" };
    where.push("json_extract(entry, '$.action') = ?");
    binds.push(action);
  }
  const path = text("path");
  if (path !== undefined) {
    if (path.length > AUDIT_TEXT_MAX) return { error: "path is too long" };
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
    if (!AUDIT_RESULTS.includes(result)) return { error: "result must be ok, denied or error" };
    where.push("json_extract(entry, '$.result') = ?");
    binds.push(result);
  }
  const kind = text("kind");
  if (kind !== undefined) {
    if (kind !== "user" && kind !== "app") return { error: "kind must be user or app" };
    where.push("who IN (SELECT name FROM identity WHERE kind = ?)");
    binds.push(kind);
  }
  const from = wholeNumber(q.from);
  const to = wholeNumber(q.to);
  const before = wholeNumber(q.before);
  if (from === null || to === null || before === null)
    return { error: "from, to and before must be whole numbers" };
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
  return { where, binds };
}

admin.get("/audit", async (c) => {
  const f = auditFilter(c.req.query());
  if ("error" in f) return c.json({ error: f.error }, 400);
  const limit = Math.min(Number(c.req.query("limit")) || 100, 500);
  const rows = await repo.auditRows(c.env.DB, f, limit);
  const kinds = await repo.kindsOf(
    c.env.DB,
    rows.map((r) => r.who),
  );
  return c.json(rows.map((r) => ({ ...r, kind: kinds.get(r.who) ?? null })));
});

// ADR 24 (Activity stat cards): the last 24 hours. `accesses` are allowed reads, `byApps` the ones made by apps.
admin.get("/audit/stats", async (c) => {
  const since = now() - 86400;
  const { accesses, byApps, blocked, actors } = await repo.auditStats(c.env.DB, since);
  return c.json({ since, accesses, byApps, blocked, actors });
});

const CSV_MAX_ROWS = 5000;

/** A CSV cell. Text that starts with = + - @ or a control character gets a leading quote so a spreadsheet won't run it. */
export function csvCell(value: string | number | undefined | null): string {
  let v = value === undefined || value === null ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(v)) v = `'${v}`;
  return /[",\n\r]/.test(v) ? `"${v.replaceAll('"', '""')}"` : v;
}

// The same filters as /audit, as a download. Capped at CSV_MAX_ROWS newest rows; the export itself is logged.
admin.get("/audit/export.csv", async (c) => {
  const f = auditFilter(c.req.query());
  if ("error" in f) return c.json({ error: f.error }, 400);
  const rows = await repo.auditRows(c.env.DB, f, CSV_MAX_ROWS);
  const kinds = await repo.kindsOf(
    c.env.DB,
    rows.map((r) => r.who),
  );
  const head = [
    "seq",
    "time",
    "who",
    "type",
    "action",
    "secret",
    "version",
    "result",
    "ip",
    "note",
  ];
  const lines = [head.join(",")];
  for (const r of rows) {
    lines.push(
      [
        r.seq,
        new Date(r.at * 1000).toISOString(),
        r.who,
        kinds.get(r.who) ?? "",
        r.action,
        r.path,
        r.version,
        r.result,
        r.ip,
        r.note,
      ]
        .map(csvCell)
        .join(","),
    );
  }
  await audit(c.env.DB, {
    who: c.get("who").name,
    action: "audit.export",
    result: "ok",
    note: `${rows.length} rows`,
    ip: c.req.header("CF-Connecting-IP"),
  });
  return new Response(`${lines.join("\r\n")}\r\n`, {
    headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": 'attachment; filename="cfs-activity.csv"',
      "Cache-Control": "no-store",
    },
  });
});

// Re-checks the chain from audit_base (or genesis if nothing was pruned), then each stored checkpoint (ADR 19).
// firstBad is the index into the rows after the base; firstBadSeq is that row's seq.
admin.get("/audit/verify", async (c) => {
  const { base, rows } = await repo.chainRows(c.env.DB);
  const start = base?.hash ?? GENESIS;
  const bad = await verifyChain(
    rows.map((r) => ({ entry: JSON.parse(r.entry), hash: r.hash })),
    start,
  );
  const bySeq = new Map(rows.map((r) => [r.seq, r.hash]));
  const cps = await repo.checkpoints(c.env.DB);
  const checkpoints = {
    stored: cps.length,
    verified: 0,
    pruned: 0,
    mismatched: [] as string[],
  };
  for (const cp of cps) {
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
    rows: rows.length,
    firstBad: chainOk ? null : bad,
    firstBadSeq: chainOk ? null : (rows[bad]?.seq ?? null),
    head: rows.at(-1)?.hash ?? start,
    base: base ? { seq: base.seq, hash: base.hash } : null,
    checkpoints,
  });
});

void prefixOf;
