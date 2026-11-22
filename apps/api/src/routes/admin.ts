import { GENESIS, verifyChain } from "@cfs/core";
import { Hono } from "hono";
import { audit } from "../audit.ts";
import { requireAdmin } from "../auth.ts";
import { prefixOf } from "../policy.ts";
import type { AppEnv } from "../types.ts";
import { newId, now } from "../util.ts";

export const admin = new Hono<AppEnv>();
admin.use("/policies/*", requireAdmin);
admin.use("/policies", requireAdmin);
admin.use("/audit/*", requireAdmin);
admin.use("/audit", requireAdmin);

// Each policy lists who holds it (identity id, name, kind, and expiry if any), so the web can show roles.
admin.get("/policies", async (c) => {
  const db = c.env.DB;
  const policies = await db
    .prepare("SELECT id, name, rules FROM policy ORDER BY name")
    .all<{ id: string; name: string; rules: string }>();
  const holders = await db
    .prepare(
      `SELECT ip.policy_id AS policyId, i.id AS identityId, i.name, i.kind, ip.expires_at AS expiresAt
       FROM identity_policy ip JOIN identity i ON i.id = ip.identity_id ORDER BY i.name`,
    )
    .all<{
      policyId: string;
      identityId: string;
      name: string;
      kind: string;
      expiresAt: number | null;
    }>();
  return c.json(
    policies.results.map((p) => ({
      id: p.id,
      name: p.name,
      rules: JSON.parse(p.rules),
      assignees: holders.results
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

type AuditDbRow = { seq: number; entry: string; hash: string };

async function auditRows(
  db: D1Database,
  f: { where: string[]; binds: (string | number)[] },
  limit: number,
) {
  const sql = `SELECT seq, entry, hash FROM audit${f.where.length ? ` WHERE ${f.where.join(" AND ")}` : ""} ORDER BY seq DESC LIMIT ?`;
  const rows = await db
    .prepare(sql)
    .bind(...f.binds, limit)
    .all<AuditDbRow>();
  return rows.results.map(
    (r) =>
      ({ seq: r.seq, hash: r.hash, ...JSON.parse(r.entry) }) as {
        seq: number;
        hash: string;
        who: string;
        at: number;
        action: string;
        path?: string;
        version?: number;
        result: string;
        ip?: string;
        note?: string;
      },
  );
}

/** Whether each name is a person or an app, by identity name. A name that is both reads as user; an unknown name is null. */
async function kindsOf(db: D1Database, names: string[]): Promise<Map<string, "user" | "app">> {
  const kinds = new Map<string, "user" | "app">();
  const unique = [...new Set(names)];
  // D1 allows 100 bound parameters per statement.
  for (let i = 0; i < unique.length; i += 90) {
    const chunk = unique.slice(i, i + 90);
    const found = await db
      .prepare(`SELECT name, kind FROM identity WHERE name IN (${chunk.map(() => "?").join(",")})`)
      .bind(...chunk)
      .all<{ name: string; kind: "user" | "app" }>();
    for (const r of found.results) if (kinds.get(r.name) !== "user") kinds.set(r.name, r.kind);
  }
  return kinds;
}

admin.get("/audit", async (c) => {
  const f = auditFilter(c.req.query());
  if ("error" in f) return c.json({ error: f.error }, 400);
  const limit = Math.min(Number(c.req.query("limit")) || 100, 500);
  const rows = await auditRows(c.env.DB, f, limit);
  const kinds = await kindsOf(
    c.env.DB,
    rows.map((r) => r.who),
  );
  return c.json(rows.map((r) => ({ ...r, kind: kinds.get(r.who) ?? null })));
});

// ADR 24 (Activity stat cards): the last 24 hours. `accesses` are allowed reads, `byApps` the ones made by apps.
admin.get("/audit/stats", async (c) => {
  const since = now() - 86400;
  const db = c.env.DB;
  const one = async (sql: string, ...binds: (string | number)[]) =>
    (
      await db
        .prepare(sql)
        .bind(...binds)
        .first<{ n: number }>()
    )?.n ?? 0;
  const reads =
    "at >= ? AND json_extract(entry, '$.action') = 'secret.read' AND json_extract(entry, '$.result') = 'ok'";
  const [accesses, byApps, blocked, actors] = await Promise.all([
    one(`SELECT count(*) AS n FROM audit WHERE ${reads}`, since),
    one(
      `SELECT count(*) AS n FROM audit WHERE ${reads} AND who IN (SELECT name FROM identity WHERE kind = 'app')`,
      since,
    ),
    one(
      "SELECT count(*) AS n FROM audit WHERE at >= ? AND json_extract(entry, '$.result') = 'denied'",
      since,
    ),
    one("SELECT count(DISTINCT who) AS n FROM audit WHERE at >= ? AND who != 'system'", since),
  ]);
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
  const rows = await auditRows(c.env.DB, f, CSV_MAX_ROWS);
  const kinds = await kindsOf(
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
