import { type Context, Hono } from "hono";
import { audit } from "../audit.ts";
import { requireAdmin } from "../auth.ts";
import { findPerson, type Person } from "../repository/identity.ts";
import {
  activeAppsOf,
  findNextOwner,
  findOwnedApp,
  finishOffboard,
  groupsOf,
  planData,
  reassignApp,
  secretNames,
} from "../repository/offboard.ts";
import type { AppEnv } from "../types.ts";
import { now } from "../util.ts";
import { countAdminsWithVault } from "./membership.ts";

// ADR 21. Offboarding: a plan the admin reviews, then idempotent steps. Admin only (default deny).
// Group removal and key rotation run on the client (ADR 14). This file never sees a key or a value.

/** The plan lists secrets the person fetched this many seconds back. */
export const OPEN_WINDOW = 90 * 86400;

export const offboard = new Hono<AppEnv>();
offboard.use("/offboard/*", requireAdmin);

/** Loads the person to offboard. Apps are offboarded with `cfs app disable` (ADR 15). */
async function personOf(c: Context<AppEnv>): Promise<Person | Response> {
  const row = await findPerson(c.env.DB, c.req.param("id"));
  if (!row) return c.json({ error: "unknown identity" }, 404);
  if (row.kind !== "user")
    return c.json({ error: "apps are offboarded with cfs app disable" }, 400);
  return row;
}

/** ADR 20: disabling this person would leave fewer than two admins with a vault. */
async function breaksTwoAdmins(db: D1Database, p: Person): Promise<boolean> {
  const counts = p.role === "admin" && p.status === "active" && !!p.publicKey;
  return counts && (await countAdminsWithVault(db, p.id)) < 2;
}

/** What still blocks finish. Empty lists and false mean finish may proceed. */
async function blockersOf(db: D1Database, p: Person, at: number) {
  const apps = await activeAppsOf(db, p.id);
  return {
    groups: await groupsOf(db, p.id, at),
    apps: apps.map((a) => a.name),
    twoAdmins: await breaksTwoAdmins(db, p),
  };
}

// The plan (admin only). Names and paths only, never values. Opened secrets come from audit, last 90 days.
offboard.get("/offboard/:id/plan", async (c) => {
  const db = c.env.DB;
  const p = await personOf(c);
  if (p instanceof Response) return p;
  const at = now();

  const { sessions, apps, reads } = await planData(db, p.id, p.name, at - OPEN_WINDOW, at);

  const byPath = new Map<string, { versions: Set<number>; opens: number; lastOpened: number }>();
  for (const r of reads.results) {
    const agg = byPath.get(r.path);
    if (agg) {
      agg.versions.add(r.version);
      agg.opens++;
    } else byPath.set(r.path, { versions: new Set([r.version]), opens: 1, lastOpened: r.at });
  }
  const secrets = [];
  for (const [path, agg] of [...byPath].sort(([a], [b]) => a.localeCompare(b))) {
    // Key names come from the stored version rows (names are not secret). A purged secret has none.
    const rows = await secretNames(db, path);
    const names = new Set<string>();
    for (const r of rows.results)
      if (agg.versions.has(r.version))
        for (const n of JSON.parse(r.names) as string[]) names.add(n);
    secrets.push({
      path,
      versions: [...agg.versions].sort((x, y) => x - y),
      names: [...names].sort(),
      opens: agg.opens,
      lastOpened: agg.lastOpened,
    });
  }

  const blockers = await blockersOf(db, p, at);
  return c.json({
    person: { id: p.id, name: p.name, role: p.role, status: p.status },
    groups: await groupsOf(db, p.id, at),
    apps: apps.results,
    sessions: sessions.results,
    opened: { windowDays: OPEN_WINDOW / 86400, secrets },
    blockers,
    canFinish: blockers.groups.length === 0 && blockers.apps.length === 0 && !blockers.twoAdmins,
  });
});

// Reassign one owned app to another active person (ADR 15: every app has an owner).
offboard.post("/offboard/:id/apps/:appId/reassign", async (c) => {
  const db = c.env.DB;
  const who = c.get("who");
  const b = await c.req.json<{ ownerId?: unknown }>().catch(() => null);
  if (!b || typeof b.ownerId !== "string" || !b.ownerId)
    return c.json({ error: "bad request" }, 400);
  const p = await personOf(c);
  if (p instanceof Response) return p;
  const app = await findOwnedApp(db, c.req.param("appId"));
  if (!app) return c.json({ error: "unknown app" }, 404);

  const next = await findNextOwner(db, b.ownerId);
  if (next?.kind !== "user" || next.status !== "active" || next.id === p.id)
    return c.json({ error: "new owner must be another active person" }, 400);
  if (app.ownerId === next.id) return c.json({ id: app.id, ownerId: next.id, changed: false });
  if (app.ownerId !== p.id) return c.json({ error: "this person does not own the app" }, 409);

  const res = await reassignApp(db, next.id, app.id, p.id);
  if (!res.meta.changes) return c.json({ error: "owner changed, reload and retry" }, 409);
  await audit(db, {
    who: who.name,
    actor: who,
    action: "app.reassign",
    note: `${app.name}: ${p.name} -> ${next.name}`,
    result: "ok",
    ip: c.req.header("CF-Connecting-IP"),
  });
  return c.json({ id: app.id, ownerId: next.id, changed: true });
});

// Finish: disables the person, ends their sessions and removes their policies. Refused while they still
// belong to a group, own an active app, or would leave fewer than two admins with a vault. Safe to re-run.
offboard.post("/offboard/:id/finish", async (c) => {
  const db = c.env.DB;
  const who = c.get("who");
  const ip = c.req.header("CF-Connecting-IP");
  const p = await personOf(c);
  if (p instanceof Response) return p;
  if (p.id === who.id) return c.json({ error: "you cannot offboard yourself" }, 400);

  const blockers = await blockersOf(db, p, now());
  if (blockers.groups.length || blockers.apps.length || blockers.twoAdmins) {
    await audit(db, {
      who: who.name,
      actor: who,
      action: "offboard.finish",
      note: `${p.name} refused`,
      result: "denied",
      ip,
    });
    return c.json(
      {
        error:
          "offboarding is not finished: remove the person from groups and reassign or disable their apps first",
        blockers,
      },
      409,
    );
  }

  // The disable is conditional on the person still being in no group, so a group add that landed after the
  // check above cannot slip through; the cleanup only runs once they are disabled.
  const results = await finishOffboard(db, p.id);
  if (p.status !== "disabled" && !results[0]?.meta.changes)
    return c.json({ error: "the person changed while finishing, reload and retry" }, 409);
  const flipped = p.status !== "disabled";
  const ended = results[1]?.meta.changes ?? 0;
  const removed = results[2]?.meta.changes ?? 0;

  // Each step that changed something is audited, then the run itself (every run is audited).
  if (flipped)
    await audit(db, {
      who: who.name,
      actor: who,
      action: "identity.disable",
      note: p.name,
      result: "ok",
      ip,
    });
  if (ended)
    await audit(db, {
      who: who.name,
      actor: who,
      action: "offboard.sessions",
      note: `${p.name}: ${ended} session(s) ended`,
      result: "ok",
      ip,
    });
  if (removed)
    await audit(db, {
      who: who.name,
      actor: who,
      action: "offboard.policies",
      note: `${p.name}: ${removed} policy link(s) removed`,
      result: "ok",
      ip,
    });
  await audit(db, {
    who: who.name,
    actor: who,
    action: "offboard.finish",
    note: p.name,
    result: "ok",
    ip,
  });
  return c.json({
    id: p.id,
    status: "disabled",
    changed: { disabled: flipped, sessionsEnded: ended, policiesRemoved: removed },
  });
});
