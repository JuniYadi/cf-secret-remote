import { AsyncLocalStorage } from "node:async_hooks";
import { chainHash } from "@cfs/core";
import type { AuditRef, AuditRow } from "./audit.ts";
import { dayOf, FREE_WRITES_PER_DAY, WARN_AT_WRITES } from "./quota.ts";
import type { Env } from "./types.ts";
import { now } from "./util.ts";

// ADR 18: alerts and notifications. Evaluated after each audit append (see onAuditWritten in audit.ts).
// Messages carry names, paths, identities, IPs and times. Never values, tokens, notes or the webhook URL.

export const RULES = [
  "blocked",
  "agent_prod_read",
  "new_network",
  "read_burst",
  "quota_80",
  "chain_broken",
  "recovery_requested",
  "access_request",
] as const;
export type Rule = (typeof RULES)[number];
export const CHANNELS = ["webhook", "email"] as const;
export type Channel = (typeof CHANNELS)[number];

// Audit actions that the recovery (ADR 20) and access request (ADR 16) routes write. Those routes must use these names.
export const RECOVERY_ACTION = "recovery.requested";
export const ACCESS_ACTION = "request.create";

const DEDUPE_SECONDS = 15 * 60;
const BURST_WINDOW_SECONDS = 5 * 60;
const BURST_MAX = 20;
const KEY_WEBHOOK = "alerts.webhook_url";
const KEY_RULES = "alerts.rules";

export type Toggles = Partial<Record<Rule, Partial<Record<Channel, boolean>>>>;
export interface AlertConfig {
  webhookUrl: string | null;
  toggles: Toggles;
}

/** Posts one alert. Injectable so tests can capture messages without a network. */
export type WebhookSender = (url: string, text: string) => Promise<void>;
/** Sends one alert to the admin addresses. */
export type EmailSender = (to: string[], subject: string, text: string) => Promise<void>;

let overrides: { webhook?: WebhookSender; email?: EmailSender } = {};

/** Test seam: replaces the webhook or email sender. Production never calls this. */
export function setAlertSenders(s: { webhook?: WebhookSender; email?: EmailSender }): void {
  overrides = { ...s };
}
export function resetAlertSenders(): void {
  overrides = {};
}

// Requests run inside this store, so evaluation can be handed to ctx.waitUntil.
const requestScope = new AsyncLocalStorage<{ env: Env; ctx: ExecutionContext }>();
export function withAlertContext<T>(env: Env, ctx: ExecutionContext, fn: () => T): T {
  return requestScope.run({ env, ctx }, fn);
}

const pending = new Set<Promise<void>>();

/** Resolves once every scheduled evaluation has finished. Tests use it; production does not need it. */
export async function flushAlerts(): Promise<void> {
  while (pending.size > 0) await Promise.all([...pending]);
}

/** Starts evaluation for one appended row. Returns at once; never throws. */
export function scheduleAlerts(row: AuditRow, ref: AuditRef): void {
  const scope = requestScope.getStore();
  const job: Promise<void> = evaluate(row, ref, scope?.env)
    .catch(() => {
      console.error("alert evaluation failed");
    })
    .finally(() => {
      pending.delete(job);
    });
  pending.add(job);
  scope?.ctx.waitUntil(job);
}

// ---- settings -------------------------------------------------------------------------------

export const channelOn = (toggles: Toggles, rule: Rule, ch: Channel): boolean =>
  toggles[rule]?.[ch] !== false;

export async function loadConfig(db: D1Database): Promise<AlertConfig> {
  const rows = await db
    .prepare("SELECT key, value FROM setting WHERE key IN (?, ?)")
    .bind(KEY_WEBHOOK, KEY_RULES)
    .all<{ key: string; value: string }>();
  const map = new Map(rows.results.map((r) => [r.key, r.value]));
  let toggles: Toggles = {};
  try {
    toggles = parseToggles(JSON.parse(map.get(KEY_RULES) ?? "{}")) ?? {};
  } catch {
    toggles = {};
  }
  return { webhookUrl: map.get(KEY_WEBHOOK) || null, toggles };
}

/** Writes only the fields present in `patch`. Toggles merge into the stored ones. */
export async function saveConfig(
  db: D1Database,
  patch: { webhookUrl?: string | null; toggles?: Toggles },
): Promise<void> {
  if (patch.webhookUrl !== undefined) {
    if (patch.webhookUrl === null)
      await db.prepare("DELETE FROM setting WHERE key = ?").bind(KEY_WEBHOOK).run();
    else
      await db
        .prepare("INSERT OR REPLACE INTO setting (key, value) VALUES (?, ?)")
        .bind(KEY_WEBHOOK, patch.webhookUrl)
        .run();
  }
  if (patch.toggles) {
    const cur = await loadConfig(db);
    const merged: Toggles = { ...cur.toggles };
    for (const rule of RULES) {
      const t = patch.toggles[rule];
      if (t) merged[rule] = { ...merged[rule], ...t };
    }
    await db
      .prepare("INSERT OR REPLACE INTO setting (key, value) VALUES (?, ?)")
      .bind(KEY_RULES, JSON.stringify(merged))
      .run();
  }
}

/** Validates a rules body: known rule names, channel names, boolean values. Null when invalid. */
export function parseToggles(v: unknown): Toggles | null {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const out: Toggles = {};
  for (const [rule, chans] of Object.entries(v)) {
    if (!(RULES as readonly string[]).includes(rule)) return null;
    if (!chans || typeof chans !== "object" || Array.isArray(chans)) return null;
    const entry: Partial<Record<Channel, boolean>> = {};
    for (const [ch, on] of Object.entries(chans)) {
      if (!(CHANNELS as readonly string[]).includes(ch) || typeof on !== "boolean") return null;
      entry[ch as Channel] = on;
    }
    out[rule as Rule] = entry;
  }
  return out;
}

export function validWebhookUrl(s: string): boolean {
  if (s.length > 2048) return false;
  try {
    return new URL(s).protocol === "https:";
  } catch {
    return false;
  }
}

/** Shows the scheme, host and the last four characters of a long path. The full URL never leaves the server. */
export function maskWebhook(url: string): string {
  const u = new URL(url);
  const tail = u.pathname.length > 12 ? u.pathname.slice(-4) : "";
  return `${u.origin}/****${tail}`;
}

/** Verified admin addresses (the Access email of each active admin). */
export async function adminEmails(db: D1Database): Promise<string[]> {
  const r = await db
    .prepare(
      "SELECT name FROM identity WHERE kind = 'user' AND role = 'admin' AND status = 'active' ORDER BY name",
    )
    .all<{ name: string }>();
  return r.results.map((x) => x.name);
}

// ---- evaluation -----------------------------------------------------------------------------

interface Hit {
  rule: Rule;
  subject: string;
  title: string;
  detail: string;
}

function emailSenderFor(env: Env | undefined): EmailSender | undefined {
  if (overrides.email) return overrides.email;
  if (env?.SEND_EMAIL && env.ALERT_EMAIL_FROM) {
    const binding = env.SEND_EMAIL;
    const from = env.ALERT_EMAIL_FROM;
    return async (to, subject, text) => {
      for (const address of to) await binding.send({ to: address, from, subject, text });
    };
  }
  return undefined;
}

const postWebhook: WebhookSender = async (url, text) => {
  const r = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ text }),
  });
  if (!r.ok) throw new Error(`webhook responded ${r.status}`);
};

/** One send plus one retry. The error is dropped, since it may echo the URL. Only the label is logged. */
async function attempt(label: string, send: () => Promise<void>): Promise<void> {
  for (let i = 0; i < 2; i++) {
    try {
      await send();
      return;
    } catch {
      // retried once below
    }
  }
  console.error(`alert send failed after retry: ${label}`);
}

async function evaluate(row: AuditRow, ref: AuditRef, env: Env | undefined): Promise<void> {
  const db = ref.db;
  const cfg = await loadConfig(db);
  const webhook = cfg.webhookUrl;
  const email = emailSenderFor(env);
  if (!webhook && !email) return;

  // A rule runs only when at least one of its channels is on.
  const on = (rule: Rule) =>
    (webhook !== null && channelOn(cfg.toggles, rule, "webhook")) ||
    (email !== undefined && channelOn(cfg.toggles, rule, "email"));

  for (const hit of await detect(db, row, ref, on)) {
    if (!(await claim(db, hit.rule, hit.subject, now()))) continue;
    const text = `[cfs] ${hit.title}: ${hit.detail} (${new Date(row.at * 1000).toISOString()})`;
    if (webhook !== null && channelOn(cfg.toggles, hit.rule, "webhook")) {
      await attempt(`webhook ${hit.rule}`, () => (overrides.webhook ?? postWebhook)(webhook, text));
    }
    if (email && channelOn(cfg.toggles, hit.rule, "email")) {
      const to = await adminEmails(db);
      if (to.length > 0)
        await attempt(`email ${hit.rule}`, () => email(to, `cfs alert: ${hit.title}`, text));
    }
  }
}

/** Atomic claim of the (rule, subject) slot. True only for the caller that opened the window. */
async function claim(db: D1Database, rule: Rule, subject: string, t: number): Promise<boolean> {
  const r = await db
    .prepare(
      `INSERT INTO alert_state (rule, subject, last_sent_at) VALUES (?, ?, ?)
       ON CONFLICT (rule, subject) DO UPDATE SET last_sent_at = excluded.last_sent_at
       WHERE alert_state.last_sent_at <= ?`,
    )
    .bind(rule, subject, t, t - DEDUPE_SECONDS)
    .run();
  return r.meta.changes > 0;
}

/** IPv4 is grouped by /24. IPv6 is matched by the exact address. */
function networkOf(ip: string): { label: string; needle: string } {
  const p = ip.split(".");
  if (!ip.includes(":") && p.length === 4) {
    const net = p.slice(0, 3).join(".");
    return { label: `${net}.0/24`, needle: `"ip":"${net}.` };
  }
  return { label: ip, needle: `"ip":"${ip}"` };
}

async function isApp(db: D1Database, name: string): Promise<boolean> {
  const r = await db
    .prepare("SELECT 1 AS x FROM identity WHERE kind = 'app' AND name = ?")
    .bind(name)
    .first<{ x: number }>();
  return r !== null;
}

interface ChainRow {
  seq: number;
  prev: string;
  hash: string;
  entry: string;
}

/**
 * Checks the new row and the two rows before it: each stored hash must match its entry, and each link must hold.
 * Returns the seq of the first bad row, or null. Older rows are left to `cfs audit verify`.
 */
async function brokenAt(db: D1Database, ref: AuditRef): Promise<number | null> {
  const { results } = await db
    .prepare("SELECT seq, prev, hash, entry FROM audit ORDER BY seq DESC LIMIT 5")
    .all<ChainRow>();
  const i = results.findIndex((r) => r.hash === ref.hash);
  if (i < 0) return null; // another write landed after ours; that write is checked instead
  const window = results.slice(i, i + 3);
  for (let k = 0; k < window.length; k++) {
    const r = window[k] as (typeof window)[number];
    try {
      if ((await chainHash(r.prev, JSON.parse(r.entry))) !== r.hash) return r.seq;
    } catch {
      return r.seq;
    }
    const older = window[k + 1];
    if (older && r.prev !== older.hash) return r.seq;
  }
  return null;
}

async function detect(
  db: D1Database,
  row: AuditRow,
  ref: AuditRef,
  on: (r: Rule) => boolean,
): Promise<Hit[]> {
  const hits: Hit[] = [];
  const who = row.who;
  const where = row.path ? ` on ${row.path}` : "";
  const from = row.ip ? ` from ${row.ip}` : "";

  if (on("blocked") && row.result === "denied") {
    hits.push({
      rule: "blocked",
      subject: `${who}|${row.action}|${row.path ?? ""}`,
      title: "Request blocked",
      detail: `${who} ${row.action}${where}${from}`,
    });
  }

  if (
    on("agent_prod_read") &&
    row.action === "secret.read" &&
    row.result === "ok" &&
    row.path?.split("/").includes("prod") &&
    (await isApp(db, who))
  ) {
    hits.push({
      rule: "agent_prod_read",
      subject: `${who}|${row.path}`,
      title: "Agent read production secret",
      detail: `agent ${who} read ${row.path}${from}`,
    });
  }

  if (on("new_network") && row.action === "login.ok" && row.ip) {
    const net = networkOf(row.ip);
    const seen = await db
      .prepare(
        `SELECT COUNT(*) AS n FROM audit
         WHERE who = ? AND at <= ? AND hash != ? AND instr(entry, ?) > 0
           AND json_extract(entry, '$.action') = 'login.ok'`,
      )
      .bind(who, row.at, ref.hash, net.needle)
      .first<{ n: number }>();
    if ((seen?.n ?? 0) === 0) {
      hits.push({
        rule: "new_network",
        subject: `${who}|${net.label}`,
        title: "Sign-in from a new network",
        detail: `${who} signed in from ${net.label} for the first time`,
      });
    }
  }

  if (on("read_burst") && row.action.startsWith("secret.read")) {
    const reads = await db
      .prepare(
        `SELECT COUNT(*) AS n FROM audit
         WHERE who = ? AND at > ? AND at <= ?
           AND json_extract(entry, '$.action') LIKE 'secret.read%'`,
      )
      .bind(who, row.at - BURST_WINDOW_SECONDS, row.at)
      .first<{ n: number }>();
    const n = reads?.n ?? 0;
    if (n > BURST_MAX) {
      hits.push({
        rule: "read_burst",
        subject: who,
        title: "Read burst",
        detail: `${who} made ${n} secret reads in 5 minutes`,
      });
    }
  }

  if (on("quota_80")) {
    const day = dayOf(row.at);
    const usage = await db
      .prepare("SELECT writes FROM usage_day WHERE day = ?")
      .bind(day)
      .first<{ writes: number }>();
    const writes = usage?.writes ?? 0;
    if (writes >= WARN_AT_WRITES) {
      hits.push({
        rule: "quota_80",
        subject: day,
        title: "Daily write quota at 80%",
        detail: `about ${writes} of ${FREE_WRITES_PER_DAY} D1 writes used on ${day}`,
      });
    }
  }

  if (on("chain_broken")) {
    const seq = await brokenAt(db, ref);
    if (seq !== null) {
      hits.push({
        rule: "chain_broken",
        subject: "chain",
        title: "Audit chain check failed",
        detail: `audit chain does not verify at seq ${seq}; run cfs audit verify`,
      });
    }
  }

  if (on("recovery_requested") && row.action === RECOVERY_ACTION) {
    hits.push({
      rule: "recovery_requested",
      subject: who,
      title: "Recovery requested",
      detail: `${who} requested recovery${from}`,
    });
  }

  if (on("access_request") && row.action === ACCESS_ACTION) {
    hits.push({
      rule: "access_request",
      subject: `${who}|${row.path ?? ""}`,
      title: "Access requested",
      detail: `${who} requested access${where}${from}`,
    });
  }

  return hits;
}
