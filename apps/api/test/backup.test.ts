import { env, SELF } from "cloudflare:test";
import { generateDek, sealText } from "@cfs/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { appendRow } from "../src/audit.ts";
import { runDaily } from "../src/cron.ts";
import {
  BACKUP_TABLES,
  backupDaily,
  COLUMNS,
  digest,
  EXCLUDED_TABLES,
  keepNewest,
  listAutoBackups,
  readFile,
  readTables,
  SCHEMA_VERSION,
  type Tables,
} from "../src/routes/backup.ts";
import type { Env } from "../src/types.ts";
import { now, sha256Hex } from "../src/util.ts";
import { flushAlerts, resetAlertSenders, setAlertSenders, testFetch } from "./alert-helpers.ts";
import { admin, api, makeIdentity } from "./helpers.ts";

const DAY = 86400;
const db = env.DB;
const cfEnv = env as unknown as Env;
const PASS = "a long enough passphrase";
const MARKER = "PLAINTEXT-MARKER-DO-NOT-LEAK-91f2c0";
const WEBHOOK = "https://hooks.test/services/SECRET-WEBHOOK-TOKEN-5d1e";

type Json = {
  schema: number;
  createdAt: number;
  tables: Record<string, Record<string, unknown>[]>;
  sha256: string;
};

const uniq = () => Math.random().toString(36).slice(2, 10);

/** Empties every table the backup covers, plus the session and login tables, in dependency order. */
async function resetDb() {
  await db.batch([
    db.prepare("DROP TRIGGER IF EXISTS fail_policy_insert"),
    db.prepare("DELETE FROM session"),
    db.prepare("DELETE FROM cli_login"),
    db.prepare("DELETE FROM login_attempt"),
    db.prepare("DELETE FROM maintenance"),
    ...[...BACKUP_TABLES].reverse().map((t) => db.prepare(`DELETE FROM ${t}`)),
  ]);
}

beforeEach(resetDb);
afterEach(async () => {
  await flushAlerts();
  resetAlertSenders();
  vi.restoreAllMocks();
  await db.prepare("DROP TRIGGER IF EXISTS fail_policy_insert").run();
});

async function download(token: string, pass?: string) {
  const r = await SELF.fetch("http://t.test/api/v1/backup", {
    headers: {
      authorization: `Bearer ${token}`,
      ...(pass ? { "X-Backup-Passphrase": pass } : {}),
    },
  });
  return { status: r.status, bytes: new Uint8Array(await r.arrayBuffer()) };
}

async function gunzipText(bytes: Uint8Array): Promise<string> {
  return new Response(
    new Blob([bytes as BlobPart]).stream().pipeThrough(new DecompressionStream("gzip")),
  ).text();
}

async function gzipBytes(text: string): Promise<Uint8Array> {
  return new Uint8Array(
    await new Response(
      new Blob([text]).stream().pipeThrough(new CompressionStream("gzip")),
    ).arrayBuffer(),
  );
}

async function plainFile(bytes: Uint8Array): Promise<Json> {
  return JSON.parse(await gunzipText(bytes)) as Json;
}

function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

async function post(path: string, token: string | null, body: unknown, pass?: string) {
  const r = await SELF.fetch(`http://t.test/api/v1${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(pass ? { "X-Backup-Passphrase": pass } : {}),
    },
    body: JSON.stringify(body),
  });
  return { status: r.status, body: (await r.json().catch(() => null)) as any, headers: r.headers };
}

const restoreBody = (bytes: Uint8Array, confirmHost = "t.test") => ({
  file: toBase64(bytes),
  confirmHost,
});

/** A fresh session for an existing identity. Restores clear sessions, so tests need a new one afterwards. */
async function resession(identityId: string): Promise<string> {
  const token = `cfs_re_${uniq()}`;
  await db
    .prepare(
      "INSERT INTO session (token_hash, identity_id, kind, created_at, expires_at) VALUES (?, ?, 'cli', 1, 9999999999)",
    )
    .bind(await sha256Hex(token), identityId)
    .run();
  return token;
}

/** Writes a secret whose value is sealed with a real AES-GCM key, so the marker is only in the envelope. */
async function seedSealedSecret(adminId: string): Promise<void> {
  const id = `s${uniq()}`;
  const kr = `kr${id}`;
  const envelope = await sealText(await generateDek(), MARKER, `secret:${id}:v1`);
  await db.batch([
    db
      .prepare("INSERT INTO keyring (id, prefix, version, created_at) VALUES (?, ?, 1, 1)")
      .bind(kr, id),
    db
      .prepare(
        "INSERT INTO secret (id, path, keyring_id, current, created_at, meta) VALUES (?, ?, ?, 1, 1, ?)",
      )
      .bind(id, `${id}/prod`, kr, JSON.stringify({ description: "db password" })),
    db
      .prepare(
        "INSERT INTO secret_version (secret_id, version, keyring_version, names, wrapped_dek, ciphertext, created_by, created_at, fps) VALUES (?, 1, 1, '[\"DB_PASSWORD\"]', 'wrapped-dek', ?, ?, 1, '{\"DB_PASSWORD\":\"0011223344556677\"}')",
      )
      .bind(id, envelope, adminId),
  ]);
}

/** Fills most tables with realistic rows. Returns the admin and a member. */
async function seedWorld() {
  const adm = await admin();
  const member = await makeIdentity({ name: `m-${uniq()}@test.dev` });
  await db
    .prepare("UPDATE identity SET last_unlocked_at = ? WHERE id = ?")
    .bind(1700000000, member.id)
    .run();
  // Old rows, pruned by the daily job: leaves an audit_base, a checkpoint and a usage row behind.
  const t = now();
  await appendRow(
    db,
    { who: "old", action: "secret.read", path: "a/b", result: "ok" },
    t - 400 * DAY,
  );
  await appendRow(
    db,
    { who: "old", action: "secret.read", path: "a/c", result: "ok" },
    t - 399 * DAY,
  );
  await runDaily(cfEnv, t);

  // Audit rows through the API, so the chain has real entries after the base.
  await api("POST", "/policies", adm.token, {
    name: `pol-${uniq()}`,
    rules: [{ path: "ops/*", caps: ["read"] }],
  });
  const polName = `ops-${uniq()}`;
  const pol = await api<{ id: string }>("POST", "/policies", adm.token, {
    name: polName,
    rules: [{ path: "ops/*", caps: ["read", "list"] }],
  });
  const polId = pol.body.id;
  await db.batch([
    db
      .prepare(
        "INSERT INTO identity_policy (identity_id, policy_id, expires_at) VALUES (?, ?, NULL)",
      )
      .bind(member.id, polId),
  ]);

  const prefix = `grp${uniq()}`;
  const kr = `kr-${prefix}`;
  await db.batch([
    db
      .prepare(
        "INSERT INTO keyring (id, prefix, version, created_at, status) VALUES (?, ?, 1, 1, 'active')",
      )
      .bind(kr, prefix),
    db
      .prepare(
        "INSERT INTO keyring_member (keyring_id, identity_id, version, wrapped_key) VALUES (?, ?, 1, 'wk-admin')",
      )
      .bind(kr, adm.id),
    db
      .prepare(
        "INSERT INTO keyring_member_staged (keyring_id, identity_id, version, wrapped_key) VALUES (?, ?, 2, 'wk-staged')",
      )
      .bind(kr, member.id),
  ]);

  const app = await makeIdentity({ kind: "app", name: `app-${uniq()}` });
  await db.batch([
    db.prepare("UPDATE identity SET owner_id = ? WHERE id = ?").bind(adm.id, app.id),
    db
      .prepare(
        "INSERT INTO app_role (identity_id, role_id, secret_hash, token_ttl, max_uses, uses, cidr, first_login_at, last_login_at, last_ip) VALUES (?, ?, 'hash-only', 3600, NULL, 2, '10.0.0.0/8', 5, 6, '10.1.2.3')",
      )
      .bind(app.id, `role-${uniq()}`),
  ]);

  await seedSealedSecret(adm.id);

  // ADR 16 and 18 tables: an access request, alert settings (the webhook is a credential) and alert dedupe state.
  await db.batch([
    db
      .prepare(
        "INSERT INTO access_request (id, requester_id, path_glob, group_prefix, reason, duration, rekey_after, status, approver_id, created_at, decided_at, expires_at) VALUES (?, ?, 'ops/*', 'ops', 'deploy', 3600, 0, 'approved', ?, 1, 2, 3602)",
      )
      .bind(`req-${uniq()}`, member.id, adm.id),
    db.prepare("INSERT INTO setting (key, value) VALUES ('alerts.webhook_url', ?)").bind(WEBHOOK),
    db.prepare("INSERT INTO setting (key, value) VALUES ('alerts.rules', '{\"burst\":5}')"),
    db.prepare("INSERT INTO alert_state (rule, subject, last_sent_at) VALUES ('burst', 'ops', 1)"),
  ]);
  return { adm, member, app };
}

async function snapshot(): Promise<Tables> {
  return readTables(db);
}

describe("ADR 23: export format", () => {
  it("is gzip JSON with the schema, every table and a SHA-256 that verifies", async () => {
    const { adm } = await seedWorld();
    const r = await download(adm.token);
    expect(r.status).toBe(200);
    const f = await plainFile(r.bytes);

    const latest = Math.max(
      ...(cfEnv as unknown as { TEST_MIGRATIONS: { name: string }[] }).TEST_MIGRATIONS.map((m) =>
        Number(m.name.slice(0, 4)),
      ),
    );
    expect(f.schema).toBe(latest);
    expect(f.schema).toBe(SCHEMA_VERSION);
    expect(Object.keys(f.tables).sort()).toEqual([...BACKUP_TABLES].sort());
    expect(f.sha256).toBe(await digest(f.schema, f.createdAt, f.tables as unknown as Tables));
  });

  it("covers every table on the instance, except the excluded ones", async () => {
    const found = await db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' AND name NOT LIKE 'd1_%'",
      )
      .all<{ name: string }>();
    const names = found.results.map((r) => r.name).sort();
    expect(names).toEqual([...BACKUP_TABLES, ...EXCLUDED_TABLES].sort());
  });

  it("lists every column of every table, so a new column cannot be dropped silently", async () => {
    for (const t of BACKUP_TABLES) {
      const cols = await db
        .prepare(`SELECT name FROM pragma_table_info('${t}')`)
        .all<{ name: string }>();
      expect(cols.results.map((c) => c.name).sort(), t).toEqual([...COLUMNS[t]].sort());
    }
  });

  it("leaves out sessions, CLI login codes and attempt counters", async () => {
    const { adm } = await seedWorld();
    await db
      .prepare(
        "INSERT INTO cli_login (device_hash, user_code, identity_id, status, expires_at) VALUES ('dh', 'UC-1', ?, 'pending', 9999999999)",
      )
      .bind(adm.id)
      .run();
    await db
      .prepare("INSERT INTO login_attempt (key, window, count) VALUES ('approle:x', 1, 9)")
      .run();
    const f = await plainFile((await download(adm.token)).bytes);
    for (const t of EXCLUDED_TABLES) expect(f.tables).not.toHaveProperty(t);
  });

  it("contains no plaintext secret value and no session token", async () => {
    const { adm, member } = await seedWorld();
    const text = await gunzipText((await download(adm.token)).bytes);
    expect(text).not.toContain(MARKER);
    expect(text).not.toContain(adm.token);
    expect(text).not.toContain(member.token);
    expect(text).not.toContain(await sha256Hex(adm.token));
    expect(text).not.toContain(await sha256Hex(member.token));
  });

  it("seals with a passphrase: no gzip header, and only the passphrase opens it", async () => {
    const { adm } = await seedWorld();
    const r = await download(adm.token, PASS);
    expect(r.status).toBe(200);
    expect(new TextDecoder().decode(r.bytes.slice(0, 8))).toBe("CFSSEAL1");
    const webhook = vi.fn(async () => {});
    setAlertSenders({ webhook });
    expect(await testFetch("http://t.test/api/v1/backup").then((x) => x.status)).toBe(401);
    await flushAlerts();
    expect(webhook).toHaveBeenCalledTimes(1);
    expect((await post("/restore/check", adm.token, restoreBody(r.bytes))).status).toBe(400);
    expect(
      (await post("/restore/check", adm.token, restoreBody(r.bytes), "not the passphrase")).status,
    ).toBe(400);
    const ok = await post("/restore/check", adm.token, restoreBody(r.bytes), PASS);
    expect(ok.status).toBe(200);
    expect(ok.body.ok).toBe(true);
  });

  it("refuses the passphrase in the URL and a short passphrase, and never echoes it", async () => {
    const { adm } = await seedWorld();
    const url = await SELF.fetch(`http://t.test/api/v1/backup?passphrase=${PASS}`, {
      headers: { authorization: `Bearer ${adm.token}` },
    });
    expect(url.status).toBe(400);
    expect(await url.text()).not.toContain(PASS);
    const short = await download(adm.token, "short");
    expect(short.status).toBe(400);
  });
});

describe("ADR 23: alert webhook is masked out", () => {
  it("leaves the webhook URL out of the file, and keeps the other settings", async () => {
    const { adm } = await seedWorld();
    const text = await gunzipText((await download(adm.token)).bytes);
    expect(text).not.toContain(WEBHOOK);
    expect(text).not.toContain("SECRET-WEBHOOK-TOKEN");
    const f = JSON.parse(text) as Json;
    expect(f.tables.setting).toEqual([{ key: "alerts.rules", value: '{"burst":5}' }]);
  });

  it("after a restore the webhook is unset, so the admin sets it again", async () => {
    const { adm } = await seedWorld();
    const file = (await download(adm.token)).bytes;
    // The live instance still has the webhook before the restore.
    expect(
      await db.prepare("SELECT 1 FROM setting WHERE key = 'alerts.webhook_url'").first(),
    ).not.toBeNull();
    expect((await post("/restore", adm.token, restoreBody(file))).status).toBe(200);
    const rows = await db.prepare("SELECT key FROM setting ORDER BY key").all<{ key: string }>();
    expect(rows.results.map((r) => r.key)).toEqual(["alerts.rules"]);
  });
});

describe("ADR 23: restore check", () => {
  it("verifies the file, reports counts and the time gap, and changes nothing", async () => {
    const { adm } = await seedWorld();
    const before = await snapshot();
    const file = (await download(adm.token)).bytes;
    const afterExport = await snapshot();
    expect(afterExport.audit.length).toBe(before.audit.length + 1); // the export row only

    const r = await post("/restore/check", adm.token, restoreBody(file));
    expect(r.status).toBe(200);
    expect(r.body.ok).toBe(true);
    expect(r.body.host).toBe("t.test");
    expect(r.body.schema).toBe(SCHEMA_VERSION);
    expect(r.body.gapSeconds).toBeGreaterThanOrEqual(0);
    expect(r.body.audit.ok).toBe(true);
    expect(r.body.counts.file.policy).toBe(before.policy.length);
    expect(r.body.counts.current.policy).toBe(before.policy.length);
    expect(await snapshot()).toEqual(afterExport);
  });

  it("refuses a file that is not a backup", async () => {
    const { adm } = await seedWorld();
    const junk = await post("/restore/check", adm.token, restoreBody(new Uint8Array([1, 2, 3, 4])));
    expect(junk.status).toBe(400);
    expect(junk.body.error).toBe("not a cfs backup file");
  });

  it("refuses a changed body: the hash no longer matches", async () => {
    const { adm } = await seedWorld();
    const f = await plainFile((await download(adm.token)).bytes);
    f.tables.policy![0]!.name = "tampered";
    const r = await post(
      "/restore/check",
      adm.token,
      restoreBody(await gzipBytes(JSON.stringify(f))),
    );
    expect(r.status).toBe(422);
    expect(r.body.error).toMatch(/hash mismatch/);
  });

  it("refuses schema 17 on both restore check and restore, even with a valid hash", async () => {
    const { adm } = await seedWorld();
    const f = await plainFile((await download(adm.token)).bytes);
    expect(f.schema).toBe(SCHEMA_VERSION);
    f.schema = 17;
    f.sha256 = await digest(f.schema, f.createdAt, f.tables as unknown as Tables);
    const file = await gzipBytes(JSON.stringify(f));
    const before = await snapshot();
    for (const path of ["/restore/check", "/restore"]) {
      const r = await post(path, adm.token, restoreBody(file));
      expect(r.status).toBe(409);
      expect(r.body.error).toContain(
        `file is schema 17; this instance runs schema ${SCHEMA_VERSION}`,
      );
    }
    expect(await snapshot()).toEqual(before);
  });

  it("refuses an audit chain that is broken inside the file, even with a recomputed hash", async () => {
    const { adm } = await seedWorld();
    const f = await plainFile((await download(adm.token)).bytes);
    const row = f.tables.audit!.find((r) => String(r.entry).includes('"result":"ok"'))!;
    row.entry = String(row.entry).replace('"result":"ok"', '"result":"denied"');
    f.sha256 = await digest(f.schema, f.createdAt, f.tables as unknown as Tables);
    const r = await post(
      "/restore/check",
      adm.token,
      restoreBody(await gzipBytes(JSON.stringify(f))),
    );
    expect(r.status).toBe(422);
    expect(r.body.error).toMatch(/audit chain broken/);
  });

  it("refuses an unknown table or column in the file", async () => {
    const { adm } = await seedWorld();
    const f = await plainFile((await download(adm.token)).bytes);
    f.tables.policy![0]!.evil = "x";
    f.sha256 = await digest(f.schema, f.createdAt, f.tables as unknown as Tables);
    const r = await post(
      "/restore/check",
      adm.token,
      restoreBody(await gzipBytes(JSON.stringify(f))),
    );
    expect(r.status).toBe(400);
    expect(r.body.error).toBe("unknown column policy.evil");
  });
});

describe("ADR 23: restore", () => {
  it("round trip: backup, wipe, restore gives the same rows, and only the restore row is new", async () => {
    const { adm, member } = await seedWorld();
    const before = await snapshot();
    expect(before.identity.find((row) => row.id === member.id)?.last_unlocked_at).toBe(1700000000);
    const file = (await download(adm.token)).bytes;

    // Wipe every backed-up table except the admin's own identity and session, which the restore needs to authenticate.
    await db.batch([
      db.prepare("DELETE FROM cli_login"),
      db.prepare("DELETE FROM login_attempt"),
      ...[...BACKUP_TABLES]
        .reverse()
        .filter((t) => t !== "identity")
        .map((t) => db.prepare(`DELETE FROM ${t}`)),
      db.prepare("DELETE FROM identity WHERE id != ?").bind(adm.id),
    ]);
    expect((await snapshot()).policy).toEqual([]);
    expect((await snapshot()).setting).toEqual([]);

    const r = await post("/restore", adm.token, restoreBody(file));
    expect(r.status).toBe(200);
    expect(r.body.ok).toBe(true);

    const after = await snapshot();
    for (const t of BACKUP_TABLES) {
      // The restore row is written after the replace, so it adds one write to the usage meter for today.
      if (t === "audit" || t === "usage_day") continue;
      // The webhook is masked out of the file, so it is not restored.
      const expected =
        t === "setting" ? before.setting.filter((r) => r.key !== "alerts.webhook_url") : before[t];
      expect(after[t], t).toEqual(expected);
    }
    expect(after.usage_day[0]?.writes).toBe((before.usage_day[0]?.writes as number) + 1);
    // The file holds the audit up to the export. The restore row is the only addition.
    expect(after.audit.slice(0, before.audit.length)).toEqual(before.audit);
    expect(after.audit.length).toBe(before.audit.length + 1);
  });

  it("refuses a wrong host name and changes nothing", async () => {
    const { adm } = await seedWorld();
    const file = (await download(adm.token)).bytes;
    const before = await snapshot();
    const r = await post("/restore", adm.token, restoreBody(file, "evil.test"));
    expect(r.status).toBe(400);
    expect(r.body.error).toContain("t.test");
    expect(await snapshot()).toEqual(before);
    expect(await db.prepare("SELECT 1 FROM maintenance").first()).toBeNull();
  });

  it("refuses a restore with no host name", async () => {
    const { adm } = await seedWorld();
    const file = (await download(adm.token)).bytes;
    const r = await post("/restore", adm.token, { file: toBase64(file) });
    expect(r.status).toBe(400);
  });

  it("refuses a tampered sealed file, and a changed byte in the gzip itself", async () => {
    const { adm } = await seedWorld();
    const sealed = (await download(adm.token, PASS)).bytes.slice();
    sealed[sealed.length - 3] = (sealed[sealed.length - 3] as number) ^ 0xff;
    expect((await post("/restore", adm.token, restoreBody(sealed), PASS)).status).toBe(400);

    const plain = (await download(adm.token)).bytes.slice();
    plain[plain.length - 8] = (plain[plain.length - 8] as number) ^ 0xff;
    expect((await post("/restore", adm.token, restoreBody(plain))).status).toBe(400);
  });

  it("invalidates every session, so the old token stops working", async () => {
    const { adm } = await seedWorld();
    const file = (await download(adm.token)).bytes;
    expect((await api("GET", "/whoami", adm.token)).status).toBe(200);
    expect((await post("/restore", adm.token, restoreBody(file))).status).toBe(200);
    expect((await api("GET", "/whoami", adm.token)).status).toBe(401);
    expect(await db.prepare("SELECT COUNT(*) AS n FROM session").first<{ n: number }>()).toEqual({
      n: 0,
    });
  });

  it("writes a restore audit row, and the restored chain verifies", async () => {
    const { adm } = await seedWorld();
    const file = (await download(adm.token)).bytes;
    expect((await post("/restore", adm.token, restoreBody(file))).status).toBe(200);
    const fresh = await resession(adm.id);
    const v = await api("GET", "/audit/verify", fresh);
    expect(v.status).toBe(200);
    expect(v.body.ok).toBe(true);
    const last = await db
      .prepare("SELECT entry FROM audit ORDER BY seq DESC LIMIT 1")
      .first<{ entry: string }>();
    const entry = JSON.parse(last!.entry);
    expect(entry.action).toBe("restore");
    expect(entry.result).toBe("ok");
    expect(entry.who).toBe(adm.name);
  });

  it("blocks writes with 503 while maintenance is on, and reads and checks still work", async () => {
    const { adm } = await seedWorld();
    const file = (await download(adm.token)).bytes;
    await db
      .prepare("INSERT INTO maintenance (id, since, by) VALUES (1, ?, ?)")
      .bind(now(), adm.id)
      .run();

    const w = await post("/policies", adm.token, { name: `blocked-${uniq()}`, rules: [] });
    expect(w.status).toBe(503);
    expect(w.headers.get("Retry-After")).toBe("60");
    expect(await db.prepare("SELECT 1 FROM policy WHERE name LIKE 'blocked-%'").first()).toBeNull();
    // Login is a write too.
    expect((await post("/auth/approle/login", null, { roleId: "r", secretId: "s" })).status).toBe(
      503,
    );
    expect((await api("GET", "/policies", adm.token)).status).toBe(200);
    expect((await post("/restore/check", adm.token, restoreBody(file))).status).toBe(200);

    await db.prepare("DELETE FROM maintenance").run();
    expect((await post("/policies", adm.token, { name: `open-${uniq()}`, rules: [] })).status).toBe(
      201,
    );
  });

  it("a restore that fails part way stays in maintenance, and a second run finishes it", async () => {
    const { adm } = await seedWorld();
    const file = (await download(adm.token)).bytes;
    await db
      .prepare(
        "CREATE TRIGGER fail_policy_insert BEFORE INSERT ON policy BEGIN SELECT RAISE(ABORT, 'boom'); END",
      )
      .run();
    const failed = await post("/restore", adm.token, restoreBody(file));
    expect(failed.status).toBe(500);
    expect(failed.body.error).toContain("stays in maintenance");
    expect(await db.prepare("SELECT 1 FROM maintenance WHERE id = 1").first()).not.toBeNull();
    // The guard runs before authentication, so writes get 503 whoever sends them.
    expect((await post("/policies", null, { name: "x", rules: [] })).status).toBe(503);
    expect((await post("/policies", adm.token, { name: "x", rules: [] })).status).toBe(503);

    // The failed batch rolled back and the restore cleared the identities, so a new admin does the second run.
    await db.prepare("DROP TRIGGER fail_policy_insert").run();
    const again = await admin();
    expect((await post("/restore", again.token, restoreBody(file))).status).toBe(200);
    expect(await db.prepare("SELECT 1 FROM maintenance").first()).toBeNull();
    const fresh = await resession(adm.id);
    expect((await post("/policies", fresh, { name: `after-${uniq()}`, rules: [] })).status).toBe(
      201,
    );
  });
});

describe("ADR 23: admin only", () => {
  it("refuses export, check and restore to a member", async () => {
    const { adm, member } = await seedWorld();
    const file = (await download(adm.token)).bytes;
    expect((await download(member.token)).status).toBe(403);
    expect((await post("/restore/check", member.token, restoreBody(file))).status).toBe(403);
    expect((await post("/restore", member.token, restoreBody(file))).status).toBe(403);
    expect(await db.prepare("SELECT 1 FROM maintenance").first()).toBeNull();
  });

  it("refuses an anonymous request", async () => {
    const r = await SELF.fetch("http://t.test/api/v1/backup");
    expect(r.status).toBe(401);
  });
});

describe("ADR 23: secrets stay out of logs and audit", () => {
  it("never writes the passphrase to the console or the audit log", async () => {
    const { adm } = await seedWorld();
    const logs = [vi.spyOn(console, "log"), vi.spyOn(console, "error"), vi.spyOn(console, "warn")];
    const secretPass = "unique-passphrase-xyz-123";
    const sealed = (await download(adm.token, secretPass)).bytes;
    await post("/restore/check", adm.token, restoreBody(sealed), secretPass);
    await post("/restore/check", adm.token, restoreBody(sealed), "wrong-but-long-enough");

    for (const spy of logs)
      for (const call of spy.mock.calls) expect(String(call[0])).not.toContain(secretPass);
    const rows = await db.prepare("SELECT entry FROM audit").all<{ entry: string }>();
    for (const r of rows.results) expect(r.entry).not.toContain(secretPass);
  });
});

describe("ADR 23: optional R2 copy", () => {
  /** A minimal in-memory R2 bucket: put, paginated list, delete. */
  function fakeR2() {
    const objects = new Map<string, Uint8Array>();
    const bucket = {
      put: async (key: string, value: Uint8Array) => {
        objects.set(key, value);
        return {};
      },
      list: async ({ prefix = "" }: { prefix?: string; cursor?: string }) => ({
        objects: [...objects.keys()]
          .filter((k) => k.startsWith(prefix))
          .sort()
          .map((key) => ({ key })),
        truncated: false,
        cursor: undefined,
      }),
      delete: async (keys: string | string[]) => {
        for (const k of Array.isArray(keys) ? keys : [keys]) objects.delete(k);
      },
    };
    return { objects, bucket: bucket as unknown as R2Bucket };
  }

  it("without a BACKUP binding the daily step does nothing", async () => {
    await seedWorld();
    const spy = vi.spyOn(db, "prepare");
    await backupDaily({ ...cfEnv, BACKUP: undefined }, now());
    expect(spy).not.toHaveBeenCalled();
  });

  it("with a BACKUP binding the cron writes a verifiable file under today's key", async () => {
    await seedWorld();
    const r2 = fakeR2();
    const t = now();
    await runDaily({ ...cfEnv, BACKUP: r2.bucket }, t);
    const keys = [...r2.objects.keys()];
    expect(keys).toHaveLength(1);
    expect(keys[0]).toMatch(/^backups\/cfs-backup-\d{4}-\d{2}-\d{2}\.cfsbackup$/);
    const f = await readFile(r2.objects.get(keys[0]!)!);
    expect(f.schema).toBe(SCHEMA_VERSION);
  });

  it("keeps the newest 30 copies and deletes the rest", async () => {
    await seedWorld();
    const r2 = fakeR2();
    const start = Math.floor(Date.UTC(2026, 0, 1) / 1000);
    for (let i = 0; i < 35; i++)
      await backupDaily({ ...cfEnv, BACKUP: r2.bucket }, start + i * DAY);
    expect(r2.objects.size).toBe(30);
    const kept = [...r2.objects.keys()].sort();
    expect(kept[0]).toBe("backups/cfs-backup-2026-01-06.cfsbackup");
    expect(kept.at(-1)).toBe("backups/cfs-backup-2026-02-04.cfsbackup");
  });

  it("keepNewest removes nothing when there are fewer than the limit", async () => {
    const r2 = fakeR2();
    await r2.bucket.put("backups/cfs-backup-2026-01-01.cfsbackup", new Uint8Array([1]));
    expect(await keepNewest(r2.bucket, 30)).toBe(0);
    expect(r2.objects.size).toBe(1);
  });
});

describe("ADR 24: backup history", () => {
  it("lists manual downloads from the audit log, newest first, and says R2 is off", async () => {
    const adm = await admin();
    await api("GET", "/backup", adm.token);
    const r = await api<{
      r2: boolean;
      copies: { at: number; type: string; size: number | null }[];
    }>("GET", "/backup/history", adm.token);
    expect(r.status).toBe(200);
    expect(r.body.r2).toBe(false);
    expect(r.body.copies[0]).toMatchObject({ type: "manual", size: null });
    const times = r.body.copies.map((x) => x.at);
    expect(times).toEqual([...times].sort((a, b) => b - a));
  });

  it("refuses a member", async () => {
    const m = await makeIdentity({ role: "member" });
    expect((await api("GET", "/backup/history", m.token)).status).toBe(403);
  });

  it("lists R2 copies with their size", async () => {
    const bucket = {
      list: async () => ({
        objects: [
          {
            key: "backups/cfs-backup-2026-01-01.cfsbackup",
            size: 10,
            uploaded: new Date(1_000_000),
          },
          {
            key: "backups/cfs-backup-2026-01-02.cfsbackup",
            size: 20,
            uploaded: new Date(2_000_000),
          },
        ],
        truncated: false,
      }),
    } as unknown as R2Bucket;
    expect(await listAutoBackups(bucket)).toEqual([
      { at: 2000, type: "auto", size: 20 },
      { at: 1000, type: "auto", size: 10 },
    ]);
  });
});
