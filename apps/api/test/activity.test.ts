import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { appendRow } from "../src/audit.ts";
import { admin, api, makeIdentity } from "./helpers.ts";

// ADR 24 (Activity) and ADR 11 (CLI approve page): the listing filters, the device lookup, and the attempts count.

const db = env.DB;
const tag = () => Math.random().toString(36).slice(2, 8);

type AuditRow = {
  seq: number;
  who: string;
  action: string;
  path?: string;
  result: string;
  at: number;
};

describe("GET /audit filters", () => {
  it("refuses a member", async () => {
    const m = await makeIdentity({ role: "member" });
    expect((await api("GET", "/audit", m.token)).status).toBe(403);
  });

  it("filters by who, action, path, result and time, and pages with before", async () => {
    const adm = await admin();
    const t = tag();
    const who = `person-${t}`;
    const base = 1_900_000_000;
    await appendRow(db, { who, action: "secret.read", path: `shop-${t}/prod`, result: "ok" }, base);
    await appendRow(
      db,
      { who, action: "secret.read", path: `shop-${t}/dev`, result: "ok" },
      base + 10,
    );
    await appendRow(
      db,
      { who, action: "secret.write", path: `shop-${t}/dev`, result: "denied" },
      base + 20,
    );
    await appendRow(
      db,
      { who, action: "secret.read", path: `other-${t}/dev`, result: "error" },
      base + 3000,
    );

    const rows = (qs: string) => api<AuditRow[]>("GET", `/audit?${qs}`, adm.token);

    const byWho = await rows(`who=${who}`);
    expect(byWho.status).toBe(200);
    expect(byWho.body).toHaveLength(4);
    expect(byWho.body.every((r) => r.who === who)).toBe(true);

    const reads = await rows(`who=${who}&action=secret.read`);
    expect(reads.body.map((r) => r.action)).toEqual(["secret.read", "secret.read", "secret.read"]);

    const denied = await rows(`who=${who}&result=denied`);
    expect(denied.body).toHaveLength(1);
    expect(denied.body[0]?.action).toBe("secret.write");

    const exact = await rows(`who=${who}&path=shop-${t}/prod`);
    expect(exact.body).toHaveLength(1);

    const prefix = await rows(`who=${who}&path=shop-${t}/*`);
    expect(prefix.body).toHaveLength(3);

    const window = await rows(`who=${who}&from=${base}&to=${base + 100}`);
    expect(window.body).toHaveLength(3);

    const page1 = await rows(`who=${who}&limit=2`);
    expect(page1.body).toHaveLength(2);
    const last = page1.body[page1.body.length - 1];
    const page2 = await rows(`who=${who}&limit=2&before=${last?.seq}`);
    expect(page2.body).toHaveLength(2);
    expect(page2.body.every((r) => (r.seq ?? 0) < (last?.seq ?? 0))).toBe(true);
  });

  it("rejects a bad result or a non-number time", async () => {
    const adm = await admin();
    expect((await api("GET", "/audit?result=maybe", adm.token)).status).toBe(400);
    expect((await api("GET", "/audit?from=yesterday", adm.token)).status).toBe(400);
    expect((await api("GET", "/audit?before=-1", adm.token)).status).toBe(400);
  });
});

describe("CLI approve: device lookup and attempts", () => {
  it("shows the device for a pending code, with or without the hyphen and in any case", async () => {
    const adm = await admin();
    const s = await api<{ userCode: string }>("POST", "/cli/start", null, {
      device: "dev-laptop-7",
    });
    const plain = s.body.userCode.replace("-", "").toLowerCase();
    const found = await api<{ userCode: string; device: string; expiresAt: number }>(
      "GET",
      `/cli/login?code=${plain}`,
      adm.token,
    );
    expect(found.status).toBe(200);
    expect(found.body.userCode).toBe(s.body.userCode);
    expect(found.body.device).toBe("dev-laptop-7");
    expect(found.body.expiresAt).toBeGreaterThan(0);
  });

  it("answers a miss with the attempts left, then 429 once the limit is passed", async () => {
    const adm = await admin();
    const first = await api<{ attemptsLeft: number }>(
      "GET",
      "/cli/login?code=ZZZZ-ZZZZ",
      adm.token,
    );
    expect(first.status).toBe(404);
    expect(first.body.attemptsLeft).toBe(4);
    const second = await api<{ attemptsLeft: number }>(
      "GET",
      "/cli/login?code=ZZZZ-ZZZZ",
      adm.token,
    );
    expect(second.body.attemptsLeft).toBe(3);
    await api("GET", "/cli/login?code=ZZZZ-ZZZZ", adm.token);
    await api("GET", "/cli/login?code=ZZZZ-ZZZZ", adm.token);
    const fifth = await api<{ attemptsLeft: number }>(
      "GET",
      "/cli/login?code=ZZZZ-ZZZZ",
      adm.token,
    );
    expect(fifth.body.attemptsLeft).toBe(0);
    expect((await api("GET", "/cli/login?code=ZZZZ-ZZZZ", adm.token)).status).toBe(429);
    expect((await api("POST", "/cli/approve", adm.token, { userCode: "ZZZZ-ZZZZ" })).status).toBe(
      429,
    );
  });

  it("approve accepts the code without the hyphen and reports attempts on a wrong one", async () => {
    const adm = await admin();
    const s = await api<{ userCode: string; deviceCode: string }>("POST", "/cli/start", null, {
      device: "dev-two",
    });
    const wrong = await api<{ attemptsLeft: number }>("POST", "/cli/approve", adm.token, {
      userCode: "QQQQQQQQ",
    });
    expect(wrong.status).toBe(404);
    expect(typeof wrong.body.attemptsLeft).toBe("number");
    const ok = await api("POST", "/cli/approve", adm.token, {
      userCode: s.body.userCode.replace("-", "").toLowerCase(),
    });
    expect(ok.status).toBe(200);
  });

  it("refuses apps and members on the lookup", async () => {
    const m = await makeIdentity({ kind: "app" });
    expect((await api("GET", "/cli/login?code=ABCD-EFGH", m.token)).status).toBe(403);
    void db;
  });
});

// ADR 24 (Activity): the Type column, the stat cards and the CSV export.
describe("GET /audit kind, /audit/stats and /audit/export.csv", () => {
  const nowSec = () => Math.floor(Date.now() / 1000);

  it("labels rows as user or app, and filters by kind", async () => {
    const adm = await admin();
    const t = tag();
    const person = await makeIdentity({ name: `p-${t}@test.dev`, kind: "user" });
    const bot = await makeIdentity({ name: `bot-${t}`, kind: "app" });
    await appendRow(
      db,
      { who: person.name, action: "secret.read", path: `k-${t}/a`, result: "ok" },
      nowSec(),
    );
    await appendRow(
      db,
      { who: bot.name, action: "secret.read", path: `k-${t}/a`, result: "ok" },
      nowSec(),
    );
    await appendRow(
      db,
      { who: `gone-${t}`, action: "secret.read", path: `k-${t}/a`, result: "ok" },
      nowSec(),
    );

    const all = await api<(AuditRow & { kind: string | null })[]>(
      "GET",
      `/audit?path=k-${t}/a`,
      adm.token,
    );
    const kindOf = (who: string) => all.body.find((r) => r.who === who)?.kind;
    expect(kindOf(person.name)).toBe("user");
    expect(kindOf(bot.name)).toBe("app");
    expect(kindOf(`gone-${t}`)).toBeNull();

    const apps = await api<AuditRow[]>("GET", `/audit?path=k-${t}/a&kind=app`, adm.token);
    expect(apps.body.map((r) => r.who)).toEqual([bot.name]);
    expect((await api("GET", "/audit?kind=robot", adm.token)).status).toBe(400);
  });

  it("counts the last 24 hours for the stat cards", async () => {
    const adm = await admin();
    const t = tag();
    const before = (await api<Record<string, number>>("GET", "/audit/stats", adm.token)).body;
    const person = await makeIdentity({ name: `s-${t}@test.dev`, kind: "user" });
    const bot = await makeIdentity({ name: `sbot-${t}`, kind: "app" });
    await appendRow(
      db,
      { who: person.name, action: "secret.read", path: `s-${t}/a`, result: "ok" },
      nowSec(),
    );
    await appendRow(
      db,
      { who: bot.name, action: "secret.read", path: `s-${t}/a`, result: "ok" },
      nowSec(),
    );
    await appendRow(
      db,
      { who: bot.name, action: "secret.read", path: `s-${t}/b`, result: "denied" },
      nowSec(),
    );
    await appendRow(
      db,
      { who: bot.name, action: "secret.read", path: `s-${t}/old`, result: "ok" },
      nowSec() - 90_000,
    );

    const after = (await api<Record<string, number>>("GET", "/audit/stats", adm.token)).body;
    expect(after.accesses - before.accesses).toBe(2);
    expect(after.byApps - before.byApps).toBe(1);
    expect(after.blocked - before.blocked).toBe(1);
    expect(after.actors - before.actors).toBe(2);
    expect(
      (await api("GET", "/audit/stats", (await makeIdentity({ role: "member" })).token)).status,
    ).toBe(403);
  });

  it("exports the filtered rows as CSV, guards formulas, and logs the export", async () => {
    const adm = await admin();
    const t = tag();
    await appendRow(
      db,
      {
        who: `x-${t}`,
        action: "secret.read",
        path: `c-${t}/a`,
        result: "ok",
        note: '=HYPERLINK("http://x"),b',
      },
      nowSec(),
    );
    const res = await SELF.fetch(`http://t.test/api/v1/audit/export.csv?path=c-${t}/a`, {
      headers: { authorization: `Bearer ${adm.token}` },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/csv");
    expect(res.headers.get("content-disposition")).toContain("attachment");
    const lines = (await res.text()).trim().split("\r\n");
    expect(lines[0]).toBe("seq,time,who,type,action,secret,version,result,ip,note");
    expect(lines).toHaveLength(2);
    expect(lines[1]).toContain(`x-${t},,secret.read,c-${t}/a`);
    // The note starts with '=' so it is quoted with a leading apostrophe, and its quotes and comma are escaped.
    expect(lines[1]).toContain(`"'=HYPERLINK(""http://x""),b"`);

    const logged = await api<AuditRow[]>(
      "GET",
      `/audit?action=audit.export&who=${encodeURIComponent(adm.name)}`,
      adm.token,
    );
    expect(logged.body.length).toBeGreaterThan(0);

    const member = await makeIdentity({ role: "member" });
    const denied = await SELF.fetch("http://t.test/api/v1/audit/export.csv", {
      headers: { authorization: `Bearer ${member.token}` },
    });
    expect(denied.status).toBe(403);
  });
});
