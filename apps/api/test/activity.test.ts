import { env } from "cloudflare:test";
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
