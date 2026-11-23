import { env } from "cloudflare:test";
import {
  diffFingerprints,
  fingerprints,
  generateKeyPair,
  newGroupKey,
  openSecret,
  sealSecret,
  type Values,
  wrapGroupKey,
} from "@cfs/core";
import { describe, expect, it } from "vitest";
import { runDaily } from "../src/cron.ts";
import type { Env } from "../src/types.ts";
import { admin, api, makeIdentity } from "./helpers.ts";

// ADR 22 tests. Every test uses its own group prefix so tests do not share paths.
let counter = 0;
const uniq = (s: string) => `${s}${++counter}${Math.random().toString(36).slice(2, 7)}`;
const DAY = 86400;

interface Person {
  id: string;
  name: string;
  token: string;
}

/** An admin, plus named members, all wrapped into a new group with the given prefix. */
async function team(prefix: string, memberNames: string[] = []) {
  const kp = await generateKeyPair();
  const adm = await admin(kp.publicKey);
  const gk = await newGroupKey();
  const members = [
    { identityId: adm.id, wrappedKey: await wrapGroupKey(gk, kp.publicKey, prefix, 1) },
  ];
  const people: Record<string, Person> = {};
  for (const n of memberNames) {
    const mk = await generateKeyPair();
    const p = await makeIdentity({ name: `${n}-${uniq("u")}@test.dev`, publicKey: mk.publicKey });
    people[n] = p;
    members.push({ identityId: p.id, wrappedKey: await wrapGroupKey(gk, mk.publicKey, prefix, 1) });
  }
  const created = await api("POST", "/keyrings", adm.token, { prefix, members });
  expect(created.status).toBe(201);
  return { adm, gk, people };
}

/** Grants the identity a single policy with the given rules (default deny otherwise). */
async function grant(adm: Person, who: Person, rules: { path: string; caps: string[] }[]) {
  const pol = await api<{ id: string }>("POST", "/policies", adm.token, {
    name: uniq("pol"),
    rules,
  });
  expect(pol.status).toBe(201);
  const a = await api("POST", `/policies/${pol.body.id}/assign`, adm.token, { identityId: who.id });
  expect(a.status).toBe(200);
}

async function nextVersion(path: string): Promise<number> {
  const r = await env.DB.prepare("SELECT current FROM secret WHERE path = ?")
    .bind(path)
    .first<{ current: number }>();
  return (r?.current ?? 0) + 1;
}

/** Seals and writes a version the way the CLI does: ciphertext plus fingerprints computed with the group key. */
async function save(
  tok: string,
  gk: Uint8Array,
  path: string,
  values: Values,
  o: { version?: number; fps?: unknown; meta?: unknown } = {},
) {
  const version = o.version ?? (await nextVersion(path));
  const sealed = await sealSecret(gk, path, version, values);
  const body: Record<string, unknown> = {
    path,
    names: Object.keys(values),
    keyringVersion: 1,
    version,
    ...sealed,
    fps: "fps" in o ? o.fps : await fingerprints(gk, path, values),
  };
  if (o.meta !== undefined) body.meta = o.meta;
  return api<{ version: number }>("PUT", "/secret", tok, body);
}

async function readValues(tok: string, gk: Uint8Array, path: string, version?: number) {
  const r = await api<{ version: number; wrappedDek: string; ciphertext: string }>(
    "GET",
    `/secret?path=${path}${version ? `&version=${version}` : ""}`,
    tok,
  );
  expect(r.status).toBe(200);
  return openSecret(gk, path, r.body.version, r.body.wrappedDek, r.body.ciphertext);
}

const versionRows = (path: string) =>
  env.DB.prepare(
    `SELECT v.version, v.ciphertext, v.wrapped_dek AS wrappedDek, v.fps, v.names
     FROM secret_version v JOIN secret s ON s.id = v.secret_id WHERE s.path = ? ORDER BY v.version`,
  )
    .bind(path)
    .all();

describe("fingerprints (ADR 22)", () => {
  it("stores fingerprints per version and returns them with the version list", async () => {
    const p = uniq("fpa");
    const path = `${p}/prod`;
    const t = await team(p);
    expect((await save(t.adm.token, t.gk, path, { A: "1", B: "2" })).status).toBe(201);
    const list = await api<{ version: number; fps: Record<string, string> }[]>(
      "GET",
      `/secret/versions?path=${path}`,
      t.adm.token,
    );
    expect(list.status).toBe(200);
    expect(list.body[0]?.fps).toEqual(await fingerprints(t.gk, path, { A: "1", B: "2" }));
  });

  it("refuses fingerprints that are malformed or do not match the names exactly", async () => {
    const p = uniq("fpbad");
    const path = `${p}/prod`;
    const t = await team(p);
    const values = { A: "1", B: "2" };
    const good = await fingerprints(t.gk, path, values);
    const bad: unknown[] = [
      { A: "zz" },
      { A: good.A },
      { A: good.A, B: good.B, C: good.A },
      { A: good.A, B: "not-hex-not-16!" },
      [good.A, good.B],
      "x",
    ];
    for (const fps of bad) {
      expect((await save(t.adm.token, t.gk, path, values, { fps })).status).toBe(400);
    }
    expect(await nextVersion(path)).toBe(1);
    expect((await save(t.adm.token, t.gk, path, values, { fps: good })).status).toBe(201);
  });

  it("the version list needs the list cap and returns no values", async () => {
    const MARK = "sk_live_VERSIONS_MARKER_4411";
    const p = uniq("vlist");
    const path = `${p}/prod`;
    const t = await team(p, ["ro", "lo"]);
    await grant(t.adm, t.people.ro as Person, [{ path: `${p}/*`, caps: ["read"] }]);
    await grant(t.adm, t.people.lo as Person, [{ path: `${p}/*`, caps: ["list"] }]);
    await save(t.adm.token, t.gk, path, { KEY: MARK });
    expect(
      (await api("GET", `/secret/versions?path=${path}`, (t.people.ro as Person).token)).status,
    ).toBe(403);
    const lo = await api("GET", `/secret/versions?path=${path}`, (t.people.lo as Person).token);
    expect(lo.status).toBe(200);
    expect(JSON.stringify(lo.body)).not.toContain(MARK);
  });
});

describe("restore writes a new version (ADR 22)", () => {
  it("restore creates a new version and never edits history", async () => {
    const p = uniq("rest");
    const path = `${p}/prod`;
    const t = await team(p);
    await save(t.adm.token, t.gk, path, { A: "old" });
    await save(t.adm.token, t.gk, path, { A: "new", B: "x" });
    const before = (await versionRows(path)).results;
    expect(before.length).toBe(2);

    // The client opens v1 and writes its values back as the next version.
    const old = await readValues(t.adm.token, t.gk, path, 1);
    const r = await save(t.adm.token, t.gk, path, old);
    expect(r.status).toBe(200);
    expect(r.body.version).toBe(3);

    const after = (await versionRows(path)).results;
    expect(after.length).toBe(3);
    expect(after.slice(0, 2)).toEqual(before);
    expect(await readValues(t.adm.token, t.gk, path)).toEqual({ A: "old" });
    expect(await readValues(t.adm.token, t.gk, path, 2)).toEqual({ A: "new", B: "x" });
    const list = await api<{ version: number; fps: unknown }[]>(
      "GET",
      `/secret/versions?path=${path}`,
      t.adm.token,
    );
    const v1 = list.body.find((v) => v.version === 1);
    const v3 = list.body.find((v) => v.version === 3);
    expect(v3?.fps).toEqual(v1?.fps);
  });

  it("a write cannot target an old or skipped version number", async () => {
    const p = uniq("stale");
    const path = `${p}/prod`;
    const t = await team(p);
    await save(t.adm.token, t.gk, path, { A: "1" });
    await save(t.adm.token, t.gk, path, { A: "2" });
    const before = (await versionRows(path)).results;
    expect((await save(t.adm.token, t.gk, path, { A: "evil" }, { version: 1 })).status).toBe(409);
    expect((await save(t.adm.token, t.gk, path, { A: "skip" }, { version: 5 })).status).toBe(409);
    expect((await versionRows(path)).results).toEqual(before);
  });
});

describe("diff never exposes values (ADR 22)", () => {
  it("names added, changed and removed, and no value appears in the versions or the diff", async () => {
    const MARK = "sk_live_DIFF_MARKER_9182";
    const p = uniq("diff");
    const path = `${p}/prod`;
    const t = await team(p);
    await save(t.adm.token, t.gk, path, { KEY: "one", GONE: "g", SAME: "s" });
    await save(t.adm.token, t.gk, path, { KEY: "two", NEW: MARK, SAME: "s" });
    const list = await api<{ version: number; fps: Record<string, string> }[]>(
      "GET",
      `/secret/versions?path=${path}`,
      t.adm.token,
    );
    const from = list.body.find((v) => v.version === 1)?.fps as Record<string, string>;
    const to = list.body.find((v) => v.version === 2)?.fps as Record<string, string>;
    const d = diffFingerprints(from, to);
    expect(d).toEqual({ added: ["NEW"], changed: ["KEY"], removed: ["GONE"] });
    expect(JSON.stringify(list.body)).not.toContain(MARK);
    expect(JSON.stringify(d)).not.toContain(MARK);
  });
});

describe("access history (ADR 22)", () => {
  it("counts only ciphertext fetches that succeeded", async () => {
    const p = uniq("hist");
    const path = `${p}/prod`;
    const t = await team(p, ["r", "x"]);
    await grant(t.adm, t.people.r as Person, [{ path: `${p}/*`, caps: ["read"] }]);
    await save(t.adm.token, t.gk, path, { A: "1" });
    const r = t.people.r as Person;
    expect((await api("GET", `/secret?path=${path}`, r.token)).status).toBe(200);
    expect((await api("GET", `/secret?path=${path}`, r.token)).status).toBe(200);
    expect((await api("GET", `/secret?path=${path}&merge=1`, r.token)).status).toBe(200);
    const merge = await env.DB.prepare(
      "SELECT identity_id, identity_kind FROM audit WHERE action = ? AND path = ?",
    )
      .bind("secret.merge_read", path)
      .first();
    expect(merge).toEqual({ identity_id: r.id, identity_kind: "user" });
    // x has no policy: the attempt is denied and is not an open.
    expect((await api("GET", `/secret?path=${path}`, (t.people.x as Person).token)).status).toBe(
      403,
    );
    // a write is not an open either.
    await save(t.adm.token, t.gk, path, { A: "2" });

    const h = await api<{
      opens: number;
      readers: number;
      lastReader: { who: string; version: number } | null;
      people: { name: string; opens: number; hasAccess: boolean }[];
    }>("GET", `/secret/history?path=${path}`, t.adm.token);
    expect(h.status).toBe(200);
    expect(h.body.opens).toBe(2);
    expect(h.body.readers).toBe(1);
    expect(h.body.lastReader?.who).toBe(r.name);
    expect(h.body.lastReader?.version).toBe(1);
    expect(h.body.people).toEqual([
      expect.objectContaining({ name: r.name, opens: 2, hasAccess: true }),
    ]);
  });

  it("the history needs the update cap", async () => {
    const p = uniq("histcap");
    const path = `${p}/prod`;
    const t = await team(p, ["ro", "lo", "up"]);
    await save(t.adm.token, t.gk, path, { A: "1" });
    await grant(t.adm, t.people.ro as Person, [{ path: `${p}/*`, caps: ["read"] }]);
    await grant(t.adm, t.people.lo as Person, [{ path: `${p}/*`, caps: ["list"] }]);
    await grant(t.adm, t.people.up as Person, [{ path: `${p}/*`, caps: ["update"] }]);
    for (const who of ["ro", "lo"]) {
      const res = await api("GET", `/secret/history?path=${path}`, (t.people[who] as Person).token);
      expect(res.status).toBe(403);
    }
    expect(
      (await api("GET", `/secret/history?path=${path}`, (t.people.up as Person).token)).status,
    ).toBe(200);
  });

  it("marks people who lost their policy or their group key", async () => {
    const p = uniq("lost");
    const path = `${p}/prod`;
    const t = await team(p, ["a", "b", "c"]);
    await save(t.adm.token, t.gk, path, { A: "1" });
    for (const n of ["a", "b", "c"]) {
      await grant(t.adm, t.people[n] as Person, [{ path: `${p}/*`, caps: ["read"] }]);
      expect((await api("GET", `/secret?path=${path}`, (t.people[n] as Person).token)).status).toBe(
        200,
      );
    }
    // a loses the policy, c loses the group key (membership). b keeps both.
    await env.DB.prepare("DELETE FROM identity_policy WHERE identity_id = ?")
      .bind((t.people.a as Person).id)
      .run();
    await env.DB.prepare("DELETE FROM keyring_member WHERE identity_id = ?")
      .bind((t.people.c as Person).id)
      .run();
    const h = await api<{
      lostAccess: number;
      people: { name: string; hasAccess: boolean }[];
    }>("GET", `/secret/history?path=${path}`, t.adm.token);
    expect(h.body.lostAccess).toBe(2);
    const access = Object.fromEntries(h.body.people.map((x) => [x.name, x.hasAccess]));
    expect(access[(t.people.a as Person).name]).toBe(false);
    expect(access[(t.people.c as Person).name]).toBe(false);
    expect(access[(t.people.b as Person).name]).toBe(true);
  });

  it("counts only the last 30 days", async () => {
    const p = uniq("window");
    const path = `${p}/prod`;
    const t = await team(p, ["r"]);
    const r = t.people.r as Person;
    await grant(t.adm, r, [{ path: `${p}/*`, caps: ["read"] }]);
    await save(t.adm.token, t.gk, path, { A: "1" });
    await api("GET", `/secret?path=${path}`, r.token);
    await api("GET", `/secret?path=${path}`, r.token);
    // Move the first open 31 days back.
    await env.DB.prepare(
      `UPDATE audit SET at = at - ? WHERE seq = (SELECT MIN(seq) FROM audit
         WHERE json_extract(entry, '$.who') = ? AND json_extract(entry, '$.path') = ?)`,
    )
      .bind(31 * DAY, r.name, path)
      .run();
    const h = await api<{ opens: number }>("GET", `/secret/history?path=${path}`, t.adm.token);
    expect(h.body.opens).toBe(1);
  });
});

describe("metadata (ADR 22)", () => {
  it("is changed with the update cap, is partial, and is listed in clear", async () => {
    const p = uniq("meta");
    const path = `${p}/prod`;
    const t = await team(p, ["ro", "up"]);
    await save(t.adm.token, t.gk, path, { A: "1" });
    await grant(t.adm, t.people.ro as Person, [{ path: `${p}/*`, caps: ["read"] }]);
    await grant(t.adm, t.people.up as Person, [{ path: `${p}/*`, caps: ["update"] }]);
    const body = {
      path,
      meta: { description: "Stripe live key", owner: t.adm.name, rotateBy: "2027-01-15" },
    };
    expect((await api("PUT", "/secret/meta", (t.people.ro as Person).token, body)).status).toBe(
      403,
    );
    expect((await api("PUT", "/secret/meta", (t.people.up as Person).token, body)).status).toBe(
      200,
    );

    const list = await api<{ path: string; meta: Record<string, string> }[]>(
      "GET",
      "/secrets",
      t.adm.token,
    );
    expect(list.body.find((s) => s.path === path)?.meta).toEqual({
      description: "Stripe live key",
      owner: t.adm.name,
      rotateBy: "2027-01-15",
    });

    // Partial: only rotateBy is cleared, the rest stays.
    const cleared = await api("PUT", "/secret/meta", t.adm.token, {
      path,
      meta: { rotateBy: null },
    });
    expect(cleared.body.meta).toEqual({ description: "Stripe live key", owner: t.adm.name });
  });

  it("refuses fields outside the three, bad values, and unknown owners", async () => {
    const p = uniq("metabad");
    const path = `${p}/prod`;
    const t = await team(p);
    await save(t.adm.token, t.gk, path, { A: "1" });
    const bad: unknown[] = [
      { values: { A: "sk_smuggled" } },
      { description: "ok", A: "sk_smuggled" },
      { owner: "nobody@test.dev" },
      { rotateBy: "2026-02-31" },
      { rotateBy: "soon" },
      { description: "x".repeat(201) },
      "not an object",
    ];
    for (const meta of bad) {
      expect((await api("PUT", "/secret/meta", t.adm.token, { path, meta })).status).toBe(400);
    }
    const list = await api<{ path: string; meta: unknown }[]>("GET", "/secrets", t.adm.token);
    expect(list.body.find((s) => s.path === path)?.meta).toEqual({});
    expect(
      (await api("PUT", "/secret/meta", t.adm.token, { path: `${p}/none`, meta: {} })).status,
    ).toBe(404);
  });

  it("holds no values: a write can carry meta, and the marker stays out of every table and response", async () => {
    const MARK = "sk_live_META_MARKER_5501";
    const p = uniq("metaval");
    const path = `${p}/prod`;
    const t = await team(p);
    expect(
      (
        await save(
          t.adm.token,
          t.gk,
          path,
          { KEY: MARK },
          { meta: { description: "payments key" } },
        )
      ).status,
    ).toBe(201);
    expect(
      (await save(t.adm.token, t.gk, path, { KEY: "rotated" }, { meta: { owner: t.adm.name } }))
        .status,
    ).toBe(200);
    expect(
      (await save(t.adm.token, t.gk, path, { KEY: "x" }, { meta: { values: { KEY: MARK } } }))
        .status,
    ).toBe(400);
    await api("PUT", "/secret/meta", t.adm.token, {
      path,
      meta: { description: "still typed by a person" },
    });

    const list = await api("GET", "/secrets", t.adm.token);
    expect(list.body.find((s: { path: string }) => s.path === path).meta).toEqual({
      description: "still typed by a person",
      owner: t.adm.name,
    });
    expect(JSON.stringify(list.body)).not.toContain(MARK);
    for (const q of [
      "SELECT * FROM secret",
      "SELECT * FROM secret_version",
      "SELECT * FROM audit",
    ]) {
      expect(JSON.stringify((await env.DB.prepare(q).all()).results)).not.toContain(MARK);
    }
  });
});

describe("soft delete and restore (ADR 22)", () => {
  it("a deleted secret is hidden, refuses new writes, and an admin restores it; members cannot", async () => {
    const p = uniq("del");
    const path = `${p}/prod`;
    const t = await team(p, ["m"]);
    await save(t.adm.token, t.gk, path, { A: "1" });
    expect((await api("DELETE", `/secret?path=${path}`, t.adm.token)).status).toBe(200);
    expect((await api("GET", `/secret?path=${path}`, t.adm.token)).status).toBe(404);
    expect((await save(t.adm.token, t.gk, path, { A: "2" })).status).toBe(409);

    expect(
      (await api("POST", `/secret/restore-delete?path=${path}`, (t.people.m as Person).token))
        .status,
    ).toBe(403);
    expect((await api("POST", `/secret/restore-delete?path=${path}`, t.adm.token)).status).toBe(
      200,
    );
    expect(await readValues(t.adm.token, t.gk, path)).toEqual({ A: "1" });
    expect((await api("POST", `/secret/restore-delete?path=${path}`, t.adm.token)).status).toBe(
      404,
    );
  });

  it("restores within 30 days and refuses after; purge removes only what is past the window", async () => {
    const p = uniq("purge");
    const old = `${p}/old`;
    const edge = `${p}/edge`;
    const recent = `${p}/recent`;
    const t = await team(p);
    for (const path of [old, edge, recent]) {
      await save(t.adm.token, t.gk, path, { A: "1" });
      await save(t.adm.token, t.gk, path, { A: "2" });
      expect((await api("DELETE", `/secret?path=${path}`, t.adm.token)).status).toBe(200);
    }
    const setDeleted = (path: string, daysAgo: number) =>
      env.DB.prepare("UPDATE secret SET deleted_at = ? WHERE path = ?")
        .bind(Math.floor(Date.now() / 1000) - daysAgo * DAY, path)
        .run();
    await setDeleted(old, 31);
    await setDeleted(edge, 29);
    await setDeleted(recent, 0);

    expect((await api("POST", `/secret/restore-delete?path=${old}`, t.adm.token)).status).toBe(410);
    expect((await api("POST", `/secret/restore-delete?path=${edge}`, t.adm.token)).status).toBe(
      200,
    );
    expect(await readValues(t.adm.token, t.gk, edge)).toEqual({ A: "2" });

    await runDaily(env as unknown as Env, Math.floor(Date.now() / 1000));
    const left = (path: string) =>
      env.DB.prepare(
        `SELECT (SELECT COUNT(*) FROM secret WHERE path = ?) AS secrets,
                (SELECT COUNT(*) FROM secret_version v JOIN secret s ON s.id = v.secret_id WHERE s.path = ?) AS versions`,
      )
        .bind(path, path)
        .first<{ secrets: number; versions: number }>();
    expect(await left(old)).toEqual({ secrets: 0, versions: 0 });
    expect(await left(recent)).toEqual({ secrets: 1, versions: 2 });
    expect((await api("POST", `/secret/restore-delete?path=${recent}`, t.adm.token)).status).toBe(
      200,
    );
  });
});

describe("default deny for the new routes (ADR 5)", () => {
  it("an identity with no policy gets nothing from any new route", async () => {
    const p = uniq("deny");
    const path = `${p}/prod`;
    const t = await team(p);
    await save(t.adm.token, t.gk, path, { A: "1" }, { meta: { description: "before" } });
    const nobody = await makeIdentity();
    expect((await api("GET", `/secret/history?path=${path}`, nobody.token)).status).toBe(403);
    expect((await api("GET", `/secret/versions?path=${path}`, nobody.token)).status).toBe(403);
    expect(
      (await api("PUT", "/secret/meta", nobody.token, { path, meta: { description: "hijack" } }))
        .status,
    ).toBe(403);
    expect((await api("POST", `/secret/restore-delete?path=${path}`, nobody.token)).status).toBe(
      403,
    );
    const list = await api<{ path: string; meta: unknown }[]>("GET", "/secrets", nobody.token);
    expect(list.body.find((s) => s.path === path)).toBeUndefined();
    const row = await env.DB.prepare("SELECT meta FROM secret WHERE path = ?")
      .bind(path)
      .first<{ meta: string }>();
    expect(JSON.parse(row?.meta ?? "{}")).toEqual({ description: "before" });
  });
});

describe("audit entries (ADR 6)", () => {
  it("record names, paths, versions and identities only, for the new actions too", async () => {
    const MARK = "sk_live_AUDIT_MARKER_0077";
    const p = uniq("aud");
    const path = `${p}/prod`;
    const t = await team(p, ["r"]);
    await grant(t.adm, t.people.r as Person, [{ path: `${p}/*`, caps: ["read"] }]);
    await save(t.adm.token, t.gk, path, { KEY: MARK });
    await api("GET", `/secret?path=${path}`, (t.people.r as Person).token);
    await api("GET", `/secret/history?path=${path}`, t.adm.token);
    await api("PUT", "/secret/meta", t.adm.token, { path, meta: { description: "d" } });
    await api("DELETE", `/secret?path=${path}`, t.adm.token);
    await api("POST", `/secret/restore-delete?path=${path}`, t.adm.token);

    const rows = (
      await env.DB.prepare("SELECT entry FROM audit WHERE json_extract(entry, '$.path') = ?")
        .bind(path)
        .all<{ entry: string }>()
    ).results;
    const actions = rows.map((r) => JSON.parse(r.entry).action);
    expect(actions).toEqual(
      expect.arrayContaining([
        "secret.write",
        "secret.read",
        "secret.meta",
        "secret.delete",
        "secret.restore",
      ]),
    );
    for (const r of rows) expect(r.entry).not.toContain(MARK);
  });
});
