import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import * as collectionRepository from "../src/repository/collections.ts";
import { admin, api, makeIdentity } from "./helpers.ts";

// ADR 36 tests: environment collections. Each test uses its own prefix so paths and collections never clash.
let counter = 0;
const pfx = () => `ec${++counter}${Math.random().toString(36).slice(2, 6)}`;

/** An admin, a keyring for the prefix, and a helper that writes a names-only version (values are opaque here). */
async function setup() {
  const adm = await admin();
  const p = pfx();
  const made = await api("POST", "/keyrings", adm.token, {
    prefix: p,
    members: [{ identityId: adm.id, wrappedKey: "w" }],
  });
  expect(made.status).toBe(201);
  const versions = new Map<string, number>();
  const put = async (path: string, names: string[]) => {
    const version = (versions.get(path) ?? 0) + 1;
    const r = await api("PUT", "/secret", adm.token, {
      path,
      names,
      wrappedDek: "d",
      ciphertext: `v1.${version}.x`,
      keyringVersion: 1,
      version,
    });
    expect(r.status).toBeLessThan(300);
    versions.set(path, version);
    return version;
  };
  return { adm, p, put, versions, collection: `col-${p}`, dev: `${p}/dev`, prod: `${p}/prod` };
}

/** A member with the given policy rules. */
async function member(adm: { token: string }, rules: unknown[]) {
  const m = await makeIdentity();
  const pol = await api("POST", "/policies", adm.token, {
    name: `pol-${pfx()}`,
    rules,
  });
  expect(pol.status).toBe(201);
  await api("POST", `/policies/${pol.body.id}/assign`, adm.token, { identityId: m.id });
  return m;
}

describe("collections: definitions", () => {
  it("checks source versions inside the same batch as collection writes", async () => {
    const s = await setup();
    await s.put(s.dev, ["FIRST"]);
    await s.put(s.dev, ["SECOND"]);
    const definition = [{ label: "dev", path: s.dev }];
    expect(
      await collectionRepository.createCollection(
        env.DB,
        `id-${s.collection}`,
        s.collection,
        1,
        definition,
        [{ name: "FIRST", description: null }],
        { [s.dev]: 1 },
      ),
    ).toBe(false);
    expect(await collectionRepository.findCollection(env.DB, s.collection)).toBeNull();
    expect(
      await collectionRepository.createCollection(
        env.DB,
        `id-${s.collection}`,
        s.collection,
        1,
        definition,
        [],
        { [s.dev]: 2 },
      ),
    ).toBe(true);
    expect(
      await collectionRepository.addKeys(
        env.DB,
        `id-${s.collection}`,
        1,
        2,
        [{ name: "FIRST", description: null }],
        { [s.dev]: 1 },
      ),
    ).toBe(false);
    expect(
      (await collectionRepository.collectionKeys(env.DB, `id-${s.collection}`)).results,
    ).toEqual([]);
    expect((await collectionRepository.findCollection(env.DB, s.collection))?.revision).toBe(1);
  });
  it("creates, reads and lists a definition without values", async () => {
    const s = await setup();
    const body = {
      name: s.collection,
      envs: [
        { label: "dev", path: s.dev },
        { label: "prod", path: s.prod },
      ],
      keys: [{ name: "API_KEY", description: "payments token" }, { name: "DATABASE_URL" }],
    };
    const created = await api("POST", "/collections", s.adm.token, body);
    expect(created.status).toBe(201);
    expect(created.body).toEqual({ name: s.collection, revision: 1 });

    const got = await api("GET", `/collections/${s.collection}`, s.adm.token);
    expect(got.status).toBe(200);
    expect(got.body.envs).toEqual([
      { label: "dev", path: s.dev },
      { label: "prod", path: s.prod },
    ]);
    expect(got.body.keys).toEqual([
      { name: "API_KEY", description: "payments token" },
      { name: "DATABASE_URL", description: null },
    ]);
    const list = await api<{ name: string; keyCount: number }[]>(
      "GET",
      "/collections",
      s.adm.token,
    );
    expect(list.body.find((c) => c.name === s.collection)).toMatchObject({
      keyCount: 2,
      envCount: 2,
    });
  });

  it("refuses duplicate names, reserved names and invalid mappings", async () => {
    const s = await setup();
    const env = [{ label: "dev", path: s.dev }];
    expect(
      (await api("POST", "/collections", s.adm.token, { name: s.collection, envs: env })).status,
    ).toBe(201);
    expect(
      (await api("POST", "/collections", s.adm.token, { name: s.collection, envs: env })).body.code,
    ).toBe("name_exists");
    expect(
      (await api("POST", "/collections", s.adm.token, { name: "new", envs: env })).status,
    ).toBe(400);
    expect(
      (
        await api("POST", "/collections", s.adm.token, {
          name: `${s.collection}-b`,
          envs: [
            { label: "dev", path: s.dev },
            { label: "dev", path: s.prod },
          ],
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await api("POST", "/collections", s.adm.token, {
          name: `${s.collection}-c`,
          envs: [{ label: "dev", path: "../etc" }],
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await api("POST", "/collections", s.adm.token, {
          name: `${s.collection}-d`,
          envs: env,
          keys: [{ name: "bad-name" }],
        })
      ).status,
    ).toBe(400);
  });

  it("is default deny: a stranger sees nothing and gets the same refusal for an unknown name", async () => {
    const s = await setup();
    await api("POST", "/collections", s.adm.token, {
      name: s.collection,
      envs: [{ label: "dev", path: s.dev }],
    });
    const stranger = await makeIdentity();
    expect(await api<unknown[]>("GET", "/collections", stranger.token)).toMatchObject({
      status: 200,
      body: [],
    });
    const exists = await api("GET", `/collections/${s.collection}`, stranger.token);
    const missing = await api("GET", `/collections/${s.collection}-nope`, stranger.token);
    expect(exists.status).toBe(403);
    expect(missing.status).toBe(403);
    expect(exists.body).toEqual(missing.body);
    const create = await api("POST", "/collections", stranger.token, {
      name: `${s.collection}-x`,
      envs: [{ label: "dev", path: s.dev }],
    });
    expect(create.status).toBe(403);
    expect((await api("GET", `/collections/${s.collection}-x`, s.adm.token)).status).toBe(404);
  });

  it("collection rules never grant path access, and secret rules never grant the collection", async () => {
    const s = await setup();
    await api("POST", "/collections", s.adm.token, {
      name: s.collection,
      envs: [{ label: "dev", path: s.dev }],
      keys: [{ name: "A" }],
    });
    await s.put(s.dev, ["A"]);
    const metaOnly = await member(s.adm, [{ collection: s.collection, caps: ["read"] }]);
    expect((await api("GET", `/collections/${s.collection}`, metaOnly.token)).status).toBe(200);
    const putBody = { revision: 1, envs: [{ label: "dev", path: s.dev }], keys: [{ name: "A" }] };
    expect((await api("PUT", `/collections/${s.collection}`, metaOnly.token, putBody)).status).toBe(
      403,
    );
    // No secret capability: the read is still refused, and the compare shows the path as inaccessible.
    expect((await api("GET", `/secret?path=${s.dev}`, metaOnly.token)).status).toBe(403);
    const cmp = await api("GET", `/collections/${s.collection}/compare`, metaOnly.token);
    expect(cmp.body.result).toBe("incomplete");
    expect(cmp.body.envs[0]).toEqual({ label: "dev", path: s.dev, status: "inaccessible" });

    const pathOnly = await member(s.adm, [{ path: `${s.p}/*`, caps: ["list", "read"] }]);
    expect((await api("GET", `/collections/${s.collection}`, pathOnly.token)).status).toBe(403);
    expect((await api("GET", `/collections/${s.collection}/compare`, pathOnly.token)).status).toBe(
      403,
    );
  });
});

describe("collections: comparison", () => {
  it("reports clean, drift, missing and inaccessible states separately", async () => {
    const s = await setup();
    await s.put(s.dev, ["API_KEY", "DATABASE_URL"]);
    await s.put(s.prod, ["API_KEY", "DATABASE_URL"]);
    await api("POST", "/collections", s.adm.token, {
      name: s.collection,
      envs: [
        { label: "dev", path: s.dev },
        { label: "prod", path: s.prod },
      ],
      keys: [{ name: "API_KEY" }, { name: "DATABASE_URL" }],
    });

    const clean = await api("GET", `/collections/${s.collection}/compare`, s.adm.token);
    expect(clean.body.result).toBe("clean");
    expect(clean.body.envs.map((e: { version: number }) => e.version)).toEqual([1, 1]);

    // prod loses DATABASE_URL and gains an undeclared name: drift, and the version moves on.
    await s.put(s.prod, ["API_KEY", "EXTRA_FLAG"]);
    const drift = await api("GET", `/collections/${s.collection}/compare`, s.adm.token);
    expect(drift.body.result).toBe("drift");
    expect(drift.body.envs[1]).toMatchObject({
      version: 2,
      missing: ["DATABASE_URL"],
      extra: ["EXTRA_FLAG"],
    });
    expect(drift.body.envs[0]).toMatchObject({ missing: [], extra: [] });
  });

  it("treats an absent path as incomplete, not as drift, and never as clean", async () => {
    const s = await setup();
    await s.put(s.dev, ["A"]);
    await api("POST", "/collections", s.adm.token, {
      name: s.collection,
      envs: [
        { label: "dev", path: s.dev },
        { label: "stg", path: `${s.p}/stg` },
      ],
      keys: [{ name: "A" }],
    });
    const cmp = await api("GET", `/collections/${s.collection}/compare`, s.adm.token);
    expect(cmp.body.result).toBe("incomplete");
    expect(cmp.body.envs[1]).toEqual({ label: "stg", path: `${s.p}/stg`, status: "missing_path" });
  });

  it("does not reveal whether an unlisted path exists", async () => {
    const s = await setup();
    await s.put(s.dev, ["A"]);
    await api("POST", "/collections", s.adm.token, {
      name: s.collection,
      envs: [
        { label: "dev", path: s.dev },
        { label: "ghost", path: `${s.p}/ghost` },
      ],
      keys: [{ name: "A" }],
    });
    const partial = await member(s.adm, [
      { collection: s.collection, caps: ["read"] },
      { path: s.dev, caps: ["list", "read"] },
    ]);
    const cmp = await api("GET", `/collections/${s.collection}/compare`, partial.token);
    expect(cmp.status).toBe(200);
    expect(cmp.body.result).toBe("incomplete");
    expect(cmp.body.envs[0]).toMatchObject({
      status: "ok",
      present: ["A"],
      missing: [],
      extra: [],
    });
    // The ghost path is refused exactly like an existing path the caller cannot list.
    expect(cmp.body.envs[1]).toEqual({
      label: "ghost",
      path: `${s.p}/ghost`,
      status: "inaccessible",
    });
  });

  it("shows only names: a compare never returns a value or ciphertext", async () => {
    const s = await setup();
    await s.put(s.dev, ["A"]);
    await api("POST", "/collections", s.adm.token, {
      name: s.collection,
      envs: [{ label: "dev", path: s.dev }],
      keys: [{ name: "A" }],
    });
    const raw = JSON.stringify(
      (await api("GET", `/collections/${s.collection}/compare`, s.adm.token)).body,
    );
    expect(raw).not.toContain("v1.");
    expect(raw).not.toContain("ciphertext");
  });
});

describe("collections: changes", () => {
  it("previews without writing, then applies a change only at the current revision", async () => {
    const s = await setup();
    await s.put(s.dev, ["A"]);
    await api("POST", "/collections", s.adm.token, {
      name: s.collection,
      envs: [{ label: "dev", path: s.dev }],
      keys: [{ name: "A" }, { name: "B" }],
    });
    const preview = await api("POST", "/collections/preview", s.adm.token, {
      name: s.collection,
      envs: [{ label: "dev", path: s.dev }],
      keys: [{ name: "A" }, { name: "C" }],
    });
    expect(preview.status).toBe(200);
    expect(preview.body).toMatchObject({
      exists: true,
      revision: 1,
      changes: { addedKeys: ["C"], removedKeys: ["B"] },
    });
    expect(preview.body.envs[0].status).toBe("ok");
    expect((await api("GET", `/collections/${s.collection}`, s.adm.token)).body.revision).toBe(1);

    // Removing B needs it listed in `removed`.
    const unlisted = await api("PUT", `/collections/${s.collection}`, s.adm.token, {
      revision: 1,
      envs: [{ label: "dev", path: s.dev }],
      keys: [{ name: "A" }, { name: "C" }],
    });
    expect(unlisted.status).toBe(400);
    const applied = await api("PUT", `/collections/${s.collection}`, s.adm.token, {
      revision: 1,
      envs: [{ label: "dev", path: s.dev }],
      keys: [{ name: "A" }, { name: "C" }],
      removed: { keys: ["B"], envs: [] },
    });
    expect(applied.status).toBe(200);
    expect(applied.body.revision).toBe(2);

    const stale = await api("PUT", `/collections/${s.collection}`, s.adm.token, {
      revision: 1,
      envs: [{ label: "dev", path: s.dev }],
      keys: [{ name: "A" }],
    });
    expect(stale.status).toBe(400); // removal of C is unlisted first
    const again = await api("PUT", `/collections/${s.collection}`, s.adm.token, {
      revision: 1,
      envs: [{ label: "dev", path: s.dev }],
      keys: [{ name: "A" }, { name: "C" }],
    });
    expect(again.status).toBe(409);
    expect(again.body.code).toBe("collection_changed");
  });

  it("reconciles a selected extra name, refusing stale revisions and stale source versions", async () => {
    const s = await setup();
    await s.put(s.dev, ["A"]);
    await s.put(s.prod, ["A", "EXTRA"]);
    await api("POST", "/collections", s.adm.token, {
      name: s.collection,
      envs: [
        { label: "dev", path: s.dev },
        { label: "prod", path: s.prod },
      ],
      keys: [{ name: "A" }],
    });

    const preview = await api(
      "POST",
      `/collections/${s.collection}/reconcile/preview`,
      s.adm.token,
      {
        names: ["EXTRA"],
      },
    );
    expect(preview.status).toBe(200);
    expect(preview.body.names).toEqual([{ name: "EXTRA", declared: false, observedIn: ["prod"] }]);
    const { revision, sourceVersions } = {
      revision: preview.body.revision,
      sourceVersions: preview.body.sourceVersions,
    };
    expect(sourceVersions).toEqual({ [s.prod]: 1 });

    // A new version of prod arrives after the preview: the apply is refused and nothing is declared.
    await s.put(s.prod, ["A", "EXTRA", "MORE"]);
    const stale = await api("POST", `/collections/${s.collection}/reconcile`, s.adm.token, {
      revision,
      names: ["EXTRA"],
      sourceVersions,
    });
    expect(stale.status).toBe(409);
    expect(stale.body.code).toBe("source_changed");

    const fresh = await api("POST", `/collections/${s.collection}/reconcile/preview`, s.adm.token, {
      names: ["EXTRA"],
    });
    const late = await api("POST", `/collections/${s.collection}/reconcile`, s.adm.token, {
      revision: 99,
      names: ["EXTRA"],
      sourceVersions: fresh.body.sourceVersions,
    });
    expect(late.status).toBe(409);
    expect(late.body.code).toBe("collection_changed");

    const ok = await api("POST", `/collections/${s.collection}/reconcile`, s.adm.token, {
      revision: 1,
      names: ["EXTRA"],
      sourceVersions: fresh.body.sourceVersions,
    });
    expect(ok.status).toBe(200);
    expect(ok.body).toEqual({ name: s.collection, revision: 2, added: ["EXTRA"] });

    // The declaration now expects EXTRA in every environment; prod has it, dev is missing it.
    const cmp = await api("GET", `/collections/${s.collection}/compare`, s.adm.token);
    expect(cmp.body.result).toBe("drift");
    expect(cmp.body.envs[0].missing).toEqual(["EXTRA"]);
    expect(cmp.body.envs[1]).toMatchObject({ version: 2, missing: [], extra: ["MORE"] });
  });

  it("refuses to reconcile a name that is declared already or no longer extra", async () => {
    const s = await setup();
    await s.put(s.dev, ["A"]);
    await api("POST", "/collections", s.adm.token, {
      name: s.collection,
      envs: [{ label: "dev", path: s.dev }],
      keys: [{ name: "A" }],
    });
    const declared = await api(
      "POST",
      `/collections/${s.collection}/reconcile/preview`,
      s.adm.token,
      {
        names: ["A"],
      },
    );
    expect(declared.body.names[0]).toMatchObject({ declared: true });
    const apply = await api("POST", `/collections/${s.collection}/reconcile`, s.adm.token, {
      revision: 1,
      names: ["A"],
      sourceVersions: { [s.dev]: 1 },
    });
    expect(apply.status).toBe(400);
    const gone = await api("POST", `/collections/${s.collection}/reconcile`, s.adm.token, {
      revision: 1,
      names: ["NOPE"],
      sourceVersions: { [s.dev]: 1 },
    });
    expect(gone.status).toBe(409);
    expect(gone.body.code).toBe("source_changed");
  });

  it("does not let a metadata-only caller reconcile or reveal extras", async () => {
    const s = await setup();
    await s.put(s.dev, ["A", "EXTRA"]);
    await api("POST", "/collections", s.adm.token, {
      name: s.collection,
      envs: [{ label: "dev", path: s.dev }],
      keys: [{ name: "A" }],
    });
    const reader = await member(s.adm, [
      { collection: s.collection, caps: ["read"] },
      { path: s.dev, caps: ["list", "read"] },
    ]);
    const preview = await api(
      "POST",
      `/collections/${s.collection}/reconcile/preview`,
      reader.token,
      {
        names: ["EXTRA"],
      },
    );
    expect(preview.status).toBe(403);
    expect(JSON.stringify(preview.body)).not.toContain("EXTRA");
  });

  it("deletes a definition at the current revision and leaves the secrets alone", async () => {
    const s = await setup();
    await s.put(s.dev, ["A"]);
    await api("POST", "/collections", s.adm.token, {
      name: s.collection,
      envs: [{ label: "dev", path: s.dev }],
      keys: [{ name: "A" }],
    });
    expect(
      (await api("DELETE", `/collections/${s.collection}?revision=9`, s.adm.token)).status,
    ).toBe(409);
    expect(
      (await api("DELETE", `/collections/${s.collection}?revision=1`, s.adm.token)).status,
    ).toBe(200);
    expect((await api("GET", `/collections/${s.collection}`, s.adm.token)).status).toBe(404);
    const secret = await api("GET", `/secret?path=${s.dev}`, s.adm.token);
    expect(secret.status).toBe(200);
    expect(secret.body.version).toBe(1);
  });
});

describe("collections: discovery and creation from paths", () => {
  it("discovers the union of readable sources and refuses the whole union if one is not listable", async () => {
    const s = await setup();
    await s.put(s.dev, ["A", "B"]);
    await s.put(s.prod, ["B", "C"]);
    const ok = await api("POST", "/collections/discover", s.adm.token, {
      paths: [s.dev, s.prod, `${s.p}/ghost`],
    });
    expect(ok.status).toBe(200);
    expect(ok.body.union).toEqual(["A", "B", "C"]);
    expect(ok.body.sources[2]).toEqual({ path: `${s.p}/ghost`, status: "missing_path" });

    const partial = await member(s.adm, [{ path: s.dev, caps: ["list"] }]);
    const refused = await api("POST", "/collections/discover", partial.token, {
      paths: [s.dev, s.prod],
    });
    expect(refused.status).toBe(403);
    expect(refused.body).toEqual({ error: "denied" });
  });

  it("creates from a reviewed union only while the source versions are current", async () => {
    const s = await setup();
    await s.put(s.dev, ["A"]);
    const body = {
      name: s.collection,
      envs: [{ label: "dev", path: s.dev }],
      keys: [{ name: "A" }],
      sourceVersions: { [s.dev]: 1 },
    };
    await s.put(s.dev, ["A", "B"]);
    const stale = await api("POST", "/collections", s.adm.token, body);
    expect(stale.status).toBe(409);
    expect(stale.body.code).toBe("source_changed");
    const fresh = await api("POST", "/collections", s.adm.token, {
      ...body,
      sourceVersions: { [s.dev]: 2 },
    });
    expect(fresh.status).toBe(201);
  });
});

describe("collections: policy and audit", () => {
  it("validates collection rules in policies and keeps the two kinds apart", async () => {
    const adm = await admin();
    const bad = [
      [{ path: "x/*", collection: "y*", caps: ["read"] }],
      [{ collection: "y*", caps: ["list"] }],
      [{ path: "x/*", caps: ["manage"] }],
      [{ collection: "bad glob!", caps: ["read"] }],
    ];
    for (const rules of bad) {
      const r = await api("POST", "/policies", adm.token, { name: `bad-${pfx()}`, rules });
      expect(r.status).toBe(400);
    }
    const good = await api("POST", "/policies", adm.token, {
      name: `good-${pfx()}`,
      rules: [{ collection: "team-*", caps: ["read", "manage"] }],
    });
    expect(good.status).toBe(201);
  });

  it("audits changes and denials by name only", async () => {
    const s = await setup();
    const stranger = await makeIdentity();
    await api("GET", `/collections/${s.collection}`, stranger.token);
    await api("POST", "/collections", s.adm.token, {
      name: s.collection,
      envs: [{ label: "dev", path: s.dev }],
      keys: [{ name: "A" }],
    });
    await api("PUT", `/collections/${s.collection}`, s.adm.token, {
      revision: 1,
      envs: [{ label: "dev", path: s.dev }],
      keys: [{ name: "A" }, { name: "NEW_ONE" }],
    });
    const log = await api<{ action: string; result: string; note?: string }[]>(
      "GET",
      "/audit?limit=200",
      s.adm.token,
    );
    const rows = log.body;
    expect(
      rows.some((r) => r.action === "collection.create" && r.note?.startsWith(s.collection)),
    ).toBe(true);
    expect(
      rows.some((r) => r.action === "collection.update" && r.note?.includes("+key NEW_ONE")),
    ).toBe(true);
    expect(rows.some((r) => r.action === "collection.read" && r.result === "denied")).toBe(true);
    expect(JSON.stringify(rows)).not.toContain("v1.");
  });

  it("caps the number of collections", async () => {
    const s = await setup();
    const have = (await api<unknown[]>("GET", "/collections", s.adm.token)).body.length;
    for (let i = have; i < 50; i++) {
      const r = await api("POST", "/collections", s.adm.token, {
        name: `${s.collection}-${i}`,
        envs: [{ label: "dev", path: `${s.p}/q${i}` }],
      });
      expect(r.status).toBe(201);
    }
    const over = await api("POST", "/collections", s.adm.token, {
      name: `${s.collection}-over`,
      envs: [{ label: "dev", path: s.dev }],
    });
    expect(over.status).toBe(400);
  });
});
