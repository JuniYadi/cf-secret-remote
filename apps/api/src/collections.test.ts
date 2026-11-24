import { describe, expect, it } from "vitest";
import {
  compareEnvs,
  diffDefinition,
  extraNames,
  MAX_ENVS,
  MAX_KEYS,
  type Observation,
  parseDefinition,
  parseRemovals,
  removalsConfirmed,
  requiredSources,
  validCollectionName,
} from "./collections.ts";
import { type CollectionRule, can, collectionCan, type Rule } from "./policy.ts";

const envs = [
  { label: "dev", path: "myapp/dev" },
  { label: "prod", path: "myapp/prod" },
];

const defOf = (r: { def: unknown } | { error: string }) => ("def" in r ? r.def : r);

describe("collection definitions", () => {
  it("accepts labels, paths and names, and trims descriptions to null when empty", () => {
    const r = parseDefinition({
      envs,
      keys: [
        { name: "API_KEY", description: "  " },
        { name: "DATABASE_URL", description: "db" },
      ],
    });
    expect(defOf(r)).toEqual({
      envs,
      keys: [
        { name: "API_KEY", description: null },
        { name: "DATABASE_URL", description: "db" },
      ],
    });
  });

  it("refuses duplicate labels, duplicate paths, duplicate names and bad values", () => {
    expect(parseDefinition({ envs: [...envs, { label: "dev", path: "other" }] })).toHaveProperty(
      "error",
    );
    expect(parseDefinition({ envs: [...envs, { label: "x", path: "myapp/dev" }] })).toHaveProperty(
      "error",
    );
    expect(parseDefinition({ envs, keys: [{ name: "A" }, { name: "A" }] })).toHaveProperty("error");
    expect(parseDefinition({ envs, keys: [{ name: "lower-case" }] })).toHaveProperty("error");
    expect(parseDefinition({ envs: [{ label: "bad label", path: "myapp/dev" }] })).toHaveProperty(
      "error",
    );
    expect(parseDefinition({ envs: [{ label: "dev", path: "../etc" }] })).toHaveProperty("error");
    expect(parseDefinition({ envs: [] })).toHaveProperty("error");
    expect(
      parseDefinition({ envs, keys: [{ name: "A", description: "x".repeat(201) }] }),
    ).toHaveProperty("error");
    expect(parseDefinition({ envs, keys: [{ name: "A", description: 7 }] })).toHaveProperty(
      "error",
    );
  });

  it("enforces the limits of envs and keys", () => {
    const many = Array.from({ length: MAX_ENVS + 1 }, (_, i) => ({
      label: `e${i}`,
      path: `a/e${i}`,
    }));
    expect(parseDefinition({ envs: many })).toHaveProperty("error");
    const keys = Array.from({ length: MAX_KEYS + 1 }, (_, i) => ({ name: `K${i}` }));
    expect(parseDefinition({ envs, keys })).toHaveProperty("error");
  });

  it("reserves the web route name and checks collection names", () => {
    expect(validCollectionName("myapp")).toBe(true);
    expect(validCollectionName("new")).toBe(false);
    expect(validCollectionName("my/app")).toBe(false);
    expect(validCollectionName("")).toBe(false);
  });

  it("diffs names, descriptions and environments without values", () => {
    const before = {
      envs,
      keys: [
        { name: "A", description: null },
        { name: "B", description: null },
      ],
    };
    const after = {
      envs: [
        { label: "dev", path: "myapp/dev2" },
        { label: "stg", path: "myapp/stg" },
      ],
      keys: [
        { name: "A", description: "now described" },
        { name: "C", description: null },
      ],
    };
    expect(diffDefinition(before, after)).toEqual({
      addedKeys: ["C"],
      removedKeys: ["B"],
      changedKeys: ["A"],
      addedEnvs: ["stg"],
      removedEnvs: ["prod"],
      changedEnvs: ["dev"],
    });
  });

  it("removals must be listed exactly", () => {
    const diff = diffDefinition(
      { envs, keys: [{ name: "A", description: null }] },
      { envs, keys: [] },
    );
    expect(removalsConfirmed(diff, { keys: ["A"], envs: [] })).toBe(true);
    expect(removalsConfirmed(diff, { keys: [], envs: [] })).toBe(false);
    expect(removalsConfirmed(diff, { keys: ["A", "Z"], envs: [] })).toBe(false);
    expect(parseRemovals(undefined)).toEqual({ keys: [], envs: [] });
    expect(parseRemovals({ keys: "A" })).toHaveProperty("error");
  });
});

describe("comparison", () => {
  const ok = (names: string[], version = 3) => ({
    status: "ok" as const,
    version,
    updatedAt: 10,
    names,
  });
  const pair = (dev: Observation, prod: Observation) => [
    { label: "dev", path: "myapp/dev", observed: dev },
    { label: "prod", path: "myapp/prod", observed: prod },
  ];

  it("is clean only when every environment matches", () => {
    const r = compareEnvs(["A", "B"], pair(ok(["A", "B"]), ok(["B", "A"])));
    expect(r.result).toBe("clean");
    expect(r.envs[0]).toMatchObject({
      status: "ok",
      present: ["A", "B"],
      missing: [],
      extra: [],
      version: 3,
    });
  });

  it("reports drift for missing and extra names", () => {
    const r = compareEnvs(["A", "B"], pair(ok(["A", "B", "X"]), ok(["A"])));
    expect(r.result).toBe("drift");
    expect(r.envs[1]).toMatchObject({ missing: ["B"], extra: [] });
    expect(r.envs[0]).toMatchObject({ extra: ["X"] });
  });

  it("treats a stored empty string as present and an absent name as missing", () => {
    const r = compareEnvs(["A"], pair(ok(["A"]), ok([])));
    expect(r.envs[0]?.missing).toEqual([]);
    expect(r.envs[1]?.missing).toEqual(["A"]);
  });

  it("is incomplete, never clean, when a path is inaccessible or missing", () => {
    const hidden = compareEnvs(["A"], pair(ok(["A"]), { status: "inaccessible" }));
    expect(hidden.result).toBe("incomplete");
    expect(hidden.envs[1]).toEqual({ label: "prod", path: "myapp/prod", status: "inaccessible" });
    const gone = compareEnvs(["A"], pair(ok(["A"]), { status: "missing_path" }));
    expect(gone.result).toBe("incomplete");
    expect(gone.envs[1]).toEqual({ label: "prod", path: "myapp/prod", status: "missing_path" });
    // Drift elsewhere does not turn an incomplete check into a drift result.
    expect(compareEnvs(["A"], pair(ok([]), { status: "missing_path" })).result).toBe("incomplete");
  });

  it("lists extra names once across readable environments and sorts them", () => {
    const found = extraNames(["A"], pair(ok(["A", "Z", "M"]), ok(["M"])));
    expect([...found.entries()]).toEqual([
      ["M", ["dev", "prod"]],
      ["Z", ["dev"]],
    ]);
    expect(extraNames(["A"], pair({ status: "inaccessible" }, ok(["Q"])))).toEqual(
      new Map([["Q", ["prod"]]]),
    );
  });

  it("maps the environments that reported a name to their paths", () => {
    const sources = requiredSources(
      new Map([["M", ["prod", "dev"]]]),
      new Map([
        ["dev", "myapp/dev"],
        ["prod", "myapp/prod"],
      ]),
    );
    expect(sources).toEqual(["myapp/dev", "myapp/prod"]);
  });
});

describe("policy rules for collections", () => {
  const secret: Rule[] = [{ path: "myapp/*", caps: ["list", "read"] }];
  const collection: CollectionRule[] = [{ collection: "myapp*", caps: ["read"] }];

  it("default deny for both kinds of rule", () => {
    expect(collectionCan([], "myapp", "read")).toBe(false);
    expect(can([], "myapp/dev", "list")).toBe(false);
  });

  it("collection rules never grant a secret path, and secret rules never grant a collection", () => {
    expect(can(collection as unknown as Rule[], "myapp", "read")).toBe(false);
    expect(collectionCan(secret as unknown as CollectionRule[], "myapp/dev", "read")).toBe(false);
    expect(collectionCan(collection, "myapp", "read")).toBe(true);
    expect(collectionCan(collection, "myapp", "manage")).toBe(false);
    // A manager may also read: a change previews the declared names, which only a reader sees.
    const manager: CollectionRule[] = [{ collection: "myapp", caps: ["manage"] }];
    expect(collectionCan(manager, "myapp", "read")).toBe(true);
    expect(collectionCan(manager, "myapp", "manage")).toBe(true);
    expect(collectionCan(manager, "other", "read")).toBe(false);
    expect(can(secret, "myapp/dev", "list")).toBe(true);
  });
});
