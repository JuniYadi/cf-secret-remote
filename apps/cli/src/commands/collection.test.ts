import { describe, expect, it } from "bun:test";
import { CliError } from "../client.ts";
import {
  applyEdits,
  EXIT,
  formatCompare,
  formatPreview,
  parseEnvFlag,
  parseKeyFlag,
} from "./collection.ts";

describe("collection flags", () => {
  it("reads label=path and keeps any later '=' in the path", () => {
    expect(parseEnvFlag("prod=myapp/prod")).toEqual({ label: "prod", path: "myapp/prod" });
    expect(() => parseEnvFlag("prod")).toThrow(CliError);
    expect(() => parseEnvFlag("bad label=x/y")).toThrow(CliError);
  });

  it("reads NAME, NAME=description and treats an empty description as none", () => {
    expect(parseKeyFlag("API_KEY")).toEqual({ name: "API_KEY" });
    expect(parseKeyFlag("API_KEY=payments token = x")).toEqual({
      name: "API_KEY",
      description: "payments token = x",
    });
    expect(parseKeyFlag("API_KEY=")).toEqual({ name: "API_KEY", description: null });
    expect(() => parseKeyFlag("api-key")).toThrow(CliError);
  });
});

describe("collection edits", () => {
  const cur = {
    envs: [
      { label: "dev", path: "myapp/dev" },
      { label: "prod", path: "myapp/prod" },
    ],
    keys: [
      { name: "A", description: "keep me" },
      { name: "B", description: null },
    ],
  };

  it("keeps a description unless a new one is given, and applies removals", () => {
    const next = applyEdits(cur, {
      env: [{ label: "stg", path: "myapp/stg" }],
      removeEnv: ["prod"],
      key: [{ name: "A" }, { name: "C", description: "new" }],
      removeKey: ["B"],
    });
    expect(next).toEqual({
      envs: [
        { label: "dev", path: "myapp/dev" },
        { label: "stg", path: "myapp/stg" },
      ],
      keys: [
        { name: "A", description: "keep me" },
        { name: "C", description: "new" },
      ],
    });
  });

  it("clears a description only when asked", () => {
    const next = applyEdits(cur, {
      env: [],
      removeEnv: [],
      key: [{ name: "A", description: null }],
      removeKey: [],
    });
    expect(next.keys[0]).toEqual({ name: "A", description: null });
  });
});

describe("collection output", () => {
  it("shows names and labels only in the preview", () => {
    const lines = formatPreview({
      name: "myapp",
      exists: true,
      revision: 2,
      changes: {
        addedKeys: ["C"],
        removedKeys: ["B"],
        changedKeys: [],
        addedEnvs: [],
        removedEnvs: [],
        changedEnvs: [],
      },
      envs: [
        { label: "dev", path: "myapp/dev", status: "ok" },
        { label: "prod", path: "myapp/prod", status: "inaccessible" },
      ],
    });
    expect(lines).toContain("  + key C");
    expect(lines.join("\n")).toContain("values are kept");
    expect(lines).toContain("  prod myapp/prod: no access");
  });

  it("shows missing and extra names per environment, and the result word", () => {
    const lines = formatCompare({
      name: "myapp",
      revision: 1,
      result: "drift",
      observedAt: 1,
      envs: [
        { label: "dev", path: "myapp/dev", status: "ok", version: 3, missing: [], extra: [] },
        {
          label: "prod",
          path: "myapp/prod",
          status: "ok",
          version: 2,
          missing: ["B"],
          extra: ["X"],
        },
        { label: "stg", path: "myapp/stg", status: "missing_path" },
      ],
    });
    expect(lines[0]).toBe("collection myapp, revision 1");
    expect(lines).toContain("  dev myapp/dev (version 3)  matches");
    expect(lines).toContain("  prod myapp/prod (version 2)  missing: B  extra: X");
    expect(lines).toContain("  stg myapp/stg: path does not exist");
    expect(lines.at(-1)).toBe("result: drift");
  });

  it("gives every outcome its own exit code, and errors a code no outcome uses", () => {
    expect(EXIT).toEqual({ clean: 0, drift: 1, incomplete: 2, error: 3 });
  });
});
