import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { PROTOCOL_VERSION, parseManifest } from "@cfs/core";
import {
  buildManifest,
  listFiles,
  MANIFEST,
  parseJsonc,
  sha256Hex,
  wranglerSettings,
  writeManifest,
} from "./bundle-worker.ts";

const here = dirname(fileURLToPath(import.meta.url));
const SETTINGS = {
  compatibility_date: "2026-08-01",
  crons: ["5 0 * * *"],
  assets: { not_found_handling: "single-page-application", run_worker_first: ["/api/*"] },
  vars: { AUDIT_RETENTION_DAYS: "365" },
};
const enc = (s: string) => new TextEncoder().encode(s);

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cfs-bundle-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** A bundle laid out like the real one: worker, assets, migrations. */
function fakeBundle(): void {
  for (const [p, body] of Object.entries({
    "worker/index.js": "export default {};",
    "assets/index.html": "<!doctype html>",
    "assets/app/app.js": "console.log(1)",
    "migrations/0001_init.sql": "CREATE TABLE a (x);",
    "migrations/0002_more.sql": "CREATE TABLE b (y);",
  })) {
    mkdirSync(dirname(join(dir, p)), { recursive: true });
    writeFileSync(join(dir, p), body);
  }
}

describe("bundle manifest (ADR 25)", () => {
  test("every file gets the SHA-256 of its exact bytes", () => {
    const files = new Map([["worker/index.js", enc("abc")]]);
    const m = buildManifest({
      version: "0.2.0",
      settings: SETTINGS,
      migrations: [],
      files,
    });
    expect(m.files["worker/index.js"]).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    expect(m.files["worker/index.js"]).toBe(sha256Hex(enc("abc")));
  });

  test("the manifest records version, protocol, and the Worker entry", () => {
    const m = buildManifest({
      version: "1.2.3",
      settings: SETTINGS,
      migrations: [],
      files: new Map(),
    });
    expect(m.format).toBe(1);
    expect(m.version).toBe("1.2.3");
    expect(m.protocol).toBe(PROTOCOL_VERSION);
    expect(m.main).toBe("worker/index.js");
    expect(m.compatibility_date).toBe("2026-08-01");
    expect(m.crons).toEqual(["5 0 * * *"]);
    expect(m.assets.run_worker_first).toEqual(["/api/*"]);
  });

  test("migrations are listed in the order given and must exist in the bundle", () => {
    const files = new Map([
      ["migrations/0001_init.sql", enc("a")],
      ["migrations/0002_more.sql", enc("b")],
    ]);
    const m = buildManifest({
      version: "1",
      settings: SETTINGS,
      migrations: ["0001_init.sql", "0002_more.sql"],
      files,
    });
    expect(m.migrations).toEqual(["0001_init.sql", "0002_more.sql"]);
    expect(() =>
      buildManifest({ version: "1", settings: SETTINGS, migrations: ["0009_gone.sql"], files }),
    ).toThrow(/0009_gone.sql/);
  });

  test("a manifest with a missing or wrong field is rejected", () => {
    const good = buildManifest({
      version: "1",
      settings: SETTINGS,
      migrations: [],
      files: new Map(),
    });
    expect(parseManifest(JSON.parse(JSON.stringify(good))).version).toBe("1");
    expect(() => parseManifest({ ...good, format: 2 })).toThrow(/format/);
    expect(() => parseManifest({ ...good, version: undefined })).toThrow(/version/);
    expect(() => parseManifest({ ...good, files: { "a.js": 1 } })).toThrow(/files/);
    expect(() => parseManifest([])).toThrow(/object/);
  });

  test("writeManifest hashes every file on disk except manifest.json itself", () => {
    fakeBundle();
    const m = writeManifest(dir, {
      version: "9.9.9",
      settings: SETTINGS,
      migrations: ["0001_init.sql", "0002_more.sql"],
    });
    expect(Object.keys(m.files).sort()).toEqual([
      "assets/app/app.js",
      "assets/index.html",
      "migrations/0001_init.sql",
      "migrations/0002_more.sql",
      "worker/index.js",
    ]);
    expect(m.files["migrations/0001_init.sql"]).toBe(sha256Hex(enc("CREATE TABLE a (x);")));
    const onDisk = JSON.parse(readFileSync(join(dir, MANIFEST), "utf8"));
    expect(onDisk).toEqual(m);
    expect(listFiles(dir)).not.toContain(MANIFEST);
  });

  test("a tampered file no longer matches the manifest hash", () => {
    fakeBundle();
    const m = writeManifest(dir, { version: "1", settings: SETTINGS, migrations: [] });
    writeFileSync(join(dir, "worker/index.js"), "evil");
    expect(sha256Hex(readFileSync(join(dir, "worker/index.js")))).not.toBe(
      m.files["worker/index.js"],
    );
  });
});

describe("wrangler.jsonc settings", () => {
  test("the real apps/api/wrangler.jsonc yields the crons, compatibility date and asset rules", () => {
    const text = readFileSync(join(here, "../apps/api/wrangler.jsonc"), "utf8");
    const s = wranglerSettings(text);
    expect(s.compatibility_date).toBe("2026-08-01");
    expect(s.crons).toEqual(["5 0 * * *"]);
    expect(s.assets.run_worker_first).toEqual(["/api/*"]);
    expect(s.assets.not_found_handling).toBe("single-page-application");
    expect(s.vars).toEqual({ AUDIT_RETENTION_DAYS: "365" });
  });

  test("comments, including ones after values, are ignored; URLs in strings survive", () => {
    const v = parseJsonc(`{
      // top comment
      "a": "https://example.com", // trailing
      "b": [1, 2,],
    }`) as { a: string; b: number[] };
    expect(v.a).toBe("https://example.com");
    expect(v.b).toEqual([1, 2]);
  });
});
