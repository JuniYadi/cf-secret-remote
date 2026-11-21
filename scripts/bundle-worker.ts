#!/usr/bin/env bun

// ADR 25: builds dist/worker-bundle.tgz, the Worker that `cfs deploy` installs.
//
// Layout inside the tarball (also written to dist/worker-bundle/ for inspection):
//   manifest.json      see packages/core/src/bundle.ts
//   worker/index.js    the Worker, bundled by wrangler's own esbuild step (dry run)
//   assets/            the built web app (apps/web/dist)
//   migrations/*.sql   D1 migrations, applied in name order
//
// The Worker is bundled with `wrangler deploy --dry-run --outdir`, the same bundler that
// `wrangler deploy` uses, so the output matches what the Cloudflare API accepts.

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { type BundleManifest, PROTOCOL_VERSION, parseManifest } from "@cfs/core";

export const MANIFEST = "manifest.json";

/** Strips // comments and trailing commas from wrangler.jsonc so JSON.parse accepts it. */
export function parseJsonc(text: string): unknown {
  const noComments = text.replace(/(^|\s)\/\/[^\n]*/g, "$1");
  const noTrailingCommas = noComments.replace(/,(\s*[}\]])/g, "$1");
  return JSON.parse(noTrailingCommas);
}

export interface WranglerSettings {
  compatibility_date: string;
  crons: string[];
  assets: { not_found_handling: string; run_worker_first: string[] };
  vars: Record<string, string>;
}

/** Reads the parts of apps/api/wrangler.jsonc that go into the manifest. */
export function wranglerSettings(jsonc: string): WranglerSettings {
  const w = parseJsonc(jsonc) as Record<string, unknown>;
  const assets = (w.assets ?? {}) as Record<string, unknown>;
  const triggers = (w.triggers ?? {}) as { crons?: string[] };
  const vars = (w.vars ?? {}) as Record<string, unknown>;
  return {
    compatibility_date: String(w.compatibility_date ?? ""),
    crons: triggers.crons ?? [],
    assets: {
      not_found_handling: String(assets.not_found_handling ?? "none"),
      run_worker_first: (assets.run_worker_first as string[] | undefined) ?? [],
    },
    vars: Object.fromEntries(
      Object.entries(vars).filter(([, v]) => typeof v === "string" && v !== "") as [
        string,
        string,
      ][],
    ),
  };
}

export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/** Every file under dir, as a relative POSIX path, sorted. Excludes the manifest itself. */
export function listFiles(dir: string, base = dir): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir).sort()) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...listFiles(full, base));
    else {
      const rel = relative(base, full).split(sep).join("/");
      if (rel !== MANIFEST) out.push(rel);
    }
  }
  return out;
}

export interface ManifestInput {
  version: string;
  settings: WranglerSettings;
  /** Migration file names in apply order. */
  migrations: string[];
  /** Relative path to file bytes, every file in the bundle except manifest.json. */
  files: Map<string, Uint8Array>;
}

/** Builds and validates the manifest for a set of bundle files. Pure: no I/O. */
export function buildManifest(input: ManifestInput): BundleManifest {
  const files: Record<string, string> = {};
  for (const path of [...input.files.keys()].sort()) {
    files[path] = sha256Hex(input.files.get(path) as Uint8Array);
  }
  for (const m of input.migrations) {
    if (!files[`migrations/${m}`])
      throw new Error(`migration ${m} is listed in the manifest but not in the bundle`);
  }
  return parseManifest({
    format: 1,
    version: input.version,
    protocol: PROTOCOL_VERSION,
    main: "worker/index.js",
    compatibility_date: input.settings.compatibility_date,
    crons: input.settings.crons,
    assets: input.settings.assets,
    vars: input.settings.vars,
    migrations: [...input.migrations],
    files,
  });
}

/** Writes manifest.json into an assembled bundle directory and returns it. */
export function writeManifest(
  bundleDir: string,
  input: Omit<ManifestInput, "files">,
): BundleManifest {
  const files = new Map<string, Uint8Array>();
  for (const rel of listFiles(bundleDir)) files.set(rel, readFileSync(join(bundleDir, rel)));
  const manifest = buildManifest({ ...input, files });
  writeFileSync(join(bundleDir, MANIFEST), `${JSON.stringify(manifest, null, 2)}\n`);
  return manifest;
}

// ---------------------------------------------------------------- build steps

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function run(cmd: string[], cwd: string): Promise<void> {
  return new Promise((ok, fail) => {
    const p = spawn(cmd[0] as string, cmd.slice(1), { cwd, stdio: "inherit" });
    p.on("error", fail);
    p.on("exit", (code) =>
      code === 0 ? ok() : fail(new Error(`${cmd.join(" ")} exited with code ${code}`)),
    );
  });
}

function copyTree(src: string, dst: string): void {
  mkdirSync(dst, { recursive: true });
  for (const name of readdirSync(src)) {
    const from = join(src, name);
    const to = join(dst, name);
    if (statSync(from).isDirectory()) copyTree(from, to);
    else copyFileSync(from, to);
  }
}

async function main(): Promise<void> {
  const version =
    process.env.CFS_VERSION ??
    (JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { version: string }).version;
  const dist = join(root, "dist");
  const scratch = join(dist, ".worker-build");
  const bundleDir = join(dist, "worker-bundle");
  rmSync(scratch, { recursive: true, force: true });
  rmSync(bundleDir, { recursive: true, force: true });
  mkdirSync(bundleDir, { recursive: true });

  await run(["bun", "run", "build:web"], root);
  const webDist = join(root, "apps/web/dist");
  if (!existsSync(join(webDist, "index.html")))
    throw new Error("apps/web/dist/index.html is missing");

  const api = join(root, "apps/api");
  await run(["bun", "x", "wrangler", "deploy", "--dry-run", "--outdir", scratch], api);
  const entry = join(scratch, "index.js");
  if (!existsSync(entry)) throw new Error("wrangler did not produce index.js");

  copyTree(webDist, join(bundleDir, "assets"));
  mkdirSync(join(bundleDir, "worker"), { recursive: true });
  copyFileSync(entry, join(bundleDir, "worker", "index.js"));
  const migDir = join(api, "migrations");
  const migrations = readdirSync(migDir)
    .filter((f) => f.endsWith(".sql"))
    .sort();
  mkdirSync(join(bundleDir, "migrations"), { recursive: true });
  for (const m of migrations) copyFileSync(join(migDir, m), join(bundleDir, "migrations", m));

  const settings = wranglerSettings(readFileSync(join(api, "wrangler.jsonc"), "utf8"));
  const manifest = writeManifest(bundleDir, { version, settings, migrations });

  const tgz = join(dist, "worker-bundle.tgz");
  rmSync(tgz, { force: true });
  await run(["tar", "-czf", tgz, "-C", bundleDir, "."], root);
  rmSync(scratch, { recursive: true, force: true });
  console.log(
    `Wrote ${relative(root, tgz)}: version ${manifest.version}, protocol ${manifest.protocol}, ${Object.keys(manifest.files).length} files, ${manifest.migrations.length} migrations.`,
  );
}

if (import.meta.main) {
  main().catch((e) => {
    console.error(e instanceof Error ? e.message : String(e));
    process.exit(1);
  });
}
