#!/usr/bin/env bun
// apps/api/wrangler.jsonc is local (gitignored) so real ids and vars stay out of the repo.
// The committed template is wrangler.example.jsonc. This copies it when the local file is missing,
// so a fresh clone and CI work after `bun install`. It never overwrites an existing file.
import { copyFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const dir = join(import.meta.dir, "..", "apps", "api");
const local = join(dir, "wrangler.jsonc");
if (!existsSync(local)) {
  copyFileSync(join(dir, "wrangler.example.jsonc"), local);
  console.log("created apps/api/wrangler.jsonc from wrangler.example.jsonc");
}
