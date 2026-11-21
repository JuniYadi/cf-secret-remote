// Bundles @cfs/core and the vector checks for a browser page (ADR 26). Output is git-ignored.
import { mkdirSync } from "node:fs";
import { join } from "node:path";

const here = import.meta.dir;
const out = join(here, ".out");
mkdirSync(out, { recursive: true });

const result = await Bun.build({
  entrypoints: [join(here, "entry.ts")],
  target: "browser",
  format: "iife",
  minify: false,
});
if (!result.success) {
  for (const log of result.logs) console.error(log);
  process.exit(1);
}
await Bun.write(join(out, "vectors.js"), await result.outputs[0]!.text());
console.log(`built ${join(out, "vectors.js")}`);
