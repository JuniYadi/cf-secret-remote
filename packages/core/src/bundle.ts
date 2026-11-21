// ADR 25: the Worker bundle manifest. Written by scripts/bundle-worker.ts, read by `cfs deploy`.
// Plain data only: the hashing happens in the tools that own the files.

export interface BundleManifest {
  /** Manifest format version. Bump when a field changes meaning. */
  format: 1;
  /** Release version, e.g. "0.2.0". */
  version: string;
  /** PROTOCOL_VERSION the bundle speaks. `cfs deploy` refuses a major it does not know. */
  protocol: number;
  /** Worker entry file, relative to the bundle root. */
  main: string;
  compatibility_date: string;
  /** Worker compatibility flags from wrangler.jsonc, e.g. "nodejs_als". Missing in older bundles. */
  compatibility_flags: string[];
  crons: string[];
  /** Static asset settings copied from wrangler.jsonc. */
  assets: { not_found_handling: string; run_worker_first: string[] };
  /** Default plain-text vars from wrangler.jsonc. Deploy sets the rest. */
  vars: Record<string, string>;
  /** Migration file names in apply order, e.g. "0001_init.sql". Files live in migrations/. */
  migrations: string[];
  /** SHA-256 (hex) of every file in the bundle except manifest.json, keyed by relative path. */
  files: Record<string, string>;
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);
const isStrings = (v: unknown): v is string[] =>
  Array.isArray(v) && v.every((x) => typeof x === "string");

/** Checks the shape of a parsed manifest.json. Throws with the first problem found. */
export function parseManifest(raw: unknown): BundleManifest {
  if (!isObj(raw)) throw new Error("manifest.json must be a JSON object.");
  if (raw.format !== 1) throw new Error(`Unknown manifest format ${String(raw.format)}.`);
  if (typeof raw.version !== "string" || !raw.version)
    throw new Error("manifest: version missing.");
  if (typeof raw.protocol !== "number") throw new Error("manifest: protocol missing.");
  if (typeof raw.main !== "string" || !raw.main) throw new Error("manifest: main missing.");
  if (typeof raw.compatibility_date !== "string")
    throw new Error("manifest: compatibility_date missing.");
  if (raw.compatibility_flags === undefined) raw.compatibility_flags = [];
  if (!isStrings(raw.compatibility_flags))
    throw new Error("manifest: compatibility_flags must be a list of strings.");
  if (!isStrings(raw.crons)) throw new Error("manifest: crons must be a list of strings.");
  if (
    !isObj(raw.assets) ||
    typeof raw.assets.not_found_handling !== "string" ||
    !isStrings(raw.assets.run_worker_first)
  )
    throw new Error("manifest: assets settings are invalid.");
  if (!isObj(raw.vars) || !Object.values(raw.vars).every((v) => typeof v === "string"))
    throw new Error("manifest: vars must map names to strings.");
  if (!isStrings(raw.migrations)) throw new Error("manifest: migrations must be a list of names.");
  if (!isObj(raw.files) || !Object.values(raw.files).every((v) => typeof v === "string"))
    throw new Error("manifest: files must map paths to SHA-256 hex digests.");
  return raw as unknown as BundleManifest;
}
