#!/usr/bin/env bun
// ADR checker. Informational only: it always exits 0, so a patch from someone else never fails CI.
// It prints a markdown report (and writes it to $GITHUB_STEP_SUMMARY when set) that answers:
//   1. Does the Status column in docs/adr/README.md agree with the `Status:` line in each ADR file?
//   2. Does each ADR marked implemented have code and tests that mention it ("ADR N")?
//   3. For a PR: which ADRs does it declare (`ADR:` in the body) and touch, and was the README updated?
//
// Env (all optional): BASE_REF (e.g. origin/main) to scope to a PR diff, PR_BODY for the `ADR:` line.
import { appendFileSync, existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const root = join(import.meta.dir, "..");
const adrDir = join(root, "docs", "adr");

type Adr = { n: number; file: string; readme: string; own: string };

function loadAdrs(): Adr[] {
  const readme = readFileSync(join(adrDir, "README.md"), "utf8");
  const rows = new Map<number, string>();
  for (const m of readme.matchAll(/^\|\s*\[(\d+)\]\([^)]+\)\s*\|[^|]*\|\s*([^|]+?)\s*\|\s*$/gm)) {
    rows.set(Number(m[1]), m[2] ?? "");
  }
  const out: Adr[] = [];
  for (const file of readdirSync(adrDir).filter((f) => /^\d{4}-.*\.md$/.test(f))) {
    const n = Number(file.slice(0, 4));
    const own = /^Status:\s*(.+)$/m.exec(readFileSync(join(adrDir, file), "utf8"))?.[1] ?? "";
    out.push({ n, file, readme: rows.get(n) ?? "(missing in README)", own: own.trim() });
  }
  return out.sort((a, b) => a.n - b.n);
}

function walk(dir: string, acc: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (["node_modules", "dist", ".git", ".wrangler"].includes(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, acc);
    else if (/\.(ts|tsx)$/.test(name)) acc.push(p);
  }
  return acc;
}

const isTest = (f: string) => /(\.test\.|\/test\/|\/test-vectors\/|e2e\.ts)/.test(f);
const mentions = (text: string) =>
  new Set([...text.matchAll(/\bADR\s?(\d{1,2})\b/g)].map((m) => Number(m[1])));
const isImplemented = (s: string) => /^implemented/i.test(s);
const isPlanned = (s: string) => /planned/i.test(s);

const adrs = loadAdrs();
const files = ["apps", "packages", "scripts"].flatMap((d) =>
  existsSync(join(root, d)) ? walk(join(root, d)) : [],
);
const srcRefs = new Map<number, number>();
const testRefs = new Map<number, number>();
for (const f of files) {
  const rel = relative(root, f);
  for (const n of mentions(readFileSync(f, "utf8"))) {
    const m = isTest(rel) ? testRefs : srcRefs;
    m.set(n, (m.get(n) ?? 0) + 1);
  }
}

const lines: string[] = [
  "## ADR check",
  "",
  "_Informational only. This never fails the build._",
  "",
];
const notes: string[] = [];

// 1 + 2: per-ADR table.
lines.push(
  "| ADR | README status | ADR file status | Source refs | Test refs | Note |",
  "|---|---|---|---|---|---|",
);
for (const a of adrs) {
  const src = srcRefs.get(a.n) ?? 0;
  const tst = testRefs.get(a.n) ?? 0;
  const note: string[] = [];
  if (isImplemented(a.readme) && /not implemented/i.test(a.own))
    note.push("ADR file still says not implemented");
  if (isPlanned(a.readme) && src + tst > 0) note.push("README says planned but code mentions it");
  if (isImplemented(a.readme) && src > 0 && tst === 0) note.push("no test mentions this ADR");
  if (isImplemented(a.readme) && src + tst === 0) note.push("no code or test mentions this ADR");
  if (a.readme.startsWith("(missing")) note.push("not in README table");
  if (note.length) notes.push(`ADR ${a.n}: ${note.join("; ")}`);
  lines.push(`| ${a.n} | ${a.readme} | ${a.own} | ${src} | ${tst} | ${note.join("; ")} |`);
}

// 3: PR scope.
const base = process.env.BASE_REF;
if (base) {
  const diff = Bun.spawnSync(["git", "diff", "--name-only", `${base}...HEAD`], { cwd: root });
  const changed = diff.stdout.toString().split("\n").filter(Boolean);
  const codeChanged = changed.filter((f) => /^(apps|packages)\//.test(f));
  const touched = new Set<number>();
  for (const f of changed.filter((c) => /\.(ts|tsx)$/.test(c) && existsSync(join(root, c)))) {
    for (const n of mentions(readFileSync(join(root, f), "utf8"))) touched.add(n);
  }
  for (const f of changed) {
    const m = /^docs\/adr\/(\d{4})-/.exec(f);
    if (m) touched.add(Number(m[1]));
  }
  const declaredLine = /^ADR:[ \t]*(.*)$/m.exec(process.env.PR_BODY ?? "")?.[1] ?? "";
  const declared = new Set([...declaredLine.matchAll(/\d+/g)].map((m) => Number(m[0])));
  const readmeChanged = changed.includes("docs/adr/README.md");

  lines.push("", "### This PR");
  lines.push(
    `- Declared in PR body (\`ADR:\`): ${declared.size ? [...declared].join(", ") : "none"}`,
  );
  lines.push(
    `- ADRs mentioned in changed files: ${touched.size ? [...touched].sort((a, b) => a - b).join(", ") : "none"}`,
  );
  lines.push(`- \`docs/adr/README.md\` updated: ${readmeChanged ? "yes" : "no"}`);
  if (codeChanged.length && declared.size === 0)
    notes.push("PR changes code but the body has no `ADR:` number");
  for (const n of declared)
    if (!touched.has(n)) notes.push(`PR declares ADR ${n} but no changed file mentions it`);
  if (declared.size && !readmeChanged)
    notes.push("PR declares an ADR but did not touch the README status column");
}

if (notes.length) lines.push("", "### Notes", ...notes.map((n) => `- ${n}`));
else lines.push("", "No notes.");

const report = lines.join("\n");
console.log(report);
for (const n of notes) console.log(`::notice title=ADR check::${n}`);
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${report}\n`);
process.exit(0);
