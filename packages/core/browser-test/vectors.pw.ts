// ADR 26: the shared test vectors, run in a real Chromium page. Same JSON files and same checks as
// src/vectors.test.ts (Bun). Run with `bun run test:browser` (builds the bundle first).
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";
import type { CheckResult, Vectors } from "./checks.ts";

const here = fileURLToPath(new URL(".", import.meta.url));
const vec = (name: string) =>
  JSON.parse(
    readFileSync(fileURLToPath(new URL(`../test-vectors/${name}`, import.meta.url)), "utf8"),
  );

const vectors: Vectors = {
  envelope: vec("envelope.json"),
  wrappedKey: vec("wrapped-key.json"),
  kit: vec("kit.json"),
  fingerprint: vec("fingerprint.json"),
  recovery: vec("recovery.json"),
  auditChain: vec("audit-chain.json"),
  secret: vec("secret.json"),
  backupSeal: vec("backup-seal.json"),
  login: vec("login.json"),
};

const bundle = readFileSync(`${here}.out/vectors.js`, "utf8");

// A page served from localhost is a secure context, so crypto.subtle is available.
const PAGE =
  '<!doctype html><html><head><meta charset="utf-8"><title>cfs vectors</title></head><body></body></html>';

test("shared vectors give the same answers in Chromium", async ({ page }) => {
  await page.route("http://localhost/vectors.html", (route) =>
    route.fulfill({ contentType: "text/html", body: PAGE }),
  );
  await page.goto("http://localhost/vectors.html");
  await page.addScriptTag({ content: bundle });

  const results = await page.evaluate(
    (v) =>
      (
        globalThis as unknown as { runVectorChecks: (x: unknown) => Promise<unknown> }
      ).runVectorChecks(v),
    vectors,
  );
  const checks = results as CheckResult[];

  expect(checks.filter((c) => !c.ok)).toEqual([]);
  expect(new Set(checks.map((c) => c.group))).toEqual(
    new Set([
      "envelope",
      "wrapped-key",
      "kit",
      "fingerprint",
      "recovery-words",
      "audit-chain",
      "secret-hierarchy",
      "backup-seal",
      "login",
    ]),
  );
  expect(checks.length).toBeGreaterThanOrEqual(20);
});
