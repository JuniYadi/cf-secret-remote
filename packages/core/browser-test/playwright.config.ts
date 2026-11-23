import { defineConfig } from "@playwright/test";

// ADR 26: real Chromium runs the shared vectors. `bun run test:browser` builds the bundle first.
export default defineConfig({
  testDir: ".",
  testMatch: ["vectors.pw.ts", "web-logins.pw.ts", "fill.pw.ts"],
  timeout: 120_000,
  outputDir: "./.out/test-results",
  reporter: "list",
  use: { headless: true },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});
