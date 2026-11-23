import { defineConfig } from "@playwright/test";

const port = process.env.CFS_BROWSER_PORT;
export default defineConfig({
  testDir: ".",
  testMatch: "smoke.pw.ts",
  timeout: 60_000,
  reporter: "list",
  outputDir: "./.out/test-results",
  use: { baseURL: `http://127.0.0.1:${port}`, browserName: "chromium" },
  webServer: {
    cwd: "..",
    command: `bunx vite --config e2e/vite.config.ts --host 127.0.0.1 --port ${port} --strictPort`,
    url: `http://127.0.0.1:${port}`,
    timeout: 60_000,
  },
});
