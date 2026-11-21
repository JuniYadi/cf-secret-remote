import preact from "@preact/preset-vite";
import { defineConfig } from "vitest/config";

// ADR 24: the build goes to dist/, which the Worker serves as static assets (apps/api/wrangler.jsonc).
// The output must pass the Worker's CSP (script-src 'self', style-src 'self'): no inline scripts or styles.
export default defineConfig({
  plugins: [preact()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // The modulepreload polyfill is an inline script in some Vite versions. Modern browsers do not need it.
    modulePreload: { polyfill: false },
    sourcemap: false,
  },
  server: {
    // `bun run dev:api` runs wrangler on 8787. The SPA dev server forwards /api to it, so requests stay same-origin.
    proxy: { "/api": "http://localhost:8787" },
  },
  test: {
    include: ["src/**/*.test.{ts,tsx}"],
    environment: "node",
  },
});
