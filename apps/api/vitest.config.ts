import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig(async () => {
  const migrations = await readD1Migrations("./migrations");
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: "./wrangler.example.jsonc" },
        miniflare: {
          bindings: {
            TEST_MIGRATIONS: migrations,
            BOOTSTRAP_ADMIN_EMAIL: "admin@test.dev",
            // ADR 20 tests sign Access JWTs for these values (see test/access-jwt.ts).
            ACCESS_TEAM_DOMAIN: "team.test",
            ACCESS_AUD: "aud-test",
          },
        },
      }),
    ],
    test: { include: ["test/**/*.test.ts", "src/**/*.test.ts"], setupFiles: ["./test/setup.ts"] },
  };
});
