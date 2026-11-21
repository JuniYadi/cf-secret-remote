import type { D1Migration } from "@cloudflare/vitest-pool-workers";
import type { Env } from "../src/types.ts";

declare global {
  namespace Cloudflare {
    interface Env {
      DB: D1Database;
      ASSETS: Fetcher;
      BOOTSTRAP_ADMIN_EMAIL: string;
      ACCESS_TEAM_DOMAIN: string;
      ACCESS_AUD: string;
      TEST_MIGRATIONS: D1Migration[];
    }
  }
}

export type { Env };
