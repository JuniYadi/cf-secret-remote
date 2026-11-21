export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  BOOTSTRAP_ADMIN_EMAIL: string;
  ACCESS_TEAM_DOMAIN: string; // e.g. "myteam.cloudflareaccess.com"
  ACCESS_AUD: string;
}

export interface Who {
  id: string;
  kind: "user" | "app";
  name: string;
  role: "admin" | "member";
}

export type AppEnv = { Bindings: Env; Variables: { who: Who } };
