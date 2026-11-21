export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  BOOTSTRAP_ADMIN_EMAIL: string;
  ACCESS_TEAM_DOMAIN: string; // e.g. "myteam.cloudflareaccess.com"
  ACCESS_AUD: string;
  AUDIT_RETENTION_DAYS?: string; // ADR 19: default 365, never below 90
  CHECKPOINT_WEBHOOK_URL?: string; // ADR 19: optional Slack-compatible webhook for the daily checkpoint
}

export interface Who {
  id: string;
  kind: "user" | "app";
  name: string;
  role: "admin" | "member";
}

export type AppEnv = { Bindings: Env; Variables: { who: Who } };
