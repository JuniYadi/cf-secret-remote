export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  BOOTSTRAP_ADMIN_EMAIL: string;
  ACCESS_TEAM_DOMAIN: string; // e.g. "myteam.cloudflareaccess.com"
  ACCESS_AUD: string;
  AUDIT_RETENTION_DAYS?: string; // ADR 19: default 365, never below 90
  CHECKPOINT_WEBHOOK_URL?: string; // ADR 19: optional Slack-compatible webhook for the daily checkpoint
  SEND_EMAIL?: EmailBinding; // ADR 18: optional send_email binding. Email alerts are off without it.
  ALERT_EMAIL_FROM?: string; // ADR 18: sender address on a domain verified for the binding
  BACKUP?: R2Bucket; // ADR 23: optional R2 bucket for daily backups (last 30 kept). Absent = no scheduled copy.
}

/** The subset of the Workers send_email binding that alerts use. */
export interface EmailBinding {
  send(message: { to: string; from: string; subject: string; text: string }): Promise<void>;
}

export interface Who {
  id: string;
  kind: "user" | "app";
  name: string;
  role: "admin" | "member";
}

export type AppEnv = { Bindings: Env; Variables: { who: Who } };
