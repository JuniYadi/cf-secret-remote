import { PROTOCOL_VERSION } from "@cfs/core";
import { Hono } from "hono";

export type Bindings = {
  DB: D1Database;
  ASSETS: Fetcher;
  BOOTSTRAP_ADMIN_EMAIL: string;
  ACCESS_TEAM_DOMAIN: string;
  ACCESS_AUD: string;
};

const app = new Hono<{ Bindings: Bindings }>();

app.get("/api/health", (c) => c.json({ ok: true, protocol: PROTOCOL_VERSION }));

// Anything else under /api is unknown. The SPA handles every other path.
app.all("/api/*", (c) => c.json({ error: "not found" }, 404));

export default app;
