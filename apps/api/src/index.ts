import { PROTOCOL_VERSION } from "@cfs/core";
import { Hono } from "hono";
import { withAlertContext } from "./alerts.ts";
import { authenticate } from "./auth.ts";
import { runDaily } from "./cron.ts";
import { bodyLimit } from "./limits.ts";
import { isQuotaError, retryAfterSeconds } from "./quota.ts";
import { admin } from "./routes/admin.ts";
import { agent_rules } from "./routes/agent-rules.ts";
import { alerts } from "./routes/alerts.ts";
import { approle } from "./routes/approle.ts";
import { apps } from "./routes/apps.ts";
import { backup, blockDuringMaintenance } from "./routes/backup.ts";
import { checkpoint } from "./routes/checkpoint.ts";
import { cliApprove, cliPublic } from "./routes/cli.ts";
import { keyrings } from "./routes/keyrings.ts";
import { logins } from "./routes/logins.ts";
import { me } from "./routes/me.ts";
import { membership } from "./routes/membership.ts";
import { offboard } from "./routes/offboard.ts";
import { recovery } from "./routes/recovery.ts";
import { requests } from "./routes/requests.ts";
import { secrets } from "./routes/secrets.ts";
import { sessions } from "./routes/sessions.ts";
import { versions } from "./routes/versions.ts";
import { serveAsset } from "./static.ts";
import type { AppEnv, Env } from "./types.ts";
import { now } from "./util.ts";

const app = new Hono<AppEnv>();
app.use("/api/*", bodyLimit);
app.use("/api/*", blockDuringMaintenance); // ADR 23: writes return 503 while a restore runs

// Read by `cfs` before it talks to the server (ADR 25). Keep in step with the release version.
const SERVER_VERSION = "0.0.0";
app.get("/api/health", (c) =>
  c.json({ ok: true, protocol: PROTOCOL_VERSION, version: SERVER_VERSION }),
);
app.route("/api/v1", approle as unknown as Hono<AppEnv>);
app.route("/api/v1", cliPublic as unknown as Hono<AppEnv>);

// Everything below needs a cfs token or a Cloudflare Access login.
const v1 = new Hono<AppEnv>();
v1.use("*", authenticate);
v1.route("/", me);
v1.route("/", cliApprove);
v1.route("/", keyrings);
v1.route("/", secrets);
v1.route("/", logins);
v1.route("/", admin);
v1.route("/", sessions);
v1.route("/", membership);
v1.route("/", apps);
v1.route("/", requests);
v1.route("/", agent_rules);
v1.route("/", alerts);
v1.route("/", checkpoint);
v1.route("/", recovery);
v1.route("/", offboard);
v1.route("/", versions);
v1.route("/", backup);
app.route("/api/v1", v1);

app.all("/api/*", (c) => c.json({ error: "not found" }, 404));
// ADR 24: every other path is the web app. wrangler.jsonc runs the Worker for all paths so the headers apply.
app.all("*", (c) => serveAsset(c.req.raw, c.env.ASSETS));
app.onError((e, c) => {
  // ADR 19: D1 over the daily quota. Writes wait until 00:00 UTC; reads and audit appends fail open (see audit.ts).
  if (isQuotaError(e)) {
    c.header("Retry-After", String(retryAfterSeconds(now())));
    return c.json({ error: "daily free-tier quota reached, retry after 00:00 UTC" }, 503);
  }
  console.error(e.message); // never log request bodies
  return c.json({ error: "server error" }, 500);
});

export default {
  // ADR 18: the request context lets alert evaluation run under ctx.waitUntil.
  fetch: (req: Request, env: Env, ctx: ExecutionContext) =>
    withAlertContext(env, ctx, () => app.fetch(req, env, ctx)),
  // ADR 19: the 00:05 UTC cron.
  scheduled: (event: ScheduledController, env: Env, ctx: ExecutionContext) =>
    ctx.waitUntil(runDaily(env, Math.floor(event.scheduledTime / 1000))),
};
