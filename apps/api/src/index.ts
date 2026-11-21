import { PROTOCOL_VERSION } from "@cfs/core";
import { Hono } from "hono";
import { authenticate } from "./auth.ts";
import { bodyLimit } from "./limits.ts";
import { admin } from "./routes/admin.ts";
import { agent_rules } from "./routes/agent-rules.ts";
import { alerts } from "./routes/alerts.ts";
import { approle } from "./routes/approle.ts";
import { apps } from "./routes/apps.ts";
import { backup } from "./routes/backup.ts";
import { checkpoint } from "./routes/checkpoint.ts";
import { cliApprove, cliPublic } from "./routes/cli.ts";
import { keyrings } from "./routes/keyrings.ts";
import { me } from "./routes/me.ts";
import { membership } from "./routes/membership.ts";
import { offboard } from "./routes/offboard.ts";
import { recovery } from "./routes/recovery.ts";
import { requests } from "./routes/requests.ts";
import { secrets } from "./routes/secrets.ts";
import { sessions } from "./routes/sessions.ts";
import { versions } from "./routes/versions.ts";
import type { AppEnv } from "./types.ts";

const app = new Hono<AppEnv>();
app.use("/api/*", bodyLimit);

app.get("/api/health", (c) => c.json({ ok: true, protocol: PROTOCOL_VERSION }));
app.route("/api/v1", approle as unknown as Hono<AppEnv>);
app.route("/api/v1", cliPublic as unknown as Hono<AppEnv>);

// Everything below needs a cfs token or a Cloudflare Access login.
const v1 = new Hono<AppEnv>();
v1.use("*", authenticate);
v1.route("/", me);
v1.route("/", cliApprove);
v1.route("/", keyrings);
v1.route("/", secrets);
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
app.onError((e, c) => {
  console.error(e.message); // never log request bodies
  return c.json({ error: "server error" }, 500);
});

export default app;
