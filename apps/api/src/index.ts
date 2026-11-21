import { PROTOCOL_VERSION } from "@cfs/core";
import { Hono } from "hono";
import { authenticate } from "./auth.ts";
import { admin } from "./routes/admin.ts";
import { approle } from "./routes/approle.ts";
import { cliApprove, cliPublic } from "./routes/cli.ts";
import { keyrings } from "./routes/keyrings.ts";
import { me } from "./routes/me.ts";
import { secrets } from "./routes/secrets.ts";
import type { AppEnv } from "./types.ts";

const app = new Hono<AppEnv>();

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
app.route("/api/v1", v1);

app.all("/api/*", (c) => c.json({ error: "not found" }, 404));
app.onError((e, c) => {
  console.error(e.message); // never log request bodies
  return c.json({ error: "server error" }, 500);
});

export default app;
