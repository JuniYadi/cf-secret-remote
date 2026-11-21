import { Hono } from "hono";
import { requireAdmin } from "../auth.ts";
import { dayOf, FREE_WRITES_PER_DAY, WARN_AT_WRITES } from "../quota.ts";
import type { AppEnv } from "../types.ts";
import { now } from "../util.ts";

// ADR 19. Routes for this feature live here; the router is already registered in src/index.ts.
export const checkpoint = new Hono<AppEnv>();
checkpoint.use("/usage", requireAdmin);

// Today's D1 write estimate against the free-tier limit. The UI warns at 80%.
checkpoint.get("/usage", async (c) => {
  const day = dayOf(now());
  const row = await c.env.DB.prepare(
    "SELECT writes, reads_logged AS readsLogged FROM usage_day WHERE day = ?",
  )
    .bind(day)
    .first<{ writes: number; readsLogged: number }>();
  const writes = row?.writes ?? 0;
  return c.json({
    day,
    writes,
    readsLogged: row?.readsLogged ?? 0,
    limit: FREE_WRITES_PER_DAY,
    warning: writes >= WARN_AT_WRITES,
  });
});
