import { Hono } from "hono";
import type { AppEnv } from "../types.ts";

// ADR 17. Routes for this feature live here; the router is already registered in src/index.ts.
export const agent_rules = new Hono<AppEnv>();
