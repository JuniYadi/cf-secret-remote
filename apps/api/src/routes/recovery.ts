import { Hono } from "hono";
import type { AppEnv } from "../types.ts";

// ADR 20. Routes for this feature live here; the router is already registered in src/index.ts.
export const recovery = new Hono<AppEnv>();
