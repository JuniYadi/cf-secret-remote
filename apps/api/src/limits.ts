import type { MiddlewareHandler } from "hono";

export const MAX_JSON = 64 * 1024;
export const MAX_SECRET = 256 * 1024;
export const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

/** Rejects bodies over the cap (ADR 27). The secret write has a larger cap. */
export const bodyLimit: MiddlewareHandler = async (c, next) => {
  if (c.req.method !== "GET" && c.req.method !== "DELETE") {
    const cap = c.req.path.endsWith("/secret") ? MAX_SECRET : MAX_JSON;
    const len = Number(c.req.header("content-length") ?? 0);
    if (len > cap) return c.json({ error: "too large" }, 413);
    if (!c.req.header("content-length")) {
      const text = await c.req.raw.clone().text();
      if (text.length > cap) return c.json({ error: "too large" }, 413);
    }
  }
  await next();
};
