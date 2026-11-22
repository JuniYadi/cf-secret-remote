import type { MiddlewareHandler } from "hono";

export const MAX_JSON = 64 * 1024;
export const MAX_SECRET = 256 * 1024;
// ADR 23: a restore carries a whole backup file (base64 in JSON). Only the two restore routes get this cap.
export const MAX_RESTORE = 64 * 1024 * 1024;
export const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

/** Rejects bodies over the cap (ADR 27). The secret write and restore have larger caps. */
export const bodyLimit: MiddlewareHandler = async (c, next) => {
  if (c.req.method !== "GET" && c.req.method !== "DELETE") {
    const cap = c.req.path.includes("/logins")
      ? MAX_SECRET
      : c.req.path.endsWith("/secret")
        ? MAX_SECRET
        : /\/restore(\/check)?$/.test(c.req.path)
          ? MAX_RESTORE
          : MAX_JSON;
    const len = Number(c.req.header("content-length") ?? 0);
    if (len > cap) return c.json({ error: "too large" }, 413);
    if (!c.req.header("content-length")) {
      const text = await c.req.raw.clone().text();
      if (text.length > cap) return c.json({ error: "too large" }, 413);
    }
  }
  await next();
};
