import { createExecutionContext, env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../src/index.ts";
import type { Env } from "../src/types.ts";

// ADR 24: the Worker serves the web app through the ASSETS binding and adds the security headers.
// The test replaces ASSETS with a stub, so it does not depend on apps/web/dist being built.

const CSP =
  "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'";

function stubAssets(body = "<!doctype html><title>cfs</title>", status = 200) {
  const seen: string[] = [];
  const assets = {
    fetch: async (req: Request) => {
      seen.push(new URL(req.url).pathname);
      return new Response(body, {
        status,
        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-cache" },
      });
    },
  } as unknown as Fetcher;
  return { assets, seen };
}

const call = (path: string, assets: Fetcher, init?: RequestInit) =>
  worker.fetch(
    new Request(`https://cfs.test${path}`, init),
    { ...env, ASSETS: assets } as Env,
    createExecutionContext(),
  );

describe("ADR 24 web security headers", () => {
  it("sets the strict CSP and the other headers on the app shell", async () => {
    const { assets, seen } = stubAssets();
    const res = await call("/secrets/myapp%2Fdev", assets);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Security-Policy")).toBe(CSP);
    expect(res.headers.get("Referrer-Policy")).toBe("no-referrer");
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    expect(await res.text()).toContain("<title>cfs</title>");
    expect(seen).toEqual(["/secrets/myapp%2Fdev"]);
  });

  it("passes /denied/<name with slashes> to the assets binding unchanged, without a redirect (#42)", async () => {
    const { assets, seen } = stubAssets();
    const res = await call("/denied/myapp/prod/db", assets);
    expect(res.status).toBe(200);
    expect(res.headers.get("Location")).toBeNull();
    expect(seen).toEqual(["/denied/myapp/prod/db"]);
  });

  it("sets the headers on static files and on the SPA fallback alike", async () => {
    const { assets } = stubAssets("body{}", 200);
    const res = await call("/assets/index-abc.css", assets);
    expect(res.headers.get("Content-Security-Policy")).toBe(CSP);
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
  });

  it("keeps the status of a missing asset and still sets the headers", async () => {
    const { assets } = stubAssets("not found", 404);
    const res = await call("/nope.js", assets);
    expect(res.status).toBe(404);
    expect(res.headers.get("Content-Security-Policy")).toBe(CSP);
  });

  it("does not send API responses to the assets binding", async () => {
    const throwing = {
      fetch: async () => {
        throw new Error("assets must not serve /api");
      },
    } as unknown as Fetcher;
    const res = await call("/api/nope", throwing);
    expect(res.status).toBe(404);
    expect(res.headers.get("Content-Security-Policy")).toBeNull();
  });
});
