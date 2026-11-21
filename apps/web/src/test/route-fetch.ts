// A fake fetch for screen tests. Routes are keyed "METHOD /path" (the path without /api/v1 and without a query).
// Each call is recorded, so a test can check which requests a screen sent and what they carried.

import { vi } from "vitest";

export interface Hit {
  method: string;
  path: string;
  search: URLSearchParams;
  body: unknown;
}

export interface Reply {
  status?: number;
  body?: unknown;
}

export type Route = Reply | ((hit: Hit) => Reply);
export type Routes = Record<string, Route>;

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export function routeFetch(routes: Routes) {
  const calls: Hit[] = [];
  const fn = vi.fn(async (input: string, init: RequestInit) => {
    const url = new URL(input, "http://cfs.test");
    const method = init.method ?? "GET";
    const path = url.pathname.replace(/^\/api\/v1/, "");
    const hit: Hit = {
      method,
      path,
      search: url.searchParams,
      body: init.body === undefined ? undefined : JSON.parse(String(init.body)),
    };
    calls.push(hit);
    const route = routes[`${method} ${path}`];
    if (route === undefined) return json(404, { error: "not found" });
    const reply = typeof route === "function" ? route(hit) : route;
    return json(reply.status ?? 200, reply.body ?? { ok: true });
  });
  return {
    fn,
    calls,
    /** Calls to one route, in order. */
    to: (key: string) => calls.filter((c) => `${c.method} ${c.path}` === key),
  };
}
