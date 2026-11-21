import { describe, expect, test } from "bun:test";
import { request as httpRequest } from "node:http";
import { CliError } from "./client.ts";
import {
  type AgentRule,
  cachedSecrets,
  clientSecretLoader,
  fetchUpstreamReal,
  handleProxyRequest,
  type ProxyDeps,
  ProxyError,
  type ProxyLogLine,
  type ProxyRequest,
  parseInjectSpec,
  parseListen,
  redactBytes,
  redactionForms,
  startProxy,
  type UpstreamInit,
} from "./proxy.ts";

// ADR 17: the proxy's rules, tested without a network. The upstream and the secret loader are injected.

const VALUE = "sk-live-TESTVALUE-123";
const RULE: AgentRule = {
  alias: "github",
  secretPath: "ops/dev",
  name: "API_KEY",
  upstream: "https://api.example.com/v1",
  inject: "header:Authorization:Bearer {value}",
  maxReadsPerHour: 60,
  requireReason: false,
  requireApproval: false,
};
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

interface Harness {
  deps: ProxyDeps;
  upstreamCalls: { url: string; init: UpstreamInit }[];
  logs: ProxyLogLine[];
  secretCalls: { alias: string; reason: string | undefined }[];
}

/** Test deps. `upstream` answers the forwarded request; the default is a plain 200. */
function harness(
  over: {
    rules?: AgentRule[];
    upstream?: (url: string, init: UpstreamInit) => Promise<Response>;
    sessionReason?: string;
    getSecret?: ProxyDeps["getSecret"];
  } = {},
): Harness {
  const h: Harness = {
    deps: {} as ProxyDeps,
    upstreamCalls: [],
    logs: [],
    secretCalls: [],
  };
  h.deps = {
    rules: over.rules ?? [RULE],
    sessionReason: over.sessionReason,
    getSecret:
      over.getSecret ??
      (async (rule, reason) => {
        h.secretCalls.push({ alias: rule.alias, reason });
        return VALUE;
      }),
    fetchUpstream: async (url, init) => {
      h.upstreamCalls.push({ url, init });
      return over.upstream ? over.upstream(url, init) : new Response("ok");
    },
    log: (line) => h.logs.push(line),
  };
  return h;
}

const send = (
  deps: ProxyDeps,
  target: string,
  init: { method?: string; headers?: Record<string, string>; body?: string } = {},
) => {
  const req: ProxyRequest = {
    method: init.method ?? "GET",
    target,
    headers: new Headers(init.headers),
    body: init.body === undefined ? undefined : new TextEncoder().encode(init.body),
  };
  return handleProxyRequest(req, deps);
};

describe("ADR 17: --listen binds to loopback only", () => {
  test("accepts 127.0.0.1 and ::1 with a port", () => {
    expect(parseListen("127.0.0.1:8787")).toEqual({ host: "127.0.0.1", port: 8787 });
    expect(parseListen("[::1]:8787")).toEqual({ host: "::1", port: 8787 });
  });

  test("refuses every other address, including hostnames that may resolve elsewhere", () => {
    for (const bad of [
      "0.0.0.0:8787",
      "192.168.1.5:8787",
      "[::]:8787",
      "localhost:8787",
      "example.com:80",
      "127.0.0.2:8787",
      "127.0.0.1:70000",
    ]) {
      expect(() => parseListen(bad), bad).toThrow(CliError);
    }
  });

  test("the listener really binds to 127.0.0.1 and startProxy refuses a public address", async () => {
    const h = harness();
    const p = await startProxy({ host: "127.0.0.1", port: 0 }, h.deps);
    try {
      const addr = p.server.address();
      expect(typeof addr === "object" && addr?.address).toBe("127.0.0.1");
    } finally {
      await p.close();
    }
    await expect(startProxy({ host: "0.0.0.0", port: 0 }, h.deps)).rejects.toThrow(CliError);
  });
});

describe("ADR 17: routing and injection", () => {
  test("routes /<alias>/<path> to <upstream>/<path>, keeping the query", async () => {
    const h = harness();
    const r = await send(h.deps, "/github/repos/a/b?page=2");
    expect(r.status).toBe(200);
    expect(h.upstreamCalls[0]?.url).toBe("https://api.example.com/v1/repos/a/b?page=2");
  });

  test("injects the value as a header from the rule's template", async () => {
    const h = harness();
    await send(h.deps, "/github/user");
    expect(h.upstreamCalls[0]?.init.headers.get("authorization")).toBe(`Bearer ${VALUE}`);
  });

  test("injects the value as a query parameter and replaces a caller-supplied one", async () => {
    const h = harness({ rules: [{ ...RULE, alias: "maps", inject: "query:key" }] });
    await send(h.deps, "/maps/geocode?key=evil&q=jakarta");
    const url = new URL(h.upstreamCalls[0]?.url ?? "");
    expect(url.searchParams.getAll("key")).toEqual([VALUE]);
    expect(url.searchParams.get("q")).toBe("jakarta");
  });

  test("strips a caller-supplied header of the same name before injecting", async () => {
    const h = harness();
    await send(h.deps, "/github/user", {
      headers: { Authorization: "Bearer attacker-token", "x-keep": "1" },
    });
    const sent = h.upstreamCalls[0]?.init.headers;
    expect(sent?.get("authorization")).toBe(`Bearer ${VALUE}`);
    expect(sent?.get("x-keep")).toBe("1");
  });

  test("forwards with identity encoding and never forwards the reason header", async () => {
    const h = harness();
    await send(h.deps, "/github/x", {
      headers: { "accept-encoding": "gzip", "x-cfs-reason": "why" },
    });
    expect(h.upstreamCalls[0]?.init.headers.get("accept-encoding")).toBe("identity");
    expect(h.upstreamCalls[0]?.init.headers.get("x-cfs-reason")).toBeNull();
  });

  test("an unknown alias is refused with 403 and nothing is fetched", async () => {
    const h = harness();
    const r = await send(h.deps, "/stripe/charges");
    expect(r.status).toBe(403);
    expect(h.upstreamCalls.length).toBe(0);
    expect(h.secretCalls.length).toBe(0);
  });

  test("a value with CR or LF is never put in a header", async () => {
    const h = harness({
      rules: [{ ...RULE, inject: "header:X-Token:{value}" }],
      getSecret: async () => "abc\r\nX-Evil: 1",
    });
    const r = await send(h.deps, "/github/x");
    expect(r.status).toBe(500);
    expect(h.upstreamCalls.length).toBe(0);
  });
});

describe("ADR 17: the reason", () => {
  const needs = { ...RULE, requireReason: true };

  test("a rule that needs a reason refuses a request without one and fetches nothing", async () => {
    const h = harness({ rules: [needs] });
    const r = await send(h.deps, "/github/x");
    expect(r.status).toBe(403);
    expect(h.secretCalls.length).toBe(0);
    expect(h.upstreamCalls.length).toBe(0);
  });

  test("the X-Cfs-Reason header is sent to the server with the fetch", async () => {
    const h = harness({ rules: [needs] });
    const r = await send(h.deps, "/github/x", { headers: { "x-cfs-reason": "ticket 9" } });
    expect(r.status).toBe(200);
    expect(h.secretCalls[0]?.reason).toBe("ticket 9");
  });

  test("the --reason given at start is used when a request has no header", async () => {
    const h = harness({ rules: [needs], sessionReason: "deploy check" });
    const r = await send(h.deps, "/github/x");
    expect(r.status).toBe(200);
    expect(h.secretCalls[0]?.reason).toBe("deploy check");
  });
});

describe("ADR 17: redaction in bodies and headers", () => {
  test("the value is replaced in the body and in every header", async () => {
    const h = harness({
      upstream: async () =>
        new Response(`token is ${VALUE}, again ${VALUE}`, {
          headers: {
            "x-echo": `Bearer ${VALUE}`,
            location: `https://api.example.com/v1/done?t=${VALUE}`,
          },
        }),
    });
    const r = await send(h.deps, "/github/x");
    const body = dec(r.body);
    expect(body).toBe("token is [redacted], again [redacted]");
    expect(body).not.toContain(VALUE);
    const headers = Object.fromEntries(r.headers);
    expect(headers["x-echo"]).toBe("Bearer [redacted]");
    expect(JSON.stringify(r.headers)).not.toContain(VALUE);
  });

  test("the value is redacted when it appears in a header and in the body together", async () => {
    const h = harness({
      upstream: async () => new Response(`body:${VALUE}`, { headers: { "x-part": VALUE } }),
    });
    const r = await send(h.deps, "/github/x");
    expect(dec(r.body)).toBe("body:[redacted]");
    expect(JSON.stringify(r.headers)).not.toContain(VALUE);
  });

  test("the URL-encoded and base64 forms of the value are redacted too", async () => {
    const enc = encodeURIComponent(VALUE);
    const b64 = Buffer.from(VALUE, "utf8").toString("base64");
    const h = harness({ upstream: async () => new Response(`a=${enc} b=${b64}`) });
    const r = await send(h.deps, "/github/x");
    expect(dec(r.body)).toBe("a=[redacted] b=[redacted]");
  });

  test("an encoded upstream body is refused, since it cannot be checked for the value", async () => {
    const h = harness({
      upstream: async () => new Response("gzip-bytes", { headers: { "content-encoding": "gzip" } }),
    });
    const r = await send(h.deps, "/github/x");
    expect(r.status).toBe(502);
  });

  test("redactBytes works on binary bodies and skips an empty value", () => {
    const bytes = new Uint8Array([0, 255, ...new TextEncoder().encode(VALUE), 1]);
    const out = redactBytes(bytes, VALUE);
    expect(out[0]).toBe(0);
    expect(out[1]).toBe(255);
    expect(new TextDecoder().decode(out.subarray(2))).toBe("[redacted]\u0001");
    expect(redactionForms("")).toEqual([]);
  });
});

describe("ADR 17: redirects and upstream errors", () => {
  test("a redirect to another host is returned as is and not followed", async () => {
    const h = harness({
      upstream: async () =>
        new Response(null, { status: 302, headers: { location: "https://evil.example/steal" } }),
    });
    const r = await send(h.deps, "/github/x");
    expect(r.status).toBe(302);
    expect(Object.fromEntries(r.headers).location).toBe("https://evil.example/steal");
    expect(h.upstreamCalls.length).toBe(1);
    expect(h.upstreamCalls[0]?.init.redirect).toBe("manual");
  });

  test("the real upstream call does not follow redirects", async () => {
    let hits = 0;
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(req) {
        hits++;
        if (new URL(req.url).pathname === "/start")
          return new Response(null, {
            status: 302,
            headers: { location: "http://127.0.0.1:1/elsewhere" },
          });
        return new Response("followed");
      },
    });
    try {
      const r = await fetchUpstreamReal(`http://127.0.0.1:${server.port}/start`, {
        method: "GET",
        headers: new Headers(),
        redirect: "manual",
      });
      expect(r.status).toBe(302);
      expect(hits).toBe(1);
    } finally {
      server.stop(true);
    }
  });

  test("an unreachable upstream gives 502, and the error text (which may hold the URL) is dropped", async () => {
    const h = harness({
      rules: [{ ...RULE, inject: "query:key" }],
      upstream: async (url) => {
        throw new Error(`connect failed for ${url}`);
      },
    });
    const r = await send(h.deps, "/github/x");
    expect(r.status).toBe(502);
    expect(dec(r.body)).not.toContain(VALUE);
    expect(dec(r.body)).not.toContain("connect failed");
  });
});

describe("ADR 17: request path checks", () => {
  test("CR and LF in the path are refused, encoded or not", async () => {
    const h = harness();
    expect((await send(h.deps, "/github/a%0d%0aX-Evil:%201")).status).toBe(400);
    expect((await send(h.deps, "/github/a%0AX-Evil")).status).toBe(400);
    expect((await send(h.deps, "/github/a\r\nX-Evil: 1")).status).toBe(400);
    expect(h.upstreamCalls.length).toBe(0);
  });

  test("path traversal is refused, both plain and encoded", async () => {
    const h = harness();
    for (const target of [
      "/github/../secret",
      "/github/a/../../secret",
      "/github/%2e%2e/secret",
      "/github/x%2F..%2F..%2Fsecret",
      "/github/%252e%252e/x",
      "/github/a%5c..%5cb",
    ]) {
      expect((await send(h.deps, target)).status, target).toBe(400);
    }
    expect(h.upstreamCalls.length).toBe(0);
  });

  test("a target that is not an origin-form path is refused", async () => {
    const h = harness();
    expect((await send(h.deps, "github/x")).status).toBe(400);
  });

  test("the request body is sent upstream for a POST, and not for a GET", async () => {
    const h = harness();
    await send(h.deps, "/github/x", { method: "POST", body: '{"a":1}' });
    expect(dec(h.upstreamCalls[0]?.init.body ?? new Uint8Array())).toBe('{"a":1}');
    await send(h.deps, "/github/x", { method: "GET" });
    expect(h.upstreamCalls[1]?.init.body).toBeUndefined();
  });

  test("a method outside the set is refused", async () => {
    const h = harness();
    expect((await send(h.deps, "/github/x", { method: "CONNECT" })).status).toBe(405);
  });

  test("a browser request (Origin header) and a foreign Host header are refused", async () => {
    const h = harness();
    expect(
      (await send(h.deps, "/github/x", { headers: { origin: "https://evil.example" } })).status,
    ).toBe(403);
    h.deps.hosts = ["127.0.0.1:8787"];
    expect(
      (await send(h.deps, "/github/x", { headers: { host: "evil.example:8787" } })).status,
    ).toBe(403);
    expect((await send(h.deps, "/github/x", { headers: { host: "127.0.0.1:8787" } })).status).toBe(
      200,
    );
  });
});

describe("ADR 17: logs hold alias, method, status and byte counts only", () => {
  test("a log line never holds the value, the path, or a header", async () => {
    const h = harness({
      upstream: async () => new Response(`echo ${VALUE}`, { headers: { "x-echo": VALUE } }),
    });
    await send(h.deps, "/github/secretpathmarker/resource", {
      method: "POST",
      headers: { authorization: "Bearer caller-token" },
      body: "payload",
    });
    expect(h.logs.length).toBe(1);
    const line = h.logs[0] as ProxyLogLine;
    expect(Object.keys(line).sort()).toEqual(["alias", "bytesIn", "bytesOut", "method", "status"]);
    expect(line).toEqual({
      alias: "github",
      method: "POST",
      status: 200,
      bytesIn: 7,
      bytesOut: `echo [redacted]`.length,
    });
    const text = JSON.stringify(h.logs);
    expect(text).not.toContain(VALUE);
    expect(text).not.toContain("secretpathmarker");
    expect(text).not.toContain("caller-token");
  });

  test("a refused request is logged with alias '-' when the alias is unknown", async () => {
    const h = harness();
    await send(h.deps, "/nope/x");
    expect(h.logs[0]?.alias).toBe("-");
    expect(h.logs[0]?.status).toBe(403);
  });
});

describe("ADR 17: the value cache and the secret loader", () => {
  test("a value is cached for 5 minutes and fetched again after that", async () => {
    let t = 0;
    let loads = 0;
    const get = cachedSecrets(
      async () => {
        loads++;
        return VALUE;
      },
      5 * 60 * 1000,
      () => t,
    );
    expect(await get(RULE, undefined)).toBe(VALUE);
    t = 4 * 60 * 1000;
    expect(await get(RULE, undefined)).toBe(VALUE);
    expect(loads).toBe(1);
    t = 5 * 60 * 1000 + 1;
    expect(await get(RULE, undefined)).toBe(VALUE);
    expect(loads).toBe(2);
  });

  test("a failed load is not cached", async () => {
    let fail = true;
    const get = cachedSecrets(async () => {
      if (fail) throw new ProxyError(429, "budget");
      return VALUE;
    });
    await expect(get(RULE, undefined)).rejects.toThrow("budget");
    fail = false;
    expect(await get(RULE, undefined)).toBe(VALUE);
  });

  test("a refusal from the server reaches the caller with the same status and no value", async () => {
    const client = {
      host: "https://cfs.example",
      call: async () => ({
        status: 429,
        body: { error: "the read budget for this alias is used up for this hour" },
      }),
      send: async () => ({ status: 429, body: {} }),
      download: async () => ({ status: 429, bytes: new Uint8Array() }),
    };
    const load = clientSecretLoader(client as never);
    await expect(load(RULE, undefined)).rejects.toMatchObject({ status: 429 });
  });

  test("the inject spec must be a header or query form", () => {
    expect(parseInjectSpec("header:Authorization:Bearer {value}")).toEqual({
      kind: "header",
      name: "Authorization",
      template: "Bearer {value}",
    });
    expect(parseInjectSpec("query:api_key")).toEqual({ kind: "query", name: "api_key" });
    expect(() => parseInjectSpec("cookie:sid")).toThrow();
    expect(() => parseInjectSpec("header:A:{value}{value}")).toThrow();
  });
});

describe("ADR 17: the listener end to end", () => {
  test("a raw request with a traversal path is refused by the real HTTP server", async () => {
    const h = harness();
    const p = await startProxy({ host: "127.0.0.1", port: 0 }, h.deps);
    try {
      const status = await new Promise<number>((resolve, reject) => {
        const req = httpRequest(
          {
            host: "127.0.0.1",
            port: p.port,
            path: "/github/a/../../secret",
            method: "GET",
            headers: { host: `127.0.0.1:${p.port}` },
          },
          (res) => {
            res.resume();
            resolve(res.statusCode ?? 0);
          },
        );
        req.on("error", reject);
        req.end();
      });
      expect(status).toBe(400);
      expect(h.upstreamCalls.length).toBe(0);
    } finally {
      await p.close();
    }
  });

  test("a normal request goes through the real listener with injection and redaction", async () => {
    const h = harness({ upstream: async () => new Response(`got ${VALUE}`) });
    const p = await startProxy({ host: "127.0.0.1", port: 0 }, h.deps);
    try {
      const res = await fetch(`http://127.0.0.1:${p.port}/github/user`);
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("got [redacted]");
      expect(h.upstreamCalls[0]?.init.headers.get("authorization")).toBe(`Bearer ${VALUE}`);
    } finally {
      await p.close();
    }
  });
});
