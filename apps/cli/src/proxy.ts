import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { openSecret } from "@cfs/core";
import { CliError, type Client, groupKey } from "./client.ts";

// ADR 17. `cfs proxy` serves http://127.0.0.1:<port>/<alias>/<path> and forwards to <upstream>/<path> with the
// rule's value injected. The agent never sees the value. The request handler is pure: it takes injectable
// `fetchUpstream` and `getSecret`, so the rules can be tested without a network.

/** One rule as the API returns it to its own app (GET /agent/rules). The value name is `name`. */
export interface AgentRule {
  alias: string;
  secretPath: string;
  name: string;
  upstream: string;
  inject: string;
  maxReadsPerHour: number;
  requireReason: boolean;
  requireApproval: boolean;
}

export type Inject =
  | { kind: "header"; name: string; template: string }
  | { kind: "query"; name: string };

/** A failure with the status the caller sees. The message never contains a value. */
export class ProxyError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/** A request as the proxy receives it. `target` is the raw request-target, before any URL normalisation. */
export interface ProxyRequest {
  method: string;
  target: string;
  headers: Headers;
  body?: Uint8Array;
}

export interface ProxyResponse {
  status: number;
  headers: [string, string][];
  body: Uint8Array;
}

export interface UpstreamInit {
  method: string;
  headers: Headers;
  body?: Uint8Array;
  redirect: "manual";
}

export interface ProxyDeps {
  rules: AgentRule[];
  /** Returns the value of `rule.name` in `rule.secretPath`. Throws ProxyError on refusal. */
  getSecret(rule: AgentRule, reason: string | undefined): Promise<string>;
  /** Sends the request upstream. The real one is `fetch` with redirect "manual". */
  fetchUpstream(url: string, init: UpstreamInit): Promise<Response>;
  /** The --reason given when the proxy started. Used when a request has no X-Cfs-Reason header. */
  sessionReason?: string;
  /** Host headers this proxy answers to (DNS rebinding guard). When absent, the Host header is not checked. */
  hosts?: string[];
  /** Writes one log line. Receives alias, method, status and byte counts only. */
  log?: (line: ProxyLogLine) => void;
}

export interface ProxyLogLine {
  alias: string;
  method: string;
  status: number;
  bytesIn: number;
  bytesOut: number;
}

export const METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];
export const REDACTED = "[redacted]";
const MAX_BODY = 1024 * 1024;
const MAX_RESPONSE = 16 * 1024 * 1024;
const MAX_REASON = 500;
/** Request headers never forwarded. The injected header is also dropped (see handleProxyRequest). */
const DROP_REQUEST = new Set([
  "host",
  "connection",
  "keep-alive",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "content-length",
  "accept-encoding",
  "x-cfs-reason",
]);
/** Response headers dropped because the body is rebuilt (length changes after redaction). */
const DROP_RESPONSE = new Set([
  "content-length",
  "content-encoding",
  "transfer-encoding",
  "connection",
  "keep-alive",
]);

const encoder = new TextEncoder();

/** Parses the inject spec: `header:Name:Template-with-{value}` or `query:name`. Throws on anything else. */
export function parseInjectSpec(spec: string): Inject {
  if (spec.startsWith("query:")) {
    const name = spec.slice("query:".length);
    if (!/^[A-Za-z0-9_.-]{1,64}$/.test(name)) throw new Error("bad query name");
    return { kind: "query", name };
  }
  const m = spec.match(/^header:([A-Za-z0-9-]{1,64}):(.*)$/);
  if (
    !m ||
    !m[1] ||
    !/^[\x20-\x7e]+$/.test(m[2] ?? "") ||
    (m[2] ?? "").split("{value}").length !== 2
  )
    throw new Error("bad inject spec");
  return { kind: "header", name: m[1], template: m[2] ?? "" };
}

/** Parses --listen. Only the loopback addresses are allowed: 127.0.0.1 and ::1. Hostnames are refused. */
export function parseListen(text: string): { host: string; port: number } {
  const m = text.match(/^(\[[^\]]+\]|[^:[\]]+):(\d{1,5})$/);
  if (!m) throw new CliError("--listen takes host:port, for example 127.0.0.1:8787.");
  const host = (m[1] ?? "").replace(/^\[|\]$/g, "");
  const port = Number(m[2]);
  if (port > 65535) throw new CliError("--listen port must be 0 to 65535.");
  if (host !== "127.0.0.1" && host !== "::1")
    throw new CliError(`cfs proxy binds to loopback only (127.0.0.1 or ::1). Refusing ${host}.`);
  return { host, port };
}

/** The forms a secret value can take in a response: as is, URL-encoded, and base64. Empty ones are skipped. */
export function redactionForms(value: string): string[] {
  const forms = new Set([
    value,
    encodeURIComponent(value),
    Buffer.from(value, "utf8").toString("base64"),
  ]);
  return [...forms].filter((s) => s.length > 0);
}

function matchesAt(hay: Uint8Array, needle: Uint8Array, at: number): boolean {
  for (let j = 0; j < needle.length; j++) if (hay[at + j] !== needle[j]) return false;
  return true;
}

function replaceBytes(hay: Uint8Array, needle: Uint8Array, repl: Uint8Array): Uint8Array {
  const parts: Uint8Array[] = [];
  let last = 0;
  let i = 0;
  while (i + needle.length <= hay.length) {
    if (matchesAt(hay, needle, i)) {
      parts.push(hay.subarray(last, i), repl);
      i += needle.length;
      last = i;
    } else i++;
  }
  if (parts.length === 0) return hay;
  parts.push(hay.subarray(last));
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** Replaces every occurrence of every form of `value` in the bytes with `[redacted]`. */
export function redactBytes(bytes: Uint8Array, value: string): Uint8Array {
  let out = bytes;
  const repl = encoder.encode(REDACTED);
  for (const form of redactionForms(value)) out = replaceBytes(out, encoder.encode(form), repl);
  return out;
}

/** Same as redactBytes for one header name or value. */
export function redactText(text: string, value: string): string {
  let out = text;
  for (const form of redactionForms(value)) out = out.split(form).join(REDACTED);
  return out;
}

/** Splits the raw target into the path and the query. Refuses anything that is not an origin-form path. */
function splitTarget(target: string): { path: string; query: string } {
  if (!target.startsWith("/") || /[\r\n\0]/.test(target))
    throw new ProxyError(400, "bad request target");
  const q = target.indexOf("?");
  return q < 0
    ? { path: target, query: "" }
    : { path: target.slice(0, q), query: target.slice(q + 1) };
}

/**
 * The path below the alias, as sent upstream. Refuses CR, LF, NUL, `%`, backslashes and `.`/`..` segments once
 * decoded, so an encoded traversal (for example %2F..%2F) cannot reach another path.
 */
function forwardedPath(rawSegments: string[]): string {
  const joined = rawSegments.join("/");
  let decoded: string;
  try {
    decoded = decodeURIComponent(joined);
  } catch {
    throw new ProxyError(400, "bad path");
  }
  if (/[\r\n\0%\\]/.test(decoded)) throw new ProxyError(400, "bad path");
  if (decoded.split("/").some((s) => s === "." || s === ".."))
    throw new ProxyError(400, "path traversal is refused");
  return joined === "" ? "" : `/${joined}`;
}

const json = (status: number, body: unknown): ProxyResponse => {
  const bytes = encoder.encode(JSON.stringify(body));
  return {
    status,
    headers: [
      ["content-type", "application/json"],
      ["content-length", String(bytes.byteLength)],
    ],
    body: bytes,
  };
};

/** The core of the proxy. Every refusal is a ProxyError, and every answer is logged with alias and counts only. */
export async function handleProxyRequest(
  req: ProxyRequest,
  deps: ProxyDeps,
): Promise<ProxyResponse> {
  const line: ProxyLogLine = {
    alias: "-",
    method: req.method,
    status: 0,
    bytesIn: req.body?.byteLength ?? 0,
    bytesOut: 0,
  };
  let res: ProxyResponse;
  try {
    res = await serve(req, deps, line);
  } catch (e) {
    const known = e instanceof ProxyError;
    res = json(known ? e.status : 502, { error: known ? e.message : "proxy error" });
  }
  line.status = res.status;
  line.bytesOut = res.body.byteLength;
  (deps.log ?? defaultLog)(line);
  return res;
}

const defaultLog = (line: ProxyLogLine) => console.log(JSON.stringify(line));

async function serve(
  req: ProxyRequest,
  deps: ProxyDeps,
  line: ProxyLogLine,
): Promise<ProxyResponse> {
  if (req.headers.has("origin")) throw new ProxyError(403, "browser requests are refused");
  if (deps.hosts && !deps.hosts.includes(req.headers.get("host") ?? ""))
    throw new ProxyError(403, "unknown host header");
  if (!METHODS.includes(req.method)) throw new ProxyError(405, "method not allowed");
  if ((req.body?.byteLength ?? 0) > MAX_BODY) throw new ProxyError(413, "request body too large");

  const { path, query } = splitTarget(req.target);
  const segments = path.slice(1).split("/");
  const rule = deps.rules.find((r) => r.alias === segments[0]);
  if (!rule) throw new ProxyError(403, "unknown alias");
  line.alias = rule.alias;
  const rest = forwardedPath(segments.slice(1));

  const reason = (req.headers.get("x-cfs-reason") || deps.sessionReason || "").trim();
  if (reason.length > MAX_REASON) throw new ProxyError(400, "reason is too long");
  if (rule.requireReason && reason === "")
    throw new ProxyError(
      403,
      "this alias needs a reason: send X-Cfs-Reason or start cfs proxy with --reason",
    );

  let inject: Inject;
  try {
    inject = parseInjectSpec(rule.inject);
  } catch {
    throw new ProxyError(500, "the rule is not valid");
  }

  const value = await deps.getSecret(rule, reason || undefined);
  if (value === "") throw new ProxyError(500, "the secret has an empty value");

  // Build the upstream URL. The host is always the rule's upstream; the caller chooses only the path.
  const params = new URLSearchParams(query);
  if (inject.kind === "query") {
    params.delete(inject.name);
    params.set(inject.name, value);
  }
  const qs = params.toString();
  const url = `${rule.upstream}${rest}${qs ? `?${qs}` : ""}`;
  if (new URL(url).origin !== new URL(rule.upstream).origin)
    throw new ProxyError(500, "the rule upstream is not valid");

  // Forward the caller's headers, minus the same header name as the injected one, then add the injected value.
  const headers = new Headers();
  const injected = inject.kind === "header" ? inject.name.toLowerCase() : null;
  req.headers.forEach((v, k) => {
    if (DROP_REQUEST.has(k) || k === injected) return;
    headers.set(k, v);
  });
  if (inject.kind === "header") {
    const headerValue = inject.template.replace("{value}", () => value);
    if (/[\r\n\0]/.test(headerValue))
      throw new ProxyError(500, "the value cannot be sent in a header");
    try {
      headers.set(inject.name, headerValue);
    } catch {
      throw new ProxyError(500, "the value cannot be sent in a header");
    }
  }
  headers.set("accept-encoding", "identity");

  const body =
    req.body && req.body.byteLength > 0 && req.method !== "GET" && req.method !== "HEAD"
      ? req.body
      : undefined;
  let upstream: Response;
  try {
    upstream = await deps.fetchUpstream(url, {
      method: req.method,
      headers,
      body,
      redirect: "manual",
    });
  } catch {
    // The error text can contain the URL, which may hold the value. It is dropped on purpose.
    throw new ProxyError(502, "upstream unreachable");
  }

  // Redaction works on the bytes, so an encoded body cannot be checked. Refuse it rather than leak.
  const encoding = upstream.headers.get("content-encoding");
  if (encoding && encoding.trim().toLowerCase() !== "identity")
    throw new ProxyError(502, "upstream sent an encoded body the proxy cannot redact");
  const raw = new Uint8Array(await upstream.arrayBuffer());
  if (raw.byteLength > MAX_RESPONSE) throw new ProxyError(502, "upstream body is too large");

  // ADR 17: the value is redacted from the body and from every header, names included.
  const out = redactBytes(raw, value);
  const outHeaders: [string, string][] = [];
  upstream.headers.forEach((v, k) => {
    if (DROP_RESPONSE.has(k)) return;
    outHeaders.push([redactText(k, value), redactText(v, value)]);
  });
  outHeaders.push(["content-length", String(out.byteLength)]);
  return { status: upstream.status, headers: outHeaders, body: out };
}

/** Caches values per alias for `ttlMs` (5 minutes by default). Concurrent calls share one fetch. */
export function cachedSecrets(
  load: (rule: AgentRule, reason: string | undefined) => Promise<string>,
  ttlMs = 5 * 60 * 1000,
  now: () => number = Date.now,
): (rule: AgentRule, reason: string | undefined) => Promise<string> {
  const cache = new Map<string, { value: Promise<string>; until: number }>();
  return (rule, reason) => {
    const hit = cache.get(rule.alias);
    if (hit && hit.until > now()) return hit.value;
    const value = load(rule, reason);
    cache.set(rule.alias, { value, until: now() + ttlMs });
    value.catch(() => cache.delete(rule.alias));
    return value;
  };
}

/** Real secret loader: reads the ciphertext through the API and opens it with the group key. */
export function clientSecretLoader(
  c: Client,
): (rule: AgentRule, reason: string | undefined) => Promise<string> {
  return async (rule, reason) => {
    const headers = reason ? { "X-Cfs-Reason": reason } : undefined;
    const r = await c.call<{ version: number; wrappedDek: string; ciphertext: string }>(
      "GET",
      `/secret?path=${encodeURIComponent(rule.secretPath)}`,
      undefined,
      headers,
    );
    if (r.status !== 200) {
      const message = (r.body as { error?: string })?.error ?? "could not read the secret";
      throw new ProxyError(
        r.status === 403 || r.status === 404 || r.status === 429 ? r.status : 502,
        message,
      );
    }
    const prefix = rule.secretPath.split("/")[0] ?? "";
    let key: Uint8Array;
    try {
      ({ key } = await groupKey(c, prefix));
    } catch (e) {
      throw new ProxyError(403, e instanceof Error ? e.message : "not allowed");
    }
    let values: Record<string, string>;
    try {
      values = await openSecret(
        key,
        rule.secretPath,
        r.body.version,
        r.body.wrappedDek,
        r.body.ciphertext,
      );
    } catch {
      throw new ProxyError(502, "could not open the secret");
    }
    const value = values[rule.name];
    if (value === undefined) throw new ProxyError(404, "that name is not in the secret");
    return value;
  };
}

/** The real upstream call. Redirects are returned as they are, never followed. */
export const fetchUpstreamReal = (url: string, init: UpstreamInit): Promise<Response> =>
  fetch(url, {
    method: init.method,
    headers: init.headers,
    body: init.body as unknown as BodyInit | undefined,
    redirect: "manual",
  });

/** Starts the HTTP listener on loopback. Browser requests (Origin set) and other Host headers are refused. */
export async function startProxy(
  listen: { host: string; port: number },
  deps: ProxyDeps,
): Promise<{ port: number; server: Server; close(): Promise<void> }> {
  if (listen.host !== "127.0.0.1" && listen.host !== "::1")
    throw new CliError("cfs proxy binds to loopback only.");
  const server = createServer((req, res) => {
    void handleNode(req, res, deps);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(listen.port, listen.host, () => resolve());
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : listen.port;
  deps.hosts = [`127.0.0.1:${port}`, `[::1]:${port}`];
  return {
    port,
    server,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

async function handleNode(req: IncomingMessage, res: ServerResponse, deps: ProxyDeps) {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) {
      res.writeHead(413, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "request body too large" }));
      req.destroy();
      return;
    }
    chunks.push(chunk as Buffer);
  }
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (v === undefined) continue;
    for (const item of Array.isArray(v) ? v : [v]) headers.append(k, item);
  }
  const out = await handleProxyRequest(
    {
      method: req.method ?? "GET",
      target: req.url ?? "/",
      headers,
      body: chunks.length ? new Uint8Array(Buffer.concat(chunks)) : undefined,
    },
    deps,
  );
  res.writeHead(out.status, out.headers);
  res.end(Buffer.from(out.body));
}
