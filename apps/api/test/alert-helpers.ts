import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { type AlertSenders, withAlertContext } from "../src/alerts.ts";
import worker from "../src/index.ts";
import type { Env } from "../src/types.ts";

let senders: AlertSenders = {};
const pending = new Set<Promise<unknown>>();
const testEnv = env as unknown as Env;

export function setAlertSenders(value: AlertSenders) {
  senders = value;
}
export function resetAlertSenders() {
  senders = {};
}
function track(job: Promise<unknown>) {
  pending.add(job);
  void job.finally(() => pending.delete(job));
}
export async function flushAlerts() {
  while (pending.size) await Promise.all([...pending]);
}
export function inAlertContext<T>(fn: () => T): T {
  const ctx = { waitUntil: track } as unknown as ExecutionContext;
  return withAlertContext(testEnv, ctx, fn, senders);
}
export function testFetch(input: string | Request, init?: RequestInit) {
  const ctx = createExecutionContext();
  return inAlertContext(async () => {
    const response = await worker.fetch(new Request(input, init), testEnv, ctx);
    track(waitOnExecutionContext(ctx));
    return response;
  });
}
export async function api<T = any>(
  method: string,
  path: string,
  token?: string | null,
  body?: unknown,
  extraHeaders: Record<string, string> = {},
) {
  const r = await testFetch(`http://t.test/api/v1${path}`, {
    method,
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...extraHeaders,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: r.status, body: (await r.json().catch(() => null)) as T };
}
