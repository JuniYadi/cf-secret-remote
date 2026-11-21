import { PROTOCOL_VERSION } from "@cfs/core";
import { CliError } from "./config.ts";

// ADR 25: a server whose protocol major differs from ours is refused.

export type Fetch = (input: string, init?: RequestInit) => Promise<Response>;

/** "1" and "1.2" both have major 1. Returns undefined when there is no number. */
export function protocolMajor(p: unknown): number | undefined {
  const n = Number.parseInt(String(p).split(".")[0] ?? "", 10);
  return Number.isFinite(n) ? n : undefined;
}

const checked = new Set<string>();

/** Throws when the server is unreachable or speaks another protocol major. */
export async function checkServer(host: string, fetchImpl: Fetch = fetch): Promise<void> {
  if (checked.has(host)) return;
  let r: Response;
  try {
    r = await fetchImpl(`${host}/api/health`);
  } catch {
    throw new CliError(`Cannot reach ${host}. Check the host and your network.`);
  }
  const body = (await r.json().catch(() => ({}))) as { protocol?: unknown; version?: string };
  if (!r.ok) throw new CliError(`${host} did not answer /api/health (status ${r.status}).`);
  const theirs = protocolMajor(body.protocol);
  const ours = Math.trunc(PROTOCOL_VERSION);
  if (theirs === undefined)
    throw new CliError(`${host} did not report a protocol version. Is it a cfs server?`);
  if (theirs !== ours) {
    const advice =
      theirs > ours
        ? "Upgrade this cfs: cfs upgrade."
        : "Upgrade the server: re-run cfs deploy on it.";
    throw new CliError(
      `${host} speaks protocol ${body.protocol} (server ${body.version ?? "unknown"}), but this cfs speaks protocol ${PROTOCOL_VERSION}. ${advice}`,
    );
  }
  checked.add(host);
}

/** POSTs JSON and returns the status and parsed body. Network errors become CliError. */
export async function postJson<T = unknown>(
  url: string,
  body: unknown,
  fetchImpl: Fetch = fetch,
): Promise<{ status: number; body: T }> {
  let r: Response;
  try {
    r = await fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch {
    throw new CliError(`Cannot reach ${new URL(url).origin}. Check the host and your network.`);
  }
  return { status: r.status, body: (await r.json().catch(() => ({}))) as T };
}
