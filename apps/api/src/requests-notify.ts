import type { Env } from "./types.ts";

// ADR 16 / ADR 18. Called when a request is created. The alerts issue (ADR 18) fills this in.
// Intentionally empty for now. Must never throw or block the request.
export async function notifyAccessRequest(
  _env: Env,
  _request: { id: string; requester: string; path: string; reason: string; duration: number },
): Promise<void> {}
