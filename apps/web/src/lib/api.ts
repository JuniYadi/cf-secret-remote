// Client for the Worker API at /api/v1 (ADR 4, ADR 20).
//
// In the browser the Cloudflare Access cookie is sent with the request (same origin). Only in dev builds
// can VITE_DEV_TOKEN add a bearer token, so the UI can be developed before Access is set up. The token is
// never read in production builds.

export const API_BASE = "/api/v1";

export type ApiErrorKind =
  | "unauthorized"
  | "forbidden"
  | "not-found"
  | "conflict"
  | "invalid"
  | "rate-limited"
  | "unavailable"
  | "server"
  | "network";

export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status: number;

  constructor(kind: ApiErrorKind, status: number) {
    // The message is the kind only. Response bodies are never copied into errors or logs.
    super(kind);
    this.name = "ApiError";
    this.kind = kind;
    this.status = status;
  }
}

/** Maps an HTTP status from the Worker to the UI's error kinds. */
export function kindForStatus(status: number): ApiErrorKind {
  switch (status) {
    case 401:
      return "unauthorized";
    case 403:
      return "forbidden";
    case 404:
      return "not-found";
    case 409:
      return "conflict";
    case 429:
      return "rate-limited";
    case 503:
      // The Worker returns 503 for the daily free-tier quota and for a restore in progress (ADR 19, ADR 23).
      return "unavailable";
    default:
      if (status >= 500) return "server";
      return "invalid";
  }
}

/** The dev-only bearer token. Production builds have DEV false, so this returns undefined there. */
export function devBearerToken(): string | undefined {
  if (!import.meta.env.DEV) return undefined;
  const token = import.meta.env.VITE_DEV_TOKEN;
  return token ? token : undefined;
}

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export async function request<T>(
  method: "GET" | "POST" | "PUT",
  path: string,
  body?: unknown,
  fetchImpl: FetchLike = (input, init) => fetch(input, init),
): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const token = devBearerToken();
  if (token) headers.Authorization = `Bearer ${token}`;

  let res: Response;
  try {
    res = await fetchImpl(`${API_BASE}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
    });
  } catch {
    throw new ApiError("network", 0);
  }
  if (!res.ok) throw new ApiError(kindForStatus(res.status), res.status);
  return (await res.json()) as T;
}

export interface Me {
  id: string;
  kind: "user" | "app";
  /** The person's email for users. */
  name: string;
  role: "admin" | "member";
  vaultReady: boolean;
  publicKey: string | null;
  /** The private key locked with the vault password. Still encrypted, so it can sit in memory. */
  lockedKey: string | null;
}

export const api = {
  whoami: (fetchImpl?: FetchLike) => request<Me>("GET", "/whoami", undefined, fetchImpl),
  createVault: (publicKey: string, lockedKey: string) =>
    request<{ ok: true }>("POST", "/vault", { publicKey, lockedKey }),
  setRecoveryKey: (lockedKey: string) =>
    request<{ ok: true }>("PUT", "/me/recovery", { lockedKey }),
};
