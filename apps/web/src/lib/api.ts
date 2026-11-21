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
  /** Set only for a wrong CLI code (ADR 27): how many tries are left. No other body field is kept. */
  readonly attemptsLeft: number | undefined;

  constructor(kind: ApiErrorKind, status: number, attemptsLeft?: number) {
    // The message is the kind only. Response bodies are never copied into errors or logs.
    super(kind);
    this.name = "ApiError";
    this.kind = kind;
    this.status = status;
    this.attemptsLeft = attemptsLeft;
  }
}

/** Reads the one numeric field the CLI code check sends back. Anything else in the body is dropped. */
async function attemptsFrom(res: Response): Promise<number | undefined> {
  try {
    const body = (await res.json()) as { attemptsLeft?: unknown } | null;
    const n = body?.attemptsLeft;
    return typeof n === "number" && Number.isInteger(n) && n >= 0 ? n : undefined;
  } catch {
    return undefined;
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
  method: "GET" | "POST" | "PUT" | "DELETE",
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
  if (!res.ok) {
    const attempts = res.status === 404 ? await attemptsFrom(res) : undefined;
    throw new ApiError(kindForStatus(res.status), res.status, attempts);
  }
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

/** Builds `?a=b&c=d`, skipping empty values. The result is "" when nothing is set. */
export function queryString(params: Record<string, string | number | undefined | null>): string {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`);
  }
  return parts.length > 0 ? `?${parts.join("&")}` : "";
}

// Shapes the Worker returns for the screens in this part (ADR 16, 17, 18, 19, 27). Times are unix seconds.

export type AuditResult = "ok" | "denied" | "error";

export interface AuditRow {
  seq: number;
  hash: string;
  at: number;
  who: string;
  action: string;
  path?: string;
  version?: number;
  result: AuditResult;
  ip?: string;
  note?: string;
}

export interface Usage {
  day: string;
  writes: number;
  readsLogged: number;
  limit: number;
  warning: boolean;
}

export interface Verify {
  ok: boolean;
  rows: number;
  firstBad: number | null;
  firstBadSeq: number | null;
  head: string;
  base: { seq: number; hash: string } | null;
  checkpoints: {
    stored: number;
    verified: number;
    pruned: number;
    mismatched: string[];
  };
}

export const RULE_NAMES = [
  "blocked",
  "agent_prod_read",
  "new_network",
  "read_burst",
  "quota_80",
  "chain_broken",
  "recovery_requested",
  "access_request",
] as const;
export type RuleName = (typeof RULE_NAMES)[number];

export interface ChannelToggles {
  webhook: boolean;
  email: boolean;
}

export interface AlertSettings {
  /** The webhook URL with its middle masked, or null when none is set. The full URL never comes back. */
  webhook: string | null;
  email: { available: boolean; recipients: string[] };
  rules: Record<RuleName, ChannelToggles>;
}

export type RequestStatus = "pending" | "approved" | "denied" | "cancelled" | "expired";

export interface AccessRequest {
  id: string;
  requesterId: string;
  requester: string;
  path: string;
  groupPrefix: string;
  reason: string;
  duration: number;
  rekeyAfter: boolean;
  status: RequestStatus;
  approver: string | null;
  createdAt: number;
  decidedAt: number | null;
  expiresAt: number | null;
}

export interface Identity {
  id: string;
  kind: "user" | "app";
  name: string;
  role: "admin" | "member";
  publicKey: string | null;
  status: string;
}

export interface AppSummary {
  id: string;
  name: string;
  status: string;
}

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

export interface AgentRuleInput {
  alias?: string;
  secretPath: string;
  name: string;
  upstream: string;
  inject: string;
  maxReadsPerHour: number;
  requireReason: boolean;
  requireApproval: boolean;
}

export interface SignedInDevice {
  id: string;
  kind: string;
  device: string;
  createdAt: number;
  expiresAt: number;
}

export interface CliLoginInfo {
  userCode: string;
  device: string;
  expiresAt: number;
}

/** Cleartext metadata of a secret (ADR 22). Owner is an identity name; rotateBy is YYYY-MM-DD. */
export interface Meta {
  description?: string;
  owner?: string;
  rotateBy?: string;
}

/** One row of GET /secrets. Names and metadata only, never values. */
export interface SecretSummary {
  path: string;
  version: number;
  updatedAt: number;
  names: string[];
  meta: Meta;
}

/** GET /secret: the sealed version. The client opens it with the group key. */
export interface SecretRecord {
  path: string;
  version: number;
  keyringVersion: number;
  names: string[];
  wrappedDek: string;
  ciphertext: string;
  createdAt: number;
}

/** GET /secret/versions: metadata and fingerprints for each version, newest first. */
export interface VersionRow {
  version: number;
  names: string[];
  fps: Record<string, string> | null;
  createdAt: number;
  createdBy: string;
}

/** GET /secret/history: aggregates over 30 days from the audit log. */
export interface SecretHistory {
  path: string;
  windowDays: number;
  opens: number;
  readers: number;
  lastReader: { who: string; at: number; version: number } | null;
  lostAccess: number;
  people: {
    name: string;
    opens: number;
    lastOpened: number;
    lastVersion: number;
    hasAccess: boolean;
  }[];
}

/** PUT /secret body. Values are already sealed by @cfs/core. */
export interface SecretWrite {
  path: string;
  names: string[];
  wrappedDek: string;
  ciphertext: string;
  keyringVersion: number;
  version: number;
  fps: Record<string, string>;
}

// --- Groups, permissions, apps (ADR 14, 5, 15). Shapes match apps/api/src/routes. ---

export interface KeyringRow {
  prefix: string;
  version: number;
}

export interface GroupMember {
  identityId: string;
  name: string;
  role: "admin" | "member";
  status: string;
}

export interface Rule {
  path: string;
  caps: Cap[];
}

export type Cap = "create" | "read" | "update" | "delete" | "list";

export interface PolicyAssignee {
  identityId: string;
  name: string;
  kind: "user" | "app";
  expiresAt: number | null;
}

export interface PolicyRow {
  id: string;
  name: string;
  rules: Rule[];
  assignees: PolicyAssignee[];
}

export interface SecretListRow {
  path: string;
  version: number;
  updatedAt: number;
  names: string[];
}

/** One stored version. Ciphertext only; opening it needs the group key. */
export interface SecretVersion {
  version: number;
  keyringVersion: number;
  names: string[];
  wrappedDek: string;
  ciphertext: string;
  createdAt: number;
}

export interface RotateSecret {
  path: string;
  names: string[];
  wrappedDek: string;
  ciphertext: string;
  version: number;
}

/** An app or bot as the list and detail pages read it. A superset of AppSummary. */
export interface AppRow {
  id: string;
  name: string;
  status: string;
  createdAt: number;
  owner: string | null;
  roleId: string;
  tokenTtl: number;
  maxUses: number | null;
  uses: number;
  cidr: string[] | null;
  expiresAt: number | null;
  firstLoginAt: number | null;
  lastLoginAt: number | null;
  lastIp: string | null;
  waiting: boolean;
}

export interface AppDetail extends AppRow {
  sessions: { id: string; createdAt: number; expiresAt: number }[];
  activity: {
    at: number;
    action: string;
    result: string;
    ip: string | null;
    note: string | null;
  }[];
}

export interface NewAppBody {
  name: string;
  publicKey: string;
  tokenTtl?: number;
  maxUses?: number | null;
  expiresAt?: number | null;
  cidr?: string | null;
}

export const api = {
  whoami: (fetchImpl?: FetchLike) => request<Me>("GET", "/whoami", undefined, fetchImpl),
  createVault: (publicKey: string, lockedKey: string) =>
    request<{ ok: true }>("POST", "/vault", { publicKey, lockedKey }),
  setRecoveryKey: (lockedKey: string) =>
    request<{ ok: true }>("PUT", "/me/recovery", { lockedKey }),

  // Activity (ADR 6, 19)
  audit: (query: Record<string, string | number | undefined>) =>
    request<AuditRow[]>("GET", `/audit${queryString(query)}`),
  usage: () => request<Usage>("GET", "/usage"),
  verify: () => request<Verify>("GET", "/audit/verify"),

  // Alerts (ADR 18)
  alerts: () => request<AlertSettings>("GET", "/alerts"),
  setWebhook: (webhook: string | null) => request<AlertSettings>("PUT", "/alerts", { webhook }),
  setRules: (rules: Record<RuleName, ChannelToggles>) =>
    request<AlertSettings>("PUT", "/alerts", { rules }),

  // Access requests (ADR 16)
  requests: (status?: RequestStatus) =>
    request<AccessRequest[]>("GET", `/requests${queryString({ status })}`),
  createRequest: (input: { path: string; reason: string; duration: number }) =>
    request<AccessRequest>("POST", "/requests", input),
  cancelRequest: (id: string) => request<AccessRequest>("POST", `/requests/${id}/cancel`),
  denyRequest: (id: string) => request<AccessRequest>("POST", `/requests/${id}/deny`),
  approveRequest: (id: string, wrappedKey: string, version: number) =>
    request<AccessRequest>("POST", `/requests/${id}/approve`, { wrappedKey, version }),
  /** The caller's wrapped copy of a group key. Used by an approver before approving. */
  groupKey: (prefix: string) =>
    request<{ wrappedKey: string; version: number }>("GET", `/keyrings/${prefix}/key`),
  identities: () => request<Identity[]>("GET", "/identities"),

  // Secrets (ADR 10, 22)
  secrets: () => request<SecretSummary[]>("GET", "/secrets"),
  secret: (path: string, version?: number) =>
    request<SecretRecord>("GET", `/secret${queryString({ path, version })}`),
  writeSecret: (body: SecretWrite) =>
    request<{ path: string; version: number }>("PUT", "/secret", body),
  secretVersions: (path: string) =>
    request<VersionRow[]>("GET", `/secret/versions${queryString({ path })}`),
  secretHistory: (path: string) =>
    request<SecretHistory>("GET", `/secret/history${queryString({ path })}`),
  keyrings: () => request<{ prefix: string; version: number }[]>("GET", "/keyrings"),

  // Agent rules (ADR 17)
  apps: () => request<AppRow[]>("GET", "/apps"),
  agentRules: (appId: string) => request<AgentRule[]>("GET", `/apps/${appId}/rules`),
  createAgentRule: (appId: string, input: AgentRuleInput & { alias: string }) =>
    request<AgentRule>("POST", `/apps/${appId}/rules`, input),
  updateAgentRule: (appId: string, alias: string, input: Omit<AgentRuleInput, "alias">) =>
    request<AgentRule>("PUT", `/apps/${appId}/rules/${alias}`, input),
  deleteAgentRule: (appId: string, alias: string) =>
    request<{ ok: true }>("DELETE", `/apps/${appId}/rules/${alias}`),

  // Devices (ADR 27)
  sessions: () => request<SignedInDevice[]>("GET", "/sessions"),
  signOutDevice: (id: string) => request<{ ok: true }>("DELETE", `/sessions/${id}`),

  // CLI login (ADR 11)
  cliLogin: (code: string) => request<CliLoginInfo>("GET", `/cli/login${queryString({ code })}`),
  cliApprove: (userCode: string) => request<{ ok: true }>("POST", "/cli/approve", { userCode }),

  // Groups (ADR 3, 14). `identities` is above, shared with the access requests part.
  keyrings: () => request<KeyringRow[]>("GET", "/keyrings"),
  keyringMembers: (prefix: string) =>
    request<GroupMember[]>("GET", `/keyrings/${encodeURIComponent(prefix)}/members`),
  myGroupKey: (prefix: string) =>
    request<{ wrappedKey: string; version: number }>(
      "GET",
      `/keyrings/${encodeURIComponent(prefix)}/key`,
    ),
  createKeyring: (prefix: string, members: { identityId: string; wrappedKey: string }[]) =>
    request<{ id: string; prefix: string }>("POST", "/keyrings", { prefix, members }),
  addGroupMember: (prefix: string, identityId: string, wrappedKey: string) =>
    request<{ ok: true }>("POST", `/keyrings/${encodeURIComponent(prefix)}/members`, {
      identityId,
      wrappedKey,
    }),
  rotateStart: (
    prefix: string,
    removeIdentityId: string,
    members: { identityId: string; wrappedKey: string }[],
  ) =>
    request<{ version: number; secrets: number }>(
      "POST",
      `/keyrings/${encodeURIComponent(prefix)}/rotate/start`,
      { removeIdentityId, members },
    ),
  rotateChunk: (prefix: string, keyringVersion: number, secrets: RotateSecret[]) =>
    request<{ staged: number }>("POST", `/keyrings/${encodeURIComponent(prefix)}/rotate/chunk`, {
      keyringVersion,
      secrets,
    }),
  rotateCommit: (prefix: string) =>
    request<{ version: number; status: string }>(
      "POST",
      `/keyrings/${encodeURIComponent(prefix)}/rotate/commit`,
    ),
  rotateAbort: (prefix: string) =>
    request<{ version: number; status: string }>(
      "POST",
      `/keyrings/${encodeURIComponent(prefix)}/rotate/abort`,
    ),

  // People (admins)
  invite: (email: string, role: "admin" | "member") =>
    request<{ ok: true }>("POST", "/invites", { email, role }),

  // Secrets, read only here (names and ciphertext for re-locking)
  secrets: () => request<SecretListRow[]>("GET", "/secrets"),
  secretVersion: (path: string) =>
    request<SecretVersion>("GET", `/secret?path=${encodeURIComponent(path)}`),

  // Permissions (ADR 5)
  policies: () => request<PolicyRow[]>("GET", "/policies"),
  createPolicy: (name: string, rules: Rule[]) =>
    request<{ id: string }>("POST", "/policies", { name, rules }),
  assignPolicy: (policyId: string, identityId: string) =>
    request<{ ok: true }>("POST", `/policies/${encodeURIComponent(policyId)}/assign`, {
      identityId,
    }),

  // Apps and bots (ADR 15). `apps` is above.
  app: (id: string) => request<AppDetail>("GET", `/apps/${encodeURIComponent(id)}`),
  createApp: (body: NewAppBody) =>
    request<{ id: string; roleId: string; secretId: string }>("POST", "/apps", body),
  rotateApp: (id: string) =>
    request<{ roleId: string; secretId: string }>("POST", `/apps/${encodeURIComponent(id)}/rotate`),
  disableApp: (id: string) =>
    request<{ ok: true }>("POST", `/apps/${encodeURIComponent(id)}/disable`),
};
