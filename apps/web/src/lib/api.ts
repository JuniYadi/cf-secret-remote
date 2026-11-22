// Client for the Worker API at /api/v1 (ADR 4, ADR 20).
//
// In the browser the Cloudflare Access cookie is sent with the request (same origin). Only in dev builds
// can VITE_DEV_TOKEN add a bearer token, so the UI can be developed before Access is set up. The token is
// never read in production builds.

import { markQuotaReached } from "./quota.ts";

export const API_BASE = "/api/v1";
/** The health route sits outside /api/v1 (apps/api/src/index.ts). */
export const HEALTH_PATH = "/api/health";

export type ApiErrorKind =
  | "unauthorized"
  | "forbidden"
  | "not-found"
  | "conflict"
  | "invalid"
  | "rate-limited"
  | "unavailable"
  | "quota"
  | "maintenance"
  | "server"
  | "network";

export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status: number;
  /** Set only for a wrong CLI code (ADR 27): how many tries are left. No other body field is kept. */
  readonly attemptsLeft: number | undefined;
  /** Seconds from the Retry-After header, when the server sent one (ADR 19, ADR 23). */
  readonly retryAfter: number | null;

  constructor(
    kind: ApiErrorKind,
    status: number,
    attemptsLeft?: number,
    retryAfter: number | null = null,
  ) {
    // The message is the kind only. Response bodies are never copied into errors or logs.
    super(kind);
    this.name = "ApiError";
    this.kind = kind;
    this.status = status;
    this.attemptsLeft = attemptsLeft;
    this.retryAfter = retryAfter;
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

/**
 * Tells the two 503s apart by the server's message. The message is read here and dropped, never kept.
 * "quota" stops writes until the reset; "maintenance" means a restore is running (ADR 23).
 */
export function kindForFailure(status: number, message: string): ApiErrorKind {
  if (status === 503 && /quota/i.test(message)) return "quota";
  if (status === 503 && /maintenance/i.test(message)) return "maintenance";
  return kindForStatus(status);
}

/** Retry-After as whole seconds, or null when absent or not a number. */
export function retryAfterOf(res: Response): number | null {
  const raw = res.headers.get("Retry-After");
  const n = raw === null ? Number.NaN : Number(raw);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

/** The dev-only bearer token. Production builds have DEV false, so this returns undefined there. */
export function devBearerToken(): string | undefined {
  if (!import.meta.env.DEV) return undefined;
  const token = import.meta.env.VITE_DEV_TOKEN;
  return token ? token : undefined;
}

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;
export type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

const defaultFetch: FetchLike = (input, init) => fetch(input, init);

/**
 * One request to `url`. Throws ApiError for any non-2xx status. A quota 503 on a write also marks the
 * quota screen (quota.ts), so every page shows the same state. Reads are never blocked by the quota.
 */
export async function send(
  method: Method,
  url: string,
  body?: unknown,
  fetchImpl: FetchLike = defaultFetch,
  headers: Record<string, string> = {},
): Promise<Response> {
  const h: Record<string, string> = { Accept: "application/json", ...headers };
  if (body !== undefined) h["Content-Type"] = "application/json";
  const token = devBearerToken();
  if (token) h.Authorization = `Bearer ${token}`;

  let res: Response;
  try {
    res = await fetchImpl(url, {
      method,
      headers: h,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
    });
  } catch {
    throw new ApiError("network", 0);
  }
  if (res.ok) return res;

  // The 503 message is read only to tell the quota from a restore; the text itself is never kept.
  const message = res.status === 503 ? await res.text().catch(() => "") : "";
  const kind = kindForFailure(res.status, message);
  const retryAfter = retryAfterOf(res);
  if (kind === "quota" && method !== "GET") markQuotaReached(retryAfter);
  const attempts = res.status === 404 ? await attemptsFrom(res) : undefined;
  throw new ApiError(kind, res.status, attempts, retryAfter);
}

export async function request<T>(
  method: Method,
  path: string,
  body?: unknown,
  fetchImpl: FetchLike = defaultFetch,
  headers?: Record<string, string>,
): Promise<T> {
  const res = await send(method, `${API_BASE}${path}`, body, fetchImpl, headers);
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
  /** Whether `who` is a person or an app. null when the identity no longer exists. */
  kind?: "user" | "app" | null;
}

/** The last 24 hours, for the Activity stat cards. `accesses` are allowed secret reads. */
export interface AuditStats {
  since: number;
  accesses: number;
  byApps: number;
  blocked: number;
  actors: number;
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

/** Per channel: "off" means it isn't set up on this server. */
export interface AlertTestResult {
  webhook: "sent" | "failed" | "off";
  email: "sent" | "failed" | "off";
}

export interface RecentAlert {
  rule: string;
  subject: string;
  at: number;
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
  /** Last browser vault unlock, in Unix seconds, or null if none is recorded. */
  last_unlocked_at: number | null;
  /** True (or 1 from SQLite) when the person has saved a recovery key (ADR 20). */
  recoverySet?: boolean | number;
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
  /** Last time the session made a call, rounded to 10 minutes. null before it was first used. */
  lastUsedAt: number | null;
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

/** GET /secrets row. The same shape the secrets screens read (names and metadata, never values). */
export type SecretListRow = SecretSummary;

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

// --- ADR 24 part 5: settings, offboarding, recovery, backup (the shapes the Worker returns) ---

/** GET /api/health. Outside /api/v1. */
export interface Health {
  ok: boolean;
  protocol: number;
  version: string;
}

/** GET /recovery (admin): a pending request, names and times only. */
export interface PendingRecovery {
  id: string;
  name: string;
  createdAt: number;
  attempts: number;
}

/** GET /recovery/:id (admin): one pending request, with the new public key the code is made from. */
export interface RecoveryDetail {
  id: string;
  name: string;
  status: string;
  attemptsLeft: number;
  publicKey: string;
  groups: string[];
}

/** POST /recovery/request: the four-word code and the cancel token, shown once to the requester. */
export interface RecoveryStart {
  id: string;
  words: string;
  cancelToken: string;
}

export interface RecoveryKeyStatus {
  set: boolean;
  lockedKey: string | null;
}

export interface RestoreCounts {
  identity: number;
  secret: number;
  audit: number;
  [table: string]: number;
}

/** POST /restore/check (ADR 23). Reads and verifies a file; changes nothing. */
/** One backup: an automatic R2 copy (with a size) or a manual download (the log keeps the time only). */
export interface BackupCopy {
  at: number;
  type: "auto" | "manual";
  size: number | null;
}

export interface BackupHistory {
  /** Whether an R2 bucket is connected, so daily copies are being kept. */
  r2: boolean;
  copies: BackupCopy[];
}

export interface RestoreCheck {
  ok: true;
  host: string;
  schema: number;
  createdAt: number;
  gapSeconds: number;
  lastAuditAt: number | null;
  audit: {
    rows: number;
    ok: boolean;
    checkpoints: { stored: number; verified: number; pruned: number; mismatched: string[] };
  };
  counts: { file: RestoreCounts; current: RestoreCounts };
  sha256: string;
}

export interface OffboardPlan {
  person: { id: string; name: string; role: string; status: string };
  groups: string[];
  apps: { id: string; name: string; status: string }[];
  sessions: {
    id: string;
    kind: string;
    device: string | null;
    createdAt: number;
    expiresAt: number;
  }[];
  opened: {
    windowDays: number;
    secrets: {
      path: string;
      versions: number[];
      names: string[];
      opens: number;
      lastOpened: number;
    }[];
  };
  blockers: { groups: string[]; apps: string[]; twoAdmins: boolean };
  canFinish: boolean;
}

/** Base64 of raw bytes, in chunks so large files do not overflow the call stack. */
export function toBase64(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    out += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(out);
}

function passphraseHeader(passphrase: string | undefined): Record<string, string> | undefined {
  return passphrase ? { "X-Backup-Passphrase": passphrase } : undefined;
}

export const api = {
  whoami: (fetchImpl?: FetchLike) => request<Me>("GET", "/whoami", undefined, fetchImpl),
  recordUnlock: () => request<{ ok: true }>("POST", "/me/unlocked"),
  createVault: (publicKey: string, lockedKey: string) =>
    request<{ ok: true }>("POST", "/vault", { publicKey, lockedKey }),
  personalKeyring: () =>
    request<{ id: string; prefix: string; version: number; wrappedKey: string } | null>(
      "GET",
      "/me/personal-keyring",
    ),
  createPersonalKeyring: (prefix: string, wrappedKey: string) =>
    request<{ id: string; prefix: string; version: number }>("POST", "/me/personal-keyring", {
      prefix,
      wrappedKey,
    }),
  setRecoveryKey: (lockedKey: string) =>
    request<{ ok: true }>("PUT", "/me/recovery", { lockedKey }),

  // Activity (ADR 6, 19)
  audit: (query: Record<string, string | number | undefined>) =>
    request<AuditRow[]>("GET", `/audit${queryString(query)}`),
  auditStats: () => request<AuditStats>("GET", "/audit/stats"),
  /** The filtered log as CSV text. The Worker caps it at the newest 5000 rows and records the export. */
  auditCsv: async (query: Record<string, string | number | undefined>): Promise<Blob> => {
    const res = await send("GET", `${API_BASE}/audit/export.csv${queryString(query)}`);
    return res.blob();
  },
  usage: () => request<Usage>("GET", "/usage"),
  verify: () => request<Verify>("GET", "/audit/verify"),

  // Alerts (ADR 18)
  alerts: () => request<AlertSettings>("GET", "/alerts"),
  setWebhook: (webhook: string | null) => request<AlertSettings>("PUT", "/alerts", { webhook }),
  setRules: (rules: Record<RuleName, ChannelToggles>) =>
    request<AlertSettings>("PUT", "/alerts", { rules }),
  alertsTest: () => request<AlertTestResult>("POST", "/alerts/test"),
  alertsRecent: () => request<RecentAlert[]>("GET", "/alerts/recent"),

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
  // The Worker does not echo the path back, and the sealed envelope is bound to it (ADR 22), so it is set here.
  secret: async (path: string, version?: number): Promise<SecretRecord> => ({
    ...(await request<Omit<SecretRecord, "path">>(
      "GET",
      `/secret${queryString({ path, version })}`,
    )),
    path,
  }),
  writeSecret: (body: SecretWrite) =>
    request<{ path: string; version: number }>("PUT", "/secret", body),
  secretVersions: (path: string) =>
    request<VersionRow[]>("GET", `/secret/versions${queryString({ path })}`),
  secretHistory: (path: string) =>
    request<SecretHistory>("GET", `/secret/history${queryString({ path })}`),
  keyrings: () => request<KeyringRow[]>("GET", "/keyrings"),

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
  /** Ends every command-line session of the caller, including the CLI that sends this when it is one. */
  signOutAllDevices: () => request<{ ok: true; ended: number }>("DELETE", "/sessions"),

  // CLI login (ADR 11)
  cliLogin: (code: string) => request<CliLoginInfo>("GET", `/cli/login${queryString({ code })}`),
  cliApprove: (userCode: string) => request<{ ok: true }>("POST", "/cli/approve", { userCode }),

  // Groups (ADR 3, 14). `identities` is above, shared with the access requests part.
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

  // Part 5: settings, offboarding, recovery, backup (ADR 14, 19, 20, 21, 23, 24).
  recoveryKeyStatus: () => request<RecoveryKeyStatus>("GET", "/me/recovery"),
  changeVaultPassword: (lockedKey: string) =>
    request<{ ok: true }>("PUT", "/me/vault", { lockedKey }),
  setRole: (id: string, role: "admin" | "member") =>
    request<{ id: string; role: string; status: string }>("PATCH", `/identities/${id}`, { role }),
  health: async (fetchImpl?: FetchLike): Promise<Health> => {
    const res = await send("GET", HEALTH_PATH, undefined, fetchImpl);
    return (await res.json()) as Health;
  },
  offboardPlan: (id: string) => request<OffboardPlan>("GET", `/offboard/${id}/plan`),
  offboardReassign: (id: string, appId: string, ownerId: string) =>
    request<unknown>("POST", `/offboard/${id}/apps/${appId}/reassign`, { ownerId }),
  offboardFinish: (id: string) =>
    request<{ changed: { disabled: boolean; sessionsEnded: number; policiesRemoved: number } }>(
      "POST",
      `/offboard/${id}/finish`,
      {},
    ),
  startRecovery: (publicKey: string, lockedKey: string) =>
    request<RecoveryStart>("POST", "/recovery/request", { publicKey, lockedKey }),
  pendingRecoveries: () => request<PendingRecovery[]>("GET", "/recovery"),
  recoveryDetail: (id: string) => request<RecoveryDetail>("GET", `/recovery/${id}`),
  grantRecovery: (
    id: string,
    words: string,
    keys: { prefix: string; version: number; wrappedKey: string }[],
  ) => request<{ ok: true; groups: string[] }>("POST", `/recovery/${id}/grant`, { words, keys }),
  cancelRecovery: (id: string, token: string) =>
    request<{ ok: true }>("POST", `/recovery/${id}/cancel`, { token }),

  // Backup and restore (ADR 23). The passphrase travels in a header only, never in the URL.
  downloadBackup: async (passphrase: string | undefined, fetchImpl?: FetchLike): Promise<Blob> => {
    const headers: Record<string, string> = { Accept: "application/octet-stream" };
    if (passphrase) headers["X-Backup-Passphrase"] = passphrase;
    const res = await send("GET", `${API_BASE}/backup`, undefined, fetchImpl, headers);
    return res.blob();
  },
  backupHistory: () => request<BackupHistory>("GET", "/backup/history"),
  restoreCheck: (file: Uint8Array, passphrase?: string, fetchImpl?: FetchLike) =>
    request<RestoreCheck>(
      "POST",
      "/restore/check",
      { file: toBase64(file) },
      fetchImpl,
      passphraseHeader(passphrase),
    ),
  restoreApply: (
    file: Uint8Array,
    confirmHost: string,
    passphrase?: string,
    fetchImpl?: FetchLike,
  ) =>
    request<{ ok: true; restoredAt: number; counts: RestoreCounts }>(
      "POST",
      "/restore",
      { file: toBase64(file), confirmHost },
      fetchImpl,
      passphraseHeader(passphrase),
    ),
};
