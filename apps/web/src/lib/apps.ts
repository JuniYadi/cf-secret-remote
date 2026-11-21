// Apps and bots: the access kit and the create flow (ADR 15, DESIGN.md "Access kit").
//
// The key pair is made here, in the browser. Only the public key is sent. The private key goes into the kit
// string (cfskit1_...), which is shown once. It is held in one variable until the kit page reads it, and
// it is never stored, put in the URL, or logged.

import { decodeKit, encodeKit, generateKeyPair } from "@cfs/core";
import { type AppRow, api as realApi } from "./api.ts";
import { addPersonToGroup, type PersonKey } from "./groups.ts";
import { t } from "./i18n.ts";

export const NAME_MAX = 80;
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]*$/;

export interface KitParts {
  host: string;
  roleId: string;
  secretId: string;
  privateKey: string;
}

/** The one-line kit for CFS_KIT. The host is this page's origin, so the kit points at this server. */
export function buildKit(parts: KitParts): string {
  return encodeKit({
    host: parts.host,
    roleId: parts.roleId,
    secretId: parts.secretId,
    privateKey: parts.privateKey,
  });
}

/** This page's origin (https in production). Falls back to empty text outside a browser. */
export function kitHost(): string {
  return typeof window === "undefined" ? "" : window.location.origin;
}

// --- Shown once: the kit lives in this variable until the kit page takes it. ---

export interface HeldKit {
  appId: string;
  name: string;
  kit: string;
  problems: CreatedApp["problems"];
}

let held: HeldKit | null = null;

export function holdKit(created: CreatedApp): void {
  held = {
    appId: created.id,
    name: created.name,
    kit: created.kit,
    problems: created.problems,
  };
}

/** Returns the kit for this app and clears it. A second call, or a reload, gets null. */
export function takeKit(appId: string): HeldKit | null {
  if (held === null || held.appId !== appId) return null;
  const taken = held;
  held = null;
  return taken;
}

/** The download file name: the app name with unsafe characters replaced. Letters, digits, dots, dashes, underscores. */
export function kitFileName(name: string): string {
  const base = name
    .trim()
    .replace(/[^A-Za-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return `${base || "cfs"}.cfskit`;
}

/** Test helper: drops anything held. */
export function clearHeldKit(): void {
  held = null;
}

// --- Form rules ---

export const KIT_LIFE: readonly { days: number; en: string; id: string }[] = [
  { days: 14, en: "14 days", id: "14 hari" },
  { days: 30, en: "30 days", id: "30 hari" },
  { days: 90, en: "90 days", id: "90 hari" },
];

/** Token lifetime in seconds. The server accepts 60 to 86400. */
export const SESSION_LIFE: readonly { seconds: number; en: string; id: string }[] = [
  { seconds: 3600, en: "1 hour", id: "1 jam" },
  { seconds: 4 * 3600, en: "4 hours", id: "4 jam" },
  { seconds: 24 * 3600, en: "24 hours", id: "24 jam" },
];

export interface NewAppForm {
  name: string;
  sessionSeconds: number;
  kitDays: number;
  /** Empty means no limit. */
  maxUses: string;
  /** Comma-separated IPs or CIDR ranges. Empty means any network. */
  network: string;
  /** The permission set to give, or "" for none. */
  policyId: string;
  /** Group prefixes the app should be added to. */
  prefixes: string[];
}

export interface NewAppErrors {
  name?: "empty" | "shape" | "tooLong";
  maxUses?: "shape";
  network?: "shape";
}

export function validateNewApp(form: NewAppForm): { valid: boolean; errors: NewAppErrors } {
  const errors: NewAppErrors = {};
  const name = form.name.trim();
  if (name === "") errors.name = "empty";
  else if (name.length > NAME_MAX) errors.name = "tooLong";
  else if (!NAME_RE.test(name)) errors.name = "shape";

  const uses = form.maxUses.trim();
  if (uses !== "" && !(/^\d+$/.test(uses) && Number(uses) >= 1)) errors.maxUses = "shape";

  const net = form.network.trim();
  if (
    net !== "" &&
    !net.split(",").every((part) => /^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(part.trim()))
  )
    errors.network = "shape";

  return { valid: Object.keys(errors).length === 0, errors };
}

export function appErrorText(code: string): string {
  switch (code) {
    case "empty":
      return t("Give it a name.", "Beri nama.");
    case "tooLong":
      return t("Keep the name under 80 characters.", "Buat nama kurang dari 80 karakter.");
    case "shape":
      return t(
        "Use letters, numbers, spaces, dots, dashes or underscores, starting with a letter or number.",
        "Pakai huruf, angka, spasi, titik, tanda hubung, atau garis bawah, mulai dengan huruf atau angka.",
      );
    default:
      return t("Check this value.", "Periksa nilai ini.");
  }
}

export interface CreatedApp {
  id: string;
  name: string;
  kit: string;
  /** Steps that did not finish, e.g. a group the admin could not add the app to. Names only. */
  problems: { step: "permission" | "group"; target: string }[];
}

export interface CreateDeps {
  client?: typeof realApi;
  host?: string;
  now?: () => number;
  makeKeys?: typeof generateKeyPair;
  addToGroup?: (prefix: string, person: PersonKey) => Promise<void>;
}

/**
 * Creates the app or bot: key pair in the browser, POST /apps with the public key only, then the kit,
 * then the permission set and the groups. Group steps can fail on their own; their failures are reported
 * and the kit is still returned, because it is the only chance to copy it.
 */
export async function createApp(form: NewAppForm, deps: CreateDeps = {}): Promise<CreatedApp> {
  const client = deps.client ?? realApi;
  const makeKeys = deps.makeKeys ?? generateKeyPair;
  const now = deps.now ?? (() => Math.floor(Date.now() / 1000));
  const name = form.name.trim();

  const pair = await makeKeys();
  const uses = form.maxUses.trim();
  const net = form.network.trim();
  const created = await client.createApp({
    name,
    publicKey: pair.publicKey,
    tokenTtl: form.sessionSeconds,
    maxUses: uses === "" ? null : Number(uses),
    expiresAt: now() + form.kitDays * 86400,
    cidr: net === "" ? null : net,
  });

  const kit = buildKit({
    host: deps.host ?? kitHost(),
    roleId: created.roleId,
    secretId: created.secretId,
    privateKey: pair.privateKey,
  });
  const problems: CreatedApp["problems"] = [];

  if (form.policyId !== "") {
    try {
      await client.assignPolicy(form.policyId, created.id);
    } catch {
      problems.push({ step: "permission", target: form.policyId });
    }
  }
  const addToGroup =
    deps.addToGroup ?? ((prefix, person) => addPersonToGroup(prefix, person, client));
  for (const prefix of form.prefixes) {
    try {
      await addToGroup(prefix, { identityId: created.id, name, publicKey: pair.publicKey });
    } catch {
      problems.push({ step: "group", target: prefix });
    }
  }
  return { id: created.id, name, kit, problems };
}

/**
 * A new kit for an existing app. The server rotates secret_id and keeps the key pair, but it never kept the
 * private key. So the owner pastes the kit they saved: the browser reads the private key from it locally,
 * checks it is for this app, rotates the secret_id, and builds the new kit. The private key is not sent.
 */
export async function reissueKit(
  pasted: string,
  app: { id: string; name: string; roleId: string },
  deps: { client?: typeof realApi; host?: string } = {},
): Promise<CreatedApp> {
  const client = deps.client ?? realApi;
  let old: ReturnType<typeof decodeKit>;
  try {
    old = decodeKit(pasted.trim());
  } catch {
    throw new KitError("unreadable");
  }
  if (old.roleId !== app.roleId) throw new KitError("otherApp");
  const rotated = await client.rotateApp(app.id);
  const kit = buildKit({
    host: deps.host ?? kitHost(),
    roleId: rotated.roleId,
    secretId: rotated.secretId,
    privateKey: old.privateKey,
  });
  return { id: app.id, name: app.name, kit, problems: [] };
}

export class KitError extends Error {
  readonly code: "unreadable" | "otherApp";
  constructor(code: "unreadable" | "otherApp") {
    super(code);
    this.name = "KitError";
    this.code = code;
  }
}

/** The app's status as a label key, for the list and the detail header. */
export function appStatus(
  app: Pick<AppRow, "status" | "waiting">,
): "disabled" | "waiting" | "active" {
  if (app.status !== "active") return "disabled";
  return app.waiting ? "waiting" : "active";
}

/** Days left on the kit, rounded down, or null when there is no expiry. Never negative. */
export function daysLeft(expiresAt: number | null, nowSec: number): number | null {
  if (expiresAt === null) return null;
  return Math.max(0, Math.floor((expiresAt - nowSec) / 86400));
}
