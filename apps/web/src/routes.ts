// Routes, titles and the guard. Pure functions, so the rules are unit tested (routes.test.ts).
//
// Title rules (DESIGN.md, "Aturan judul dan breadcrumb"):
// - The last crumb is the page title, and it is the document <title>.
// - Main sections (Secrets, Groups, ...) have one crumb and no breadcrumb.
// - Child pages have the section first, e.g. "Secrets / myapp/prod / Access denied".
// - A name such as myapp/prod is one crumb, never split.
// - Single-task pages (sign in, vault setup, unlock) have one crumb and no breadcrumb.

import { GROUP_FIXED_NAMES, SECRET_FIXED_NAMES, SECRET_PAGE_SUFFIXES } from "@cfs/core";
import { t } from "./lib/i18n.ts";

export const PATHS = {
  secrets: "/secrets",
  logins: "/logins",
  loginsNew: "/logins/new",
  groups: "/groups",
  permissions: "/permissions",
  // ADR 36: environment collections (declared key names per environment).
  collections: "/collections",
  collectionsNew: "/collections/new",
  apps: "/apps",
  activity: "/activity",
  settings: "/settings",
  denied: "/denied",
  signIn: "/sign-in",
  sessionEnded: "/session-ended",
  setup: "/setup",
  setupRecovery: "/setup/recovery",
  unlock: "/unlock",
  forgot: "/forgot",
  recover: "/recover",
  alerts: "/activity/alerts",
  requests: "/permissions/requests",
  agentRules: "/apps/rules",
  devices: "/account/devices",
  cliAuthorize: "/cli/authorize",
  cliDone: "/cli/done",
  groupNew: `/groups/${GROUP_FIXED_NAMES.new}`,
  invite: "/invite",
  permNew: "/permissions/new",
  roleNew: "/permissions/roles/new",
  appNew: "/apps/new",
  secretsNew: `/secrets/${SECRET_FIXED_NAMES.new}`,
  secretsImport: `/secrets/${SECRET_FIXED_NAMES.import}`,
  secretsImportReview: `/secrets/${SECRET_FIXED_NAMES.importReview}`,
  // ADR 24 part 5: settings tabs, offboarding, give access again, account, quota, and "Was this you?".
  settingsAdmins: "/settings/admins",
  settingsBackup: "/settings/backup",
  restore: "/settings/backup/restore",
  offboard: `/groups/${GROUP_FIXED_NAMES.offboard}`,
  regrant: `/groups/${GROUP_FIXED_NAMES.regrant}`,
  password: "/account/password",
  quota: "/quota",
  wasYou: "/was-you",
} as const;

/** Suffixes of a secret's own pages. The secret name comes first: /secrets/myapp/dev/versions. */
export const SECRET_TABS = {
  edit: `/${SECRET_PAGE_SUFFIXES.edit}`,
  versions: `/${SECRET_PAGE_SUFFIXES.versions}`,
  history: `/${SECRET_PAGE_SUFFIXES.history}`,
} as const;

/** Paths with a name or id in them. Each is built with encodeURIComponent, so a slash stays inside one segment. */
/** Secret names keep their slashes in the path, like /secrets/<name>. Other characters are escaped. */
const encodeName = (name: string) => name.split("/").map(encodeURIComponent).join("/");
export const deniedPath = (name: string) => `${PATHS.denied}/${encodeName(name)}`;
/** The access request form, with the secret name filled in. */
export const askAccessPath = (name: string) => `${PATHS.requests}?path=${encodeURIComponent(name)}`;
export const groupPath = (prefix: string) => `${PATHS.groups}/${encodeURIComponent(prefix)}`;
export const groupAddPath = (prefix: string) => `${groupPath(prefix)}/add`;
export const groupRelockPath = (prefix: string) => `${groupPath(prefix)}/relock`;
export const appPath = (id: string) => `${PATHS.apps}/${encodeURIComponent(id)}`;
export const appKitPath = (id: string) => `${appPath(id)}/kit`;
export const collectionPath = (name: string) => `${PATHS.collections}/${encodeURIComponent(name)}`;
export const collectionEditPath = (name: string) => `${collectionPath(name)}/edit`;

export type PageId =
  | "root"
  | "secrets"
  | "logins"
  | "loginDetail"
  | "loginNew"
  | "loginEdit"
  | "groups"
  | "permissions"
  | "collections"
  | "collectionNew"
  | "collectionDetail"
  | "collectionEdit"
  | "apps"
  | "activity"
  | "settings"
  | "denied"
  | "signIn"
  | "sessionEnded"
  | "setup"
  | "setupRecovery"
  | "unlock"
  | "forgot"
  | "recover"
  | "alerts"
  | "requests"
  | "agentRules"
  | "devices"
  | "cliAuthorize"
  | "cliDone"
  | "notFound"
  | "secretsNew"
  | "secretsImport"
  | "secretsImportReview"
  | "secretDetail"
  | "secretEdit"
  | "secretVersions"
  | "secretHistory"
  | "groupNew"
  | "groupDetail"
  | "groupAdd"
  | "groupRelock"
  | "invite"
  | "permNew"
  | "roleNew"
  | "appNew"
  | "appDetail"
  | "appKit"
  | "settingsAdmins"
  | "settingsBackup"
  | "restore"
  | "offboard"
  | "regrant"
  | "password"
  | "quota"
  | "wasYou";

/** Pages inside the signed-in shell (sidebar and header). They need an unlocked vault. */
export const SHELL_PAGES: ReadonlySet<PageId> = new Set<PageId>([
  "secrets",
  "collections",
  "collectionNew",
  "collectionDetail",
  "collectionEdit",
  "logins",
  "loginDetail",
  "loginNew",
  "loginEdit",
  "groups",
  "permissions",
  "apps",
  "activity",
  "settings",
  "denied",
  "alerts",
  "requests",
  "agentRules",
  "devices",
  "secretsNew",
  "secretsImport",
  "secretsImportReview",
  "secretDetail",
  "secretEdit",
  "secretVersions",
  "secretHistory",
  "groupNew",
  "groupDetail",
  "groupAdd",
  "groupRelock",
  "invite",
  "permNew",
  "roleNew",
  "appNew",
  "appDetail",
  "appKit",
  "settingsAdmins",
  "settingsBackup",
  "restore",
  "offboard",
  "regrant",
  "password",
  "quota",
]);

export interface Crumb {
  label: string;
  href?: string;
}

export interface MatchedPage {
  id: PageId;
  /** For /denied/:name, the decoded name, such as myapp/prod. */
  name?: string;
}

const STATIC_PATHS: Readonly<Record<string, PageId>> = {
  "/": "root",
  [PATHS.secrets]: "secrets",
  [PATHS.logins]: "logins",
  [PATHS.loginsNew]: "loginNew",
  [PATHS.groups]: "groups",
  [PATHS.permissions]: "permissions",
  [PATHS.collections]: "collections",
  [PATHS.collectionsNew]: "collectionNew",
  [PATHS.apps]: "apps",
  [PATHS.activity]: "activity",
  [PATHS.settings]: "settings",
  [PATHS.signIn]: "signIn",
  [PATHS.sessionEnded]: "sessionEnded",
  [PATHS.setup]: "setup",
  [PATHS.setupRecovery]: "setupRecovery",
  [PATHS.unlock]: "unlock",
  [PATHS.forgot]: "forgot",
  [PATHS.recover]: "recover",
  [PATHS.alerts]: "alerts",
  [PATHS.requests]: "requests",
  [PATHS.agentRules]: "agentRules",
  [PATHS.devices]: "devices",
  [PATHS.cliAuthorize]: "cliAuthorize",
  [PATHS.cliDone]: "cliDone",
  [PATHS.secretsNew]: "secretsNew",
  [PATHS.secretsImport]: "secretsImport",
  [PATHS.secretsImportReview]: "secretsImportReview",
  [PATHS.groupNew]: "groupNew",
  [PATHS.invite]: "invite",
  [PATHS.permNew]: "permNew",
  [PATHS.roleNew]: "roleNew",
  [PATHS.appNew]: "appNew",
  [PATHS.settingsAdmins]: "settingsAdmins",
  [PATHS.settingsBackup]: "settingsBackup",
  [PATHS.restore]: "restore",
  [PATHS.offboard]: "offboard",
  [PATHS.regrant]: "regrant",
  [PATHS.password]: "password",
  [PATHS.quota]: "quota",
  [PATHS.wasYou]: "wasYou",
};

function decodeSegment(segment: string): string | undefined {
  try {
    const value = decodeURIComponent(segment);
    return value === "" ? undefined : value;
  } catch {
    return undefined;
  }
}

/** Parameterised paths, tried in order after the fixed ones. The first capture is the decoded name or id. */
const PARAM_PATHS: readonly { re: RegExp; id: PageId }[] = [
  { re: /^\/logins\/([^/]+)\/edit$/, id: "loginEdit" },
  { re: /^\/logins\/([^/]+)$/, id: "loginDetail" },
  { re: /^\/groups\/([^/]+)\/add$/, id: "groupAdd" },
  { re: /^\/groups\/([^/]+)\/relock$/, id: "groupRelock" },
  { re: /^\/groups\/([^/]+)$/, id: "groupDetail" },
  { re: /^\/collections\/([^/]+)\/edit$/, id: "collectionEdit" },
  { re: /^\/collections\/([^/]+)$/, id: "collectionDetail" },
  { re: /^\/apps\/([^/]+)\/kit$/, id: "appKit" },
  { re: /^\/apps\/([^/]+)$/, id: "appDetail" },
];

/** Maps a pathname to a page. Unknown paths map to notFound. Trailing slashes are ignored. */
export function matchPage(pathname: string): MatchedPage {
  const path = pathname.replace(/\/+$/, "") || "/";
  // The name is the rest of the path, so myapp/prod/db (raw slashes) and myapp%2Fprod both work.
  const denied = path.match(/^\/denied\/(.+)$/);
  if (denied?.[1] !== undefined) {
    const name = decodeSegment(denied[1]);
    return name ? { id: "denied", name } : { id: "notFound" };
  }
  // Give access again for one request: /groups/regrant/:id (the list is /groups/regrant).
  const regrant = path.match(new RegExp(`^/groups/${GROUP_FIXED_NAMES.regrant}/([^/]+)$`));
  if (regrant?.[1] !== undefined) {
    const id = decodeSegment(regrant[1]);
    return id ? { id: "regrant", name: id } : { id: "notFound" };
  }
  const fixed = STATIC_PATHS[path];
  if (fixed !== undefined) return { id: fixed };
  for (const { re, id } of PARAM_PATHS) {
    const found = path.match(re);
    if (found?.[1] !== undefined) {
      const name = decodeSegment(found[1]);
      return name ? { id, name } : { id: "notFound" };
    }
  }
  return matchSecretPage(path);
}

/** /secrets/<name> and its tabs. Names contain slashes, so the tab is the suffix after the name. */
function matchSecretPage(path: string): MatchedPage {
  const prefix = `${PATHS.secrets}/`;
  if (!path.startsWith(prefix)) return { id: "notFound" };
  const rest = path.slice(prefix.length);
  const tabs: [string, PageId][] = [
    [SECRET_TABS.edit, "secretEdit"],
    [SECRET_TABS.versions, "secretVersions"],
    [SECRET_TABS.history, "secretHistory"],
  ];
  for (const [suffix, id] of tabs) {
    if (rest.endsWith(suffix) && rest.length > suffix.length) {
      const name = decodeSegment(rest.slice(0, -suffix.length));
      return name ? { id, name } : { id: "notFound" };
    }
  }
  const name = decodeSegment(rest);
  return name ? { id: "secretDetail", name } : { id: "notFound" };
}

/** The crumbs for a page. The last one is the title. Empty for the root redirect. */
export function pageCrumbs(id: PageId, name?: string): Crumb[] {
  const secrets = { label: t("Secrets", "Secret"), href: PATHS.secrets };
  const activity = { label: t("Activity", "Aktivitas"), href: PATHS.activity };
  const groups = { label: t("Groups", "Grup"), href: PATHS.groups };
  const permissions = { label: t("Permissions", "Izin"), href: PATHS.permissions };
  const apps = { label: t("Apps & bots", "Aplikasi & bot"), href: PATHS.apps };
  switch (id) {
    case "root":
      return [];
    case "secrets":
      return [{ label: t("Secrets", "Secret"), href: PATHS.secrets }];
    case "logins":
      return [{ label: t("Logins", "Akun"), href: PATHS.logins }];
    case "loginDetail":
      return [{ label: t("Logins", "Akun"), href: PATHS.logins }, { label: t("Login", "Akun") }];
    case "loginNew":
      return [
        { label: t("Logins", "Akun"), href: PATHS.logins },
        { label: t("New login", "Akun baru") },
      ];
    case "loginEdit":
      return [
        { label: t("Logins", "Akun"), href: PATHS.logins },
        { label: t("Edit login", "Ubah akun") },
      ];
    case "groups":
      return [{ label: t("Groups", "Grup"), href: PATHS.groups }];
    case "permissions":
      return [{ label: t("Permissions", "Izin"), href: PATHS.permissions }];
    case "collections":
      return [{ label: t("Collections", "Koleksi"), href: PATHS.collections }];
    case "collectionNew":
      return [
        { label: t("Collections", "Koleksi"), href: PATHS.collections },
        { label: t("New collection", "Koleksi baru") },
      ];
    case "collectionDetail":
      return [
        { label: t("Collections", "Koleksi"), href: PATHS.collections },
        { label: name ?? "" },
      ];
    case "collectionEdit":
      return [
        { label: t("Collections", "Koleksi"), href: PATHS.collections },
        { label: name ?? "", href: collectionPath(name ?? "") },
        { label: t("Edit", "Ubah") },
      ];
    case "apps":
      return [{ label: t("Apps & bots", "Aplikasi & bot"), href: PATHS.apps }];
    case "activity":
      return [{ label: t("Activity", "Aktivitas"), href: PATHS.activity }];
    case "settings":
      return [{ label: t("Settings", "Pengaturan"), href: PATHS.settings }];
    case "denied":
      return [secrets, { label: name ?? "" }, { label: t("Access denied", "Akses ditolak") }];
    case "signIn":
      return [{ label: t("Sign in", "Masuk") }];
    case "sessionEnded":
      return [{ label: t("Your session ended", "Sesimu berakhir") }];
    case "setup":
      return [{ label: t("Create your vault password", "Buat vault password-mu") }];
    case "setupRecovery":
      return [{ label: t("Save your recovery key", "Simpan kunci pemulihanmu") }];
    case "unlock":
      return [{ label: t("Unlock your vault", "Buka vault-mu") }];
    case "forgot":
      return [{ label: t("Forgot your vault password?", "Lupa vault password?") }];
    case "recover":
      return [{ label: t("Use your recovery key", "Pakai kunci pemulihan") }];
    case "alerts":
      return [activity, { label: t("Alerts", "Peringatan") }];
    case "requests":
      return [permissions, { label: t("Access requests", "Permintaan akses") }];
    case "agentRules":
      return [apps, { label: t("Agent rules", "Aturan agen") }];
    case "devices":
      return [
        { label: t("Account", "Akun") },
        { label: t("Signed-in devices", "Perangkat yang masuk") },
      ];
    case "cliAuthorize":
      return [{ label: t("Authorize cfs", "Izinkan cfs") }];
    case "cliDone":
      return [{ label: t("You're signed in", "Kamu sudah masuk") }];
    case "settingsAdmins":
      return [
        { label: t("Settings", "Pengaturan"), href: PATHS.settings },
        { label: t("Admins", "Admin") },
      ];
    case "settingsBackup":
      return [
        { label: t("Settings", "Pengaturan"), href: PATHS.settings },
        { label: t("Backup", "Cadangan") },
      ];
    case "restore":
      return [
        { label: t("Settings", "Pengaturan"), href: PATHS.settings },
        { label: t("Backup", "Cadangan"), href: PATHS.settingsBackup },
        { label: t("Restore from a backup", "Pulihkan dari cadangan") },
      ];
    case "offboard":
      return [
        { label: t("Groups", "Grup"), href: PATHS.groups },
        { label: t("Offboard a teammate", "Keluarkan anggota") },
      ];
    case "regrant":
      return [
        { label: t("Groups", "Grup"), href: PATHS.groups },
        { label: t("Give access again", "Beri akses lagi") },
      ];
    case "password":
      return [
        { label: t("Account", "Akun") },
        { label: t("Change vault password", "Ganti vault password") },
      ];
    case "quota":
      return [{ label: t("Free plan limit reached", "Batas paket gratis tercapai") }];
    case "wasYou":
      return [{ label: t("Was this you?", "Apakah ini kamu?") }];
    case "notFound":
      return [{ label: t("Page not found", "Halaman tidak ditemukan") }];
    case "secretsNew":
      return [secrets, { label: t("New secret", "Secret baru") }];
    case "secretsImport":
      return [secrets, { label: t("Import a .env file", "Impor file .env") }];
    case "secretsImportReview":
      return [
        secrets,
        { label: t("Import a .env file", "Impor file .env"), href: PATHS.secretsImport },
        { label: t("Review before saving", "Tinjau sebelum menyimpan") },
      ];
    case "secretDetail":
      return [secrets, { label: name ?? "" }];
    case "secretEdit":
      return [secrets, { label: name ?? "", href: secretHref(name) }, { label: t("Edit", "Ubah") }];
    case "secretVersions":
      return [
        secrets,
        { label: name ?? "", href: secretHref(name) },
        { label: t("Versions", "Versi") },
      ];
    case "secretHistory":
      return [
        secrets,
        { label: name ?? "", href: secretHref(name) },
        { label: t("Access history", "Riwayat akses") },
      ];
    case "groupNew":
      return [groups, { label: t("New group", "Grup baru") }];
    case "groupDetail":
      return [groups, { label: name ?? "" }];
    case "groupAdd":
      return [groups, { label: t("Add member", "Tambah anggota") }];
    case "groupRelock":
      return [groups, { label: t(`Re-locking ${name ?? ""}`, `Mengunci ulang ${name ?? ""}`) }];
    case "invite":
      return [groups, { label: t("Invite a teammate", "Undang anggota baru") }];
    case "permNew":
      return [permissions, { label: t("New permission set", "Set izin baru") }];
    case "roleNew":
      return [permissions, { label: t("New role", "Peran baru") }];
    case "appNew":
      return [apps, { label: t("New app or bot", "Aplikasi atau bot baru") }];
    case "appDetail":
      return [apps, { label: name ?? "" }];
    case "appKit":
      return [
        apps,
        { label: name ?? "" },
        { label: t(`Kit for ${name ?? ""}`, `Kit untuk ${name ?? ""}`) },
      ];
  }
}

/** The link to a secret's own page. The name is one crumb and is never split (DESIGN.md rule 3). */
export const secretHref = (name?: string): string => `${PATHS.secrets}/${name ?? ""}`;

/** The document title and the h1 are the same text. */
export function pageTitle(id: PageId, name?: string): string {
  const crumbs = pageCrumbs(id, name);
  return crumbs[crumbs.length - 1]?.label ?? "cfs";
}

export interface NavItem {
  path: string;
  label: () => string;
  /** The sidebar icon, as a key for the icon component. */
  icon: "secrets" | "groups" | "permissions" | "apps" | "activity" | "devices" | "settings";
}

export const NAV_ITEMS: readonly NavItem[] = [
  { path: PATHS.secrets, label: () => t("Secrets", "Secret"), icon: "secrets" },
  { path: PATHS.logins, label: () => t("Logins", "Akun"), icon: "secrets" },
  { path: PATHS.groups, label: () => t("Groups", "Grup"), icon: "groups" },
  { path: PATHS.permissions, label: () => t("Permissions", "Izin"), icon: "permissions" },
  { path: PATHS.collections, label: () => t("Collections", "Koleksi"), icon: "groups" },
  { path: PATHS.apps, label: () => t("Apps & bots", "Aplikasi & bot"), icon: "apps" },
  { path: PATHS.activity, label: () => t("Activity", "Aktivitas"), icon: "activity" },
  { path: PATHS.devices, label: () => t("Devices", "Perangkat"), icon: "devices" },
  { path: PATHS.settings, label: () => t("Settings", "Pengaturan"), icon: "settings" },
];

export interface GuardInput {
  page: PageId;
  phase: "loading" | "signed-out" | "error" | "ready";
  vaultReady: boolean;
  unlocked: boolean;
}

/**
 * Where the person must go instead of the current page, or null to stay.
 * Public pages (sign in, session ended, help) never redirect. Shell pages need an unlocked vault.
 */
export function guardTarget(input: GuardInput): string | null {
  const { page, phase, vaultReady, unlocked } = input;
  if (page === "root") return PATHS.secrets;
  // A person whose session is live must not stay on these pages (for example a reloaded /session-ended URL
  // from before they signed in); go on to the app, which sends them to setup or unlock.
  if ((page === "signIn" || page === "sessionEnded") && phase === "ready") return PATHS.secrets;
  if (
    page === "signIn" ||
    page === "sessionEnded" ||
    page === "forgot" ||
    page === "recover" ||
    page === "wasYou"
  ) {
    return null;
  }
  if (page === "notFound") return null;
  if (phase === "loading" || phase === "error") return null;
  if (phase === "signed-out") return PATHS.sessionEnded;
  // Authorizing a terminal needs a signed-in person, not an unlocked vault (ADR 11).
  if (page === "cliAuthorize" || page === "cliDone") return null;

  if (!vaultReady) {
    if (page === "setup") return null;
    if (page === "setupRecovery" && unlocked) return null;
    return PATHS.setup;
  }
  if (page === "setup") return unlocked ? PATHS.secrets : PATHS.unlock;
  if (page === "setupRecovery") return unlocked ? null : PATHS.unlock;
  if (page === "unlock") return unlocked ? PATHS.secrets : null;
  return unlocked ? null : PATHS.unlock;
}
