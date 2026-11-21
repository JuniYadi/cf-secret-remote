// Routes, titles and the guard. Pure functions, so the rules are unit tested (routes.test.ts).
//
// Title rules (DESIGN.md, "Aturan judul dan breadcrumb"):
// - The last crumb is the page title, and it is the document <title>.
// - Main sections (Secrets, Groups, ...) have one crumb and no breadcrumb.
// - Child pages have the section first, e.g. "Secrets / myapp/prod / Access denied".
// - A name such as myapp/prod is one crumb, never split.
// - Single-task pages (sign in, vault setup, unlock) have one crumb and no breadcrumb.

import { t } from "./lib/i18n.ts";

export const PATHS = {
  secrets: "/secrets",
  groups: "/groups",
  permissions: "/permissions",
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
} as const;

export type PageId =
  | "root"
  | "secrets"
  | "groups"
  | "permissions"
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
  | "notFound";

/** Pages inside the signed-in shell (sidebar and header). They need an unlocked vault. */
export const SHELL_PAGES: ReadonlySet<PageId> = new Set<PageId>([
  "secrets",
  "groups",
  "permissions",
  "apps",
  "activity",
  "settings",
  "denied",
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
  [PATHS.groups]: "groups",
  [PATHS.permissions]: "permissions",
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
};

function decodeSegment(segment: string): string | undefined {
  try {
    const value = decodeURIComponent(segment);
    return value === "" ? undefined : value;
  } catch {
    return undefined;
  }
}

/** Maps a pathname to a page. Unknown paths map to notFound. Trailing slashes are ignored. */
export function matchPage(pathname: string): MatchedPage {
  const path = pathname.replace(/\/+$/, "") || "/";
  const denied = path.match(/^\/denied\/([^/]+)$/);
  if (denied?.[1] !== undefined) {
    const name = decodeSegment(denied[1]);
    return name ? { id: "denied", name } : { id: "notFound" };
  }
  return { id: STATIC_PATHS[path] ?? "notFound" };
}

/** The crumbs for a page. The last one is the title. Empty for the root redirect. */
export function pageCrumbs(id: PageId, name?: string): Crumb[] {
  const secrets = { label: t("Secrets", "Secret"), href: PATHS.secrets };
  switch (id) {
    case "root":
      return [];
    case "secrets":
      return [{ label: t("Secrets", "Secret"), href: PATHS.secrets }];
    case "groups":
      return [{ label: t("Groups", "Grup"), href: PATHS.groups }];
    case "permissions":
      return [{ label: t("Permissions", "Izin"), href: PATHS.permissions }];
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
      return [{ label: t("Forgot password", "Lupa password") }];
    case "recover":
      return [{ label: t("Use your recovery key", "Pakai kunci pemulihan") }];
    case "notFound":
      return [{ label: t("Page not found", "Halaman tidak ditemukan") }];
  }
}

/** The document title and the h1 are the same text. */
export function pageTitle(id: PageId, name?: string): string {
  const crumbs = pageCrumbs(id, name);
  return crumbs[crumbs.length - 1]?.label ?? "cfs";
}

export interface NavItem {
  path: string;
  label: () => string;
  /** The sidebar icon, as a key for the icon component. */
  icon: "secrets" | "groups" | "permissions" | "apps" | "activity" | "settings";
}

export const NAV_ITEMS: readonly NavItem[] = [
  { path: PATHS.secrets, label: () => t("Secrets", "Secret"), icon: "secrets" },
  { path: PATHS.groups, label: () => t("Groups", "Grup"), icon: "groups" },
  { path: PATHS.permissions, label: () => t("Permissions", "Izin"), icon: "permissions" },
  { path: PATHS.apps, label: () => t("Apps & bots", "Aplikasi & bot"), icon: "apps" },
  { path: PATHS.activity, label: () => t("Activity", "Aktivitas"), icon: "activity" },
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
  if (page === "signIn" || page === "sessionEnded" || page === "forgot" || page === "recover") {
    return null;
  }
  if (page === "notFound") return null;
  if (phase === "loading" || phase === "error") return null;
  if (phase === "signed-out") return PATHS.sessionEnded;

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
