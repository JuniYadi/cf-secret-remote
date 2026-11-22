import { afterEach, describe, expect, it } from "vitest";
import { setLang } from "./lib/i18n.ts";
import {
  guardTarget,
  matchPage,
  PATHS,
  type PageId,
  pageCrumbs,
  pageTitle,
  SHELL_PAGES,
} from "./routes.ts";

afterEach(() => setLang("en", undefined));

const ALL_PAGES: PageId[] = [
  "secrets",
  "groups",
  "permissions",
  "apps",
  "activity",
  "settings",
  "denied",
  "signIn",
  "sessionEnded",
  "setup",
  "setupRecovery",
  "unlock",
  "forgot",
  "recover",
  "notFound",
];

describe("title and breadcrumb rules (DESIGN.md)", () => {
  it("main sections have a single crumb and no breadcrumb", () => {
    for (const id of [
      "secrets",
      "groups",
      "permissions",
      "apps",
      "activity",
      "settings",
    ] as const) {
      expect(pageCrumbs(id)).toHaveLength(1);
    }
    expect(pageTitle("secrets")).toBe("Secrets");
    expect(pageTitle("apps")).toBe("Apps & bots");
  });

  it("the last crumb is the title for every page", () => {
    for (const id of ALL_PAGES) {
      const crumbs = pageCrumbs(id, "myapp/prod");
      expect(crumbs[crumbs.length - 1]?.label).toBe(pageTitle(id, "myapp/prod"));
    }
  });

  it("access denied is a child page: section, name, then the title", () => {
    const crumbs = pageCrumbs("denied", "myapp/prod");
    expect(crumbs.map((c) => c.label)).toEqual(["Secrets", "myapp/prod", "Access denied"]);
    expect(crumbs[0]?.href).toBe(PATHS.secrets);
    expect(pageTitle("denied", "myapp/prod")).toBe("Access denied");
  });

  it("a name with a slash stays one crumb", () => {
    expect(pageCrumbs("denied", "backend/payments/dev")).toHaveLength(3);
  });

  it("single-task pages have one crumb", () => {
    for (const id of ["signIn", "setup", "setupRecovery", "unlock", "sessionEnded"] as const) {
      expect(pageCrumbs(id)).toHaveLength(1);
    }
    expect(pageTitle("setup")).toBe("Create your vault password");
    expect(pageTitle("unlock")).toBe("Unlock your vault");
    expect(pageTitle("sessionEnded")).toBe("Your session ended");
  });

  it("titles follow the language", () => {
    setLang("id", undefined);
    expect(pageTitle("groups")).toBe("Grup");
    expect(pageTitle("signIn")).toBe("Masuk");
    expect(pageCrumbs("denied", "x").map((c) => c.label)).toEqual(["Secret", "x", "Akses ditolak"]);
  });
});

describe("matchPage", () => {
  it("maps every fixed path", () => {
    expect(matchPage("/secrets").id).toBe("secrets");
    expect(matchPage("/setup/recovery").id).toBe("setupRecovery");
    expect(matchPage("/unlock").id).toBe("unlock");
    expect(matchPage("/").id).toBe("root");
  });

  it("ignores trailing slashes", () => {
    expect(matchPage("/unlock/").id).toBe("unlock");
  });

  it("decodes the name in /denied/:name", () => {
    expect(matchPage("/denied/myapp%2Fprod")).toEqual({ id: "denied", name: "myapp/prod" });
  });

  it("treats a broken encoding or a missing name as not found", () => {
    expect(matchPage("/denied/%E0%A4%A").id).toBe("notFound");
    expect(matchPage("/denied").id).toBe("notFound");
    expect(matchPage("/nope").id).toBe("notFound");
  });

  it("every shell page is in SHELL_PAGES", () => {
    expect(SHELL_PAGES.has("secrets")).toBe(true);
    expect(SHELL_PAGES.has("unlock")).toBe(false);
  });
});

describe("guardTarget", () => {
  const base = { phase: "ready" as const, vaultReady: true, unlocked: true };

  it("sends the root to Secrets", () => {
    expect(guardTarget({ ...base, page: "root" })).toBe(PATHS.secrets);
  });

  it("keeps shell pages behind the unlock", () => {
    expect(guardTarget({ ...base, unlocked: false, page: "secrets" })).toBe(PATHS.unlock);
    expect(guardTarget({ ...base, page: "secrets" })).toBeNull();
    expect(guardTarget({ ...base, unlocked: false, page: "denied" })).toBe(PATHS.unlock);
  });

  it("sends a locked vault with no setup to setup", () => {
    expect(
      guardTarget({ phase: "ready", vaultReady: false, unlocked: false, page: "unlock" }),
    ).toBe(PATHS.setup);
    expect(
      guardTarget({ phase: "ready", vaultReady: false, unlocked: false, page: "secrets" }),
    ).toBe(PATHS.setup);
  });

  it("lets setup run, and the recovery step only after the vault is unlocked", () => {
    expect(
      guardTarget({ phase: "ready", vaultReady: false, unlocked: false, page: "setup" }),
    ).toBeNull();
    expect(
      guardTarget({ phase: "ready", vaultReady: false, unlocked: false, page: "setupRecovery" }),
    ).toBe(PATHS.setup);
    expect(
      guardTarget({ phase: "ready", vaultReady: true, unlocked: true, page: "setupRecovery" }),
    ).toBeNull();
  });

  it("does not show the unlock or setup screens to an unlocked person", () => {
    expect(guardTarget({ ...base, page: "unlock" })).toBe(PATHS.secrets);
    expect(guardTarget({ ...base, page: "setup" })).toBe(PATHS.secrets);
  });

  it("leaves Sign in and Session ended once the session is live (a stale URL must not trap a signed-in person)", () => {
    for (const page of ["signIn", "sessionEnded"] as const) {
      // Signed in: go on to the app, which then sends the person to setup or unlock.
      expect(guardTarget({ ...base, page })).toBe(PATHS.secrets);
      expect(guardTarget({ ...base, vaultReady: false, unlocked: false, page })).toBe(
        PATHS.secrets,
      );
      // Not signed in, still loading, or a load error: stay, so the person sees the page.
      expect(guardTarget({ ...base, phase: "signed-out", page })).toBeNull();
      expect(guardTarget({ ...base, phase: "loading", page })).toBeNull();
      expect(guardTarget({ ...base, phase: "error", page })).toBeNull();
    }
  });

  it("sends a signed-out person to Session ended, but not for public pages", () => {
    const out = { phase: "signed-out" as const, vaultReady: false, unlocked: false };
    expect(guardTarget({ ...out, page: "secrets" })).toBe(PATHS.sessionEnded);
    expect(guardTarget({ ...out, page: "signIn" })).toBeNull();
    expect(guardTarget({ ...out, page: "sessionEnded" })).toBeNull();
  });

  it("waits while loading and on error", () => {
    for (const phase of ["loading", "error"] as const) {
      expect(
        guardTarget({ phase, vaultReady: false, unlocked: false, page: "secrets" }),
      ).toBeNull();
    }
  });

  it("public help pages never redirect", () => {
    for (const page of ["forgot", "recover", "notFound"] as const) {
      expect(
        guardTarget({ phase: "loading", vaultReady: false, unlocked: false, page }),
      ).toBeNull();
      expect(guardTarget({ phase: "ready", vaultReady: true, unlocked: false, page })).toBeNull();
    }
  });
});
