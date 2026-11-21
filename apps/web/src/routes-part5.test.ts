import { afterEach, describe, expect, it } from "vitest";
import { setLang } from "./lib/i18n.ts";
import { guardTarget, matchPage, PATHS, pageCrumbs, pageTitle, SHELL_PAGES } from "./routes.ts";

// Routes added by ADR 24 part 5 (settings tabs, offboarding, give access again, recovery, quota).

afterEach(() => setLang("en", undefined));

describe("part 5 routes", () => {
  it("maps the settings tabs, account, quota and the recovery pages", () => {
    expect(matchPage("/settings/admins").id).toBe("settingsAdmins");
    expect(matchPage("/settings/backup").id).toBe("settingsBackup");
    expect(matchPage("/settings/backup/restore").id).toBe("restore");
    expect(matchPage("/groups/offboard").id).toBe("offboard");
    expect(matchPage("/account/password").id).toBe("password");
    expect(matchPage("/quota").id).toBe("quota");
    expect(matchPage("/was-you").id).toBe("wasYou");
  });

  it("maps /groups/regrant to the list, and /groups/regrant/:id to one request", () => {
    expect(matchPage("/groups/regrant")).toEqual({ id: "regrant" });
    expect(matchPage("/groups/regrant/abc123")).toEqual({ id: "regrant", name: "abc123" });
    expect(matchPage("/groups/regrant/a%2Fb")).toEqual({ id: "regrant", name: "a/b" });
  });

  it("settings tab pages keep the Settings section and the backup crumb (DESIGN.md title rules)", () => {
    expect(pageCrumbs("settingsAdmins").map((c) => c.label)).toEqual(["Settings", "Admins"]);
    expect(pageCrumbs("restore").map((c) => c.label)).toEqual([
      "Settings",
      "Backup",
      "Restore from a backup",
    ]);
    expect(pageCrumbs("restore")[1]?.href).toBe(PATHS.settingsBackup);
    expect(pageTitle("restore")).toBe("Restore from a backup");
  });

  it("the account and single-task pages have the right crumbs", () => {
    expect(pageTitle("password")).toBe("Change vault password");
    expect(pageCrumbs("password")[0]?.label).toBe("Account");
    expect(pageTitle("quota")).toBe("Free plan limit reached");
    expect(pageCrumbs("quota")).toHaveLength(1);
    expect(pageTitle("wasYou")).toBe("Was this you?");
    expect(pageCrumbs("wasYou")).toHaveLength(1);
    expect(pageTitle("forgot")).toBe("Forgot your vault password?");
  });

  it("the shell pages need an unlocked vault, and Was this you? does not", () => {
    for (const id of [
      "settingsAdmins",
      "settingsBackup",
      "restore",
      "offboard",
      "regrant",
      "password",
      "quota",
    ] as const) {
      expect(SHELL_PAGES.has(id)).toBe(true);
    }
    expect(SHELL_PAGES.has("wasYou")).toBe(false);
    expect(
      guardTarget({ page: "wasYou", phase: "ready", vaultReady: true, unlocked: false }),
    ).toBeNull();
    expect(
      guardTarget({ page: "restore", phase: "ready", vaultReady: true, unlocked: false }),
    ).toBe(PATHS.unlock);
  });

  it("the titles follow the language", () => {
    setLang("id", undefined);
    expect(pageTitle("restore")).toBe("Pulihkan dari cadangan");
    expect(pageTitle("quota")).toBe("Batas paket gratis tercapai");
  });
});
