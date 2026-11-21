import { afterEach, describe, expect, it } from "vitest";
import { setLang } from "./lib/i18n.ts";
import { guardTarget, matchPage, PATHS, pageCrumbs, pageTitle, SHELL_PAGES } from "./routes.ts";

afterEach(() => setLang("en", undefined));

describe("routes for ADR 24 part 4", () => {
  it("matches each new path to its page", () => {
    expect(matchPage(PATHS.alerts).id).toBe("alerts");
    expect(matchPage(PATHS.requests).id).toBe("requests");
    expect(matchPage(PATHS.agentRules).id).toBe("agentRules");
    expect(matchPage(PATHS.devices).id).toBe("devices");
    expect(matchPage("/cli/authorize").id).toBe("cliAuthorize");
    expect(matchPage("/cli/done").id).toBe("cliDone");
  });

  it("puts the signed-in pages in the shell and keeps the CLI pages out of it", () => {
    for (const id of ["alerts", "requests", "agentRules", "devices"] as const) {
      expect(SHELL_PAGES.has(id)).toBe(true);
    }
    expect(SHELL_PAGES.has("cliAuthorize")).toBe(false);
    expect(SHELL_PAGES.has("cliDone")).toBe(false);
  });

  it("uses Section / Tab crumbs, and the last crumb is the title", () => {
    expect(pageCrumbs("alerts").map((c) => c.label)).toEqual(["Activity", "Alerts"]);
    expect(pageTitle("alerts")).toBe("Alerts");
    expect(pageCrumbs("requests").map((c) => c.label)).toEqual(["Permissions", "Access requests"]);
    expect(pageCrumbs("agentRules").map((c) => c.label)).toEqual(["Apps & bots", "Agent rules"]);
    expect(pageCrumbs("devices").map((c) => c.label)).toEqual(["Account", "Signed-in devices"]);
  });

  it("has no breadcrumb on the one-task CLI pages", () => {
    expect(pageCrumbs("cliAuthorize")).toHaveLength(1);
    expect(pageTitle("cliAuthorize")).toBe("Authorize cfs");
    expect(pageTitle("cliDone")).toBe("You're signed in");
  });

  it("gives the Indonesian crumbs with the language choice", () => {
    setLang("id", undefined);
    expect(pageTitle("devices")).toBe("Perangkat yang masuk");
    expect(pageCrumbs("alerts")[0]?.label).toBe("Aktivitas");
  });

  it("lets the CLI pages open with a signed-in person and no unlocked vault", () => {
    const base = { phase: "ready" as const, vaultReady: true, unlocked: false };
    expect(guardTarget({ page: "cliAuthorize", ...base })).toBeNull();
    expect(guardTarget({ page: "cliDone", ...base })).toBeNull();
    // The shell pages still need an unlocked vault.
    expect(guardTarget({ page: "requests", ...base })).toBe(PATHS.unlock);
  });

  it("sends a signed-out person from the CLI page to the session-ended page", () => {
    expect(
      guardTarget({
        page: "cliAuthorize",
        phase: "signed-out",
        vaultReady: false,
        unlocked: false,
      }),
    ).toBe(PATHS.sessionEnded);
  });
});
