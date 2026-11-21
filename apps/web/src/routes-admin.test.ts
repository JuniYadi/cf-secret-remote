import { afterEach, describe, expect, it } from "vitest";
import { setLang } from "./lib/i18n.ts";
import {
  appKitPath,
  appPath,
  groupAddPath,
  groupPath,
  groupRelockPath,
  matchPage,
  PATHS,
  pageCrumbs,
  pageTitle,
  SHELL_PAGES,
} from "./routes.ts";

// Routes for the groups, permissions, and apps and bots part (ADR 24, part 3). Rules from DESIGN.md.

afterEach(() => setLang("en", undefined));

describe("matching the new paths", () => {
  it("matches the fixed pages before the parameterised ones", () => {
    expect(matchPage("/groups/new")).toEqual({ id: "groupNew" });
    expect(matchPage("/permissions/new")).toEqual({ id: "permNew" });
    expect(matchPage("/permissions/roles/new")).toEqual({ id: "roleNew" });
    expect(matchPage("/apps/new")).toEqual({ id: "appNew" });
    expect(matchPage("/invite")).toEqual({ id: "invite" });
  });

  it("reads the group and app name or id from the path, decoded", () => {
    expect(matchPage("/groups/data")).toEqual({ id: "groupDetail", name: "data" });
    expect(matchPage("/groups/data/add")).toEqual({ id: "groupAdd", name: "data" });
    expect(matchPage("/groups/data/relock")).toEqual({ id: "groupRelock", name: "data" });
    expect(matchPage("/apps/abc123")).toEqual({ id: "appDetail", name: "abc123" });
    expect(matchPage("/apps/abc123/kit")).toEqual({ id: "appKit", name: "abc123" });
  });

  it("round-trips the path builders", () => {
    expect(matchPage(groupPath("data"))).toEqual({ id: "groupDetail", name: "data" });
    expect(matchPage(groupAddPath("data"))).toEqual({ id: "groupAdd", name: "data" });
    expect(matchPage(groupRelockPath("data"))).toEqual({ id: "groupRelock", name: "data" });
    expect(matchPage(appPath("a 1"))).toEqual({ id: "appDetail", name: "a 1" });
    expect(matchPage(appKitPath("a1"))).toEqual({ id: "appKit", name: "a1" });
  });

  it("keeps unknown and empty segments on the not-found page", () => {
    expect(matchPage("/groups/data/unknown")).toEqual({ id: "notFound" });
    expect(matchPage("/apps/a/b/c")).toEqual({ id: "notFound" });
  });

  it("every new page is a shell page, so it needs an unlocked vault", () => {
    for (const id of [
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
    ] as const) {
      expect(SHELL_PAGES.has(id), id).toBe(true);
    }
  });

  it("keeps the new fixed paths in PATHS", () => {
    expect(PATHS.groupNew).toBe("/groups/new");
    expect(PATHS.appNew).toBe("/apps/new");
  });
});

describe("titles and breadcrumbs for the new pages (DESIGN.md)", () => {
  it("a group is one crumb, under the Groups section", () => {
    expect(pageCrumbs("groupDetail", "data/prod").map((c) => c.label)).toEqual([
      "Groups",
      "data/prod",
    ]);
    expect(pageTitle("groupDetail", "data/prod")).toBe("data/prod");
  });

  it("child pages end with their own title", () => {
    expect(pageCrumbs("groupAdd", "data").map((c) => c.label)).toEqual(["Groups", "Add member"]);
    expect(pageCrumbs("groupNew").map((c) => c.label)).toEqual(["Groups", "New group"]);
    expect(pageCrumbs("invite").map((c) => c.label)).toEqual(["Groups", "Invite a teammate"]);
    expect(pageCrumbs("permNew").map((c) => c.label)).toEqual([
      "Permissions",
      "New permission set",
    ]);
    expect(pageCrumbs("roleNew").map((c) => c.label)).toEqual(["Permissions", "New role"]);
    expect(pageCrumbs("appNew").map((c) => c.label)).toEqual(["Apps & bots", "New app or bot"]);
  });

  it("the app page is named after the app, and its kit page is a third crumb", () => {
    expect(pageCrumbs("appDetail", "agent-billing").map((c) => c.label)).toEqual([
      "Apps & bots",
      "agent-billing",
    ]);
    expect(pageCrumbs("appKit", "agent-billing").map((c) => c.label)).toEqual([
      "Apps & bots",
      "agent-billing",
      "Kit for agent-billing",
    ]);
  });

  it("the last crumb is the title for every new page", () => {
    for (const id of ["groupRelock", "appKit", "groupDetail", "roleNew"] as const) {
      const crumbs = pageCrumbs(id, "data");
      expect(crumbs[crumbs.length - 1]?.label).toBe(pageTitle(id, "data"));
    }
  });

  it("uses the Indonesian text when the language is ID", () => {
    setLang("id", undefined);
    expect(pageTitle("groupNew")).toBe("Grup baru");
    expect(pageTitle("appKit", "agent-billing")).toBe("Kit untuk agent-billing");
  });
});
