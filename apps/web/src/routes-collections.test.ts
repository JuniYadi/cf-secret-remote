import { describe, expect, it } from "vitest";
import {
  guardTarget,
  matchPage,
  NAV_ITEMS,
  PATHS,
  pageCrumbs,
  pageTitle,
  SHELL_PAGES,
} from "./routes.ts";

// ADR 36: fixed and parameterised routes for collections, their crumbs, and the sidebar entry.

describe("collection routes", () => {
  it("maps the list, the new form, the detail and the edit form", () => {
    expect(matchPage("/collections")).toEqual({ id: "collections" });
    expect(matchPage("/collections/new")).toEqual({ id: "collectionNew" });
    expect(matchPage("/collections/myapp")).toEqual({ id: "collectionDetail", name: "myapp" });
    expect(matchPage("/collections/myapp/edit")).toEqual({ id: "collectionEdit", name: "myapp" });
    expect(matchPage("/collections/my%20app")).toEqual({ id: "collectionDetail", name: "my app" });
  });

  it("builds the links the screens use", () => {
    expect(PATHS.collections).toBe("/collections");
    expect(PATHS.collectionsNew).toBe("/collections/new");
  });

  it("uses the section and page crumbs, with the name as one crumb", () => {
    expect(pageCrumbs("collections")).toHaveLength(1);
    expect(pageTitle("collectionNew")).toBe("New collection");
    expect(pageCrumbs("collectionDetail", "myapp/dev")).toEqual([
      { label: "Collections", href: "/collections" },
      { label: "myapp/dev" },
    ]);
    expect(pageTitle("collectionDetail", "myapp")).toBe("myapp");
    expect(pageTitle("collectionEdit", "myapp")).toBe("Edit");
  });

  it("keeps every collection page in the signed-in shell and in the sidebar", () => {
    for (const id of [
      "collections",
      "collectionNew",
      "collectionDetail",
      "collectionEdit",
    ] as const) {
      expect(SHELL_PAGES.has(id), id).toBe(true);
    }
    expect(NAV_ITEMS.some((n) => n.path === PATHS.collections)).toBe(true);
    expect(
      guardTarget({ page: "collectionNew", phase: "ready", vaultReady: true, unlocked: false }),
    ).toBe("/unlock");
  });
});
