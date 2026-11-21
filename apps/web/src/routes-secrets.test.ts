import { describe, expect, it } from "vitest";
import { guardTarget, matchPage, pageCrumbs, pageTitle, SHELL_PAGES } from "./routes.ts";

// The secrets routes (ADR 24, part 2). Names contain slashes, so a tab is the suffix after the name.

describe("secret routes", () => {
  it("maps a secret name, with and without a tab, as one name", () => {
    expect(matchPage("/secrets/myapp/dev")).toEqual({ id: "secretDetail", name: "myapp/dev" });
    expect(matchPage("/secrets/backend/payments/prod/edit")).toEqual({
      id: "secretEdit",
      name: "backend/payments/prod",
    });
    expect(matchPage("/secrets/myapp/dev/versions")).toEqual({
      id: "secretVersions",
      name: "myapp/dev",
    });
    expect(matchPage("/secrets/myapp/dev/history/")).toEqual({
      id: "secretHistory",
      name: "myapp/dev",
    });
  });

  it("maps the fixed pages before any name", () => {
    expect(matchPage("/secrets/new").id).toBe("secretsNew");
    expect(matchPage("/secrets/import").id).toBe("secretsImport");
    expect(matchPage("/secrets/import/review").id).toBe("secretsImportReview");
    expect(matchPage("/secrets").id).toBe("secrets");
  });

  it("treats a bare tab suffix as not found", () => {
    expect(matchPage("/secrets/edit").id).toBe("secretDetail");
    expect(matchPage("/secrets/%E0%A4%A/edit").id).toBe("notFound");
  });

  it("gives every secret page the shell, so a locked vault goes to Unlock", () => {
    for (const id of [
      "secrets",
      "secretsNew",
      "secretsImport",
      "secretsImportReview",
      "secretDetail",
      "secretEdit",
      "secretVersions",
      "secretHistory",
    ] as const) {
      expect(SHELL_PAGES.has(id)).toBe(true);
      expect(guardTarget({ page: id, phase: "ready", vaultReady: true, unlocked: false })).toBe(
        "/unlock",
      );
      expect(
        guardTarget({ page: id, phase: "ready", vaultReady: true, unlocked: true }),
      ).toBeNull();
    }
  });

  it("follows the title rules: child pages end with their own title, a name is one crumb", () => {
    expect(pageTitle("secretDetail", "myapp/dev")).toBe("myapp/dev");
    expect(pageCrumbs("secretDetail", "myapp/dev").map((c) => c.label)).toEqual([
      "Secrets",
      "myapp/dev",
    ]);
    const edit = pageCrumbs("secretEdit", "myapp/dev");
    expect(edit.map((c) => c.label)).toEqual(["Secrets", "myapp/dev", "Edit"]);
    expect(pageTitle("secretEdit", "myapp/dev")).toBe("Edit");
    expect(pageTitle("secretVersions", "myapp/dev")).toBe("Versions");
    expect(pageTitle("secretHistory", "myapp/dev")).toBe("Access history");
    expect(pageTitle("secretsImportReview")).toBe("Review before saving");
    expect(pageCrumbs("secretsImportReview")[1]?.href).toBe("/secrets/import");
  });
});
