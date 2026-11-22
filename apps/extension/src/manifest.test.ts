import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const manifest = JSON.parse(
  readFileSync(new URL("../public/manifest.json", import.meta.url), "utf8"),
);
describe("extension permissions", () => {
  it("has only the required permissions and no always-on content script", () => {
    expect(manifest.manifest_version).toBe(3);
    expect(manifest.permissions.sort()).toEqual(["activeTab", "scripting", "storage"].sort());
    expect(manifest.optional_host_permissions).not.toContain("<all_urls>");
    expect(manifest.host_permissions).toBeUndefined();
    expect(manifest.content_scripts).toBeUndefined();
  });
});
