// @vitest-environment happy-dom

import { render } from "preact";
import { afterEach, expect, it, vi } from "vitest";
import { setLang } from "../lib/i18n.ts";
import { RecoveryKeyDownload } from "./RecoveryKeyDownload.tsx";

const host = document.createElement("div");

afterEach(() => {
  render(null, host);
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

it("downloads the recovery key in a text file and revokes its URL", async () => {
  setLang("en", undefined);
  const phrase = "anchor velvet kiwi sixty";
  const create = vi.fn((_blob: Blob) => "blob:recovery");
  const revoke = vi.fn();
  vi.stubGlobal(
    "URL",
    Object.assign(class extends URL {}, { createObjectURL: create, revokeObjectURL: revoke }),
  );
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
    expect(this.download).toMatch(/^cfs-recovery-key-\d{4}-\d{2}-\d{2}\.txt$/);
    expect(this.href).toBe("blob:recovery");
  });
  render(<RecoveryKeyDownload phrase={phrase} />, host);
  host.querySelector("button")?.click();
  expect(click).toHaveBeenCalledOnce();
  const blob = create.mock.calls[0]?.[0] as Blob;
  expect(blob.type).toBe("text/plain");
  expect(await blob.text()).toContain(phrase);
  expect(await blob.text()).toContain("keep these words safe");
  expect(revoke).not.toHaveBeenCalled();
  await new Promise((r) => setTimeout(r, 0));
  expect(revoke).toHaveBeenCalledWith("blob:recovery");
});
