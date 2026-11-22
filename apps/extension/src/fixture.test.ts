// @vitest-environment happy-dom
import { readFileSync } from "node:fs";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fillPage } from "./fill.ts";

beforeEach(() => {
  document.body.innerHTML = readFileSync("test-fixtures/fill.html", "utf8").replace(
    /<iframe[^>]*><\/iframe>/,
    "",
  );
  vi.stubGlobal("location", new URL("https://shop.com/login"));
  vi.stubGlobal("top", window);
  vi.stubGlobal("getComputedStyle", (element: HTMLElement) => ({
    display: element.style.display || "block",
    visibility: "visible",
    opacity: "1",
  }));
  vi.spyOn(HTMLInputElement.prototype, "getClientRects").mockImplementation(function (
    this: HTMLInputElement,
  ) {
    return (this.id === "zero" ? [] : [{}]) as unknown as DOMRectList;
  });
  vi.spyOn(HTMLInputElement.prototype, "getBoundingClientRect").mockReturnValue({
    width: 10,
    height: 10,
  } as DOMRect);
});
describe("fill fixture", () => {
  it("fills only visible top-frame fields without setting attributes or submitting", () => {
    const password = document.querySelector<HTMLInputElement>("#password") as HTMLInputElement;
    const input = vi.fn();
    const change = vi.fn();
    password.addEventListener("input", input);
    password.addEventListener("change", change);
    expect(fillPage("https://shop.com", "person", "secret")).toBe(2);
    expect((document.querySelector("#user") as HTMLInputElement).value).toBe("person");
    expect(password.value).toBe("secret");
    expect(password.getAttribute("value")).toBeNull();
    expect((document.querySelector("#invisible") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#zero") as HTMLInputElement).value).toBe("");
    expect(input).toHaveBeenCalledOnce();
    expect(change).toHaveBeenCalledOnce();
  });
  it("rejects a changed origin and a cross-origin frame", () => {
    expect(fillPage("https://other.example", "person", "secret")).toBe(0);
    vi.stubGlobal("top", {});
    expect(fillPage("https://shop.com", "person", "secret")).toBe(0);
  });
});
