import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";
import { fillPage } from "../../../apps/extension/src/fill.ts";

const fixture = readFileSync(
  new URL("../../../apps/extension/test-fixtures/fill.html", import.meta.url),
  "utf8",
);

test("fills only visible top-frame fields without submitting or changing attributes", async ({
  page,
}) => {
  await page.route("http://localhost/fill.html", (route) =>
    route.fulfill({ contentType: "text/html", body: fixture }),
  );
  await page.route("**/frame.html", (route) =>
    route.fulfill({
      contentType: "text/html",
      body: '<input id="frame-password" type="password">',
    }),
  );
  await page.goto("http://localhost/fill.html");
  await page.evaluate(() =>
    document.querySelector("form")?.addEventListener("submit", (event) => {
      event.preventDefault();
      document.documentElement.dataset.submitted = "yes";
    }),
  );
  await page.addScriptTag({ content: `window.fillPage = ${fillPage.toString()}` });
  const runFill = (origin: string) =>
    page.evaluate(
      (expectedOrigin) =>
        (window as unknown as { fillPage: typeof fillPage }).fillPage(
          expectedOrigin,
          "alice",
          "secret-password",
        ),
      origin,
    );
  expect(await runFill("http://different.example")).toBe(0);
  expect(await runFill("http://localhost")).toBe(2);
  for (const id of ["hidden-field", "display", "visibility", "opacity", "zero"]) {
    await expect(page.locator(`#${id}`)).toHaveValue("");
  }
  await expect(page.locator("#user")).toHaveValue("alice");
  await expect(page.locator("#password")).toHaveValue("secret-password");
  for (const frame of page.frames().slice(1)) {
    await expect(frame.locator("#frame-password")).toHaveValue("");
    expect(
      await frame.evaluate((source) => {
        const fill = new Function(`return (${source})`)();
        return fill(location.origin, "alice", "secret-password");
      }, fillPage.toString()),
    ).toBe(0);
  }
  expect(await page.evaluate(() => document.documentElement.outerHTML)).not.toContain(
    "secret-password",
  );
  expect(await page.locator("html").getAttribute("data-submitted")).toBeNull();
});
