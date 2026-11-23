import { expect, test } from "@playwright/test";

test("sign in, unlock and see the secrets list", async ({ page }) => {
  await page.route("**/api/v1/whoami", (route) => route.fulfill({ status: 401, body: "{}" }));
  await page.goto("/sign-in");
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await page.unrouteAll({ behavior: "wait" });
  await page.getByRole("link", { name: "Sign in with your work account" }).click();
  await expect(page.getByRole("heading", { name: "Unlock" })).toBeVisible();
  await page.getByLabel("Vault password").fill(process.env.CFS_BROWSER_PASSWORD ?? "");
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Secrets", exact: true })).toBeVisible();
  await expect(page.getByText("team/dev", { exact: true })).toBeVisible();
});
