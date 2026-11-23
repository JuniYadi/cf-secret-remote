// Requires a running web app, an authenticated browser storage state, an unlocked vault password,
// and a group the user belongs to. The current CI browser job supplies none of these yet.
import { expect, test } from "@playwright/test";

const base = process.env.CFS_WEB_SMOKE_URL;
const password = process.env.CFS_WEB_SMOKE_PASSWORD;
const state = process.env.CFS_WEB_SMOKE_STORAGE_STATE;
const group = process.env.CFS_WEB_SMOKE_GROUP;
test.skip(!base || !password || !state || !group, "Web smoke environment is not configured");
test.use({ storageState: state });

test("create, reveal, TOTP and move a login", async ({ page }) => {
  await page.goto(`${base}/unlock`);
  await page.getByLabel("Vault password").fill(password ?? "");
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await page.getByRole("link", { name: "Logins", exact: true }).click();
  await page.getByRole("link", { name: "+ New login" }).click();
  await page.getByLabel("Name", { exact: true }).fill(`Smoke ${Date.now()}`);
  await page.getByLabel("Password", { exact: true }).fill("smoke-password");
  await page.getByLabel("TOTP seed or otpauth URI").fill("JBSWY3DPEHPK3PXP");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("Verification code")).toBeVisible();
  await page.getByRole("button", { name: "Show Password" }).click();
  await expect(page.getByText("smoke-password", { exact: true })).toBeVisible();
  await page.getByLabel("Move to group").selectOption({ label: group ?? "" });
  await page.getByRole("button", { name: "Move", exact: true }).click();
  await expect(
    page.getByLabel("Move to group").locator("option", { hasText: group ?? "" }),
  ).toHaveCount(0);
});
