import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import { mkdir } from "node:fs/promises";

async function signIn(page: Page, username = "aurora-security") {
  const password = process.env.DEMO_PASSWORD;
  if (!password) throw new Error("Source .local/secrets.env before running browser tests.");
  await page.goto("/");
  await page.getByRole("button", { name: "Continue with Keycloak" }).click();
  await page.locator("#username").fill(username);
  await page.locator("#password").fill(password);
  await page.locator("#kc-login").click();
  await expect(page.getByRole("heading", { name: "Overview", exact: true })).toBeVisible();
}

test("Keycloak PKCE, live console, tool registry and protected attack", async ({ page }) => {
  const screenshotPath = process.env.SMCP_SCREENSHOT_DIR;
  if (screenshotPath) await mkdir(screenshotPath, { recursive: true });
  await signIn(page);
  await expect(page.getByText("Aurora Systems").first()).toBeVisible();
  await expect(page.getByRole("heading", { name: "Gateway health" })).toBeVisible();
  if (screenshotPath) await page.screenshot({ path: screenshotPath + "/overview.png", fullPage: true });
  await page.getByRole("link", { name: "Tool Registry" }).click();
  await expect(page.getByRole("heading", { name: "Tool Registry", exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "crm__get_customer", exact: true })).toBeVisible();
  await page.getByRole("link", { name: "crm__get_customer", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Approved definition" })).toBeVisible();
  await page.getByRole("link", { name: "Attack Lab" }).click();
  await page.getByRole("button", { name: "Run scenario" }).click();
  await expect(page.getByText("Run completed.")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Case outcomes" })).toBeVisible();
  await expect(page.getByText("Destination blocked", { exact: true })).toBeVisible();
  await expect(page.getByText(/attacker@external.example/)).toBeVisible();
  if (screenshotPath)
    await page.screenshot({ path: screenshotPath + "/attack-lab.png", fullPage: true });
});

test("non-admin navigation, mobile menu and server-side role denial", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await signIn(page, "borealis-support");
  await expect(page.getByText("Borealis Systems").last()).toBeVisible();
  await page
    .getByRole("button")
    .filter({ has: page.locator("svg.lucide-menu") })
    .click();
  await page.getByRole("link", { name: "Security Events" }).click();
  await expect(page.getByRole("alert")).toContainText("Forbidden");
  await page
    .getByRole("button")
    .filter({ has: page.locator("svg.lucide-menu") })
    .click();
  await page.getByRole("link", { name: "Settings" }).click();
  await expect(page.getByRole("heading", { name: "Authenticated identity" })).toBeVisible();
  const screenshots = process.env.SMCP_SCREENSHOT_DIR;
  if (screenshots) {
    await mkdir(screenshots, { recursive: true });
    await page.screenshot({ path: screenshots + "/mobile-settings.png", fullPage: true });
  }
});
