import { randomUUID } from "node:crypto";
import { expect, type Page } from "@playwright/test";

export async function connect(page: Page, role: "admin" | "analyst" | "viewer") {
  const token = `dashboard-${role}-${randomUUID()}`;
  await page.goto("/");
  await page.getByRole("button", { name: "Connect API", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Access token").fill(token);
  await dialog.getByRole("button", { name: "Connect API", exact: true }).click();
  await expect(page.getByRole("button", { name: "API connected", exact: true })).toBeVisible();
  return token;
}
