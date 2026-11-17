import { expect, test, type Page } from "@playwright/test";
import { connect } from "./fixtures/connect";

async function coverage(page: Page) {
  await page.getByRole("link", { name: "Rules and Detection", exact: true }).click();
  await page.getByRole("button", { name: "ATT&CK Coverage", exact: true }).click();
  await expect(page.getByRole("heading", { name: "ATT&CK Coverage Matrix" })).toBeVisible();
}

async function openValidation(page: Page) {
  await page.getByRole("button", { name: "Validation for Scheduled task persistence" }).click();
  await expect(page.getByRole("dialog", { name: "Validation evidence" })).toBeVisible();
}

async function record(page: Page, result: string, date: string, reference: string) {
  await page.getByRole("button", { name: "Record test" }).click();
  const form = page.locator(".validation-form");
  await form.getByLabel("Test result").selectOption(result);
  await form.getByLabel("Test date").fill(date);
  await form.getByLabel("Evidence reference").fill(reference);
  await form.getByRole("button", { name: "Save test" }).click();
  await expect(page.getByText("Deployment test saved.")).toBeVisible();
}

test("latest validation shows not tested, refreshes after save, and respects test date", async ({ page }) => {
  await connect(page, "admin");
  await coverage(page);
  const row = page.getByRole("row").filter({ hasText: "Scheduled task persistence" });
  await expect(row.getByText("Not tested")).toBeVisible();
  await openValidation(page);
  await record(page, "passed", "2026-11-16", "fixture-pass");
  await page.getByRole("button", { name: "Close validation evidence" }).click();
  await expect(row.getByText("Passed")).toBeVisible();
  await expect(row.getByText("2026-11-16")).toBeVisible();

  await openValidation(page);
  await record(page, "failed", "2026-11-17", "fixture-fail");
  await page.getByRole("button", { name: "Close validation evidence" }).click();
  await expect(row.getByText("Failed")).toBeVisible();
  await expect(row.getByText("2026-11-17")).toBeVisible();

  await openValidation(page);
  await record(page, "inconclusive", "2026-11-15", "fixture-older");
  await page.getByRole("button", { name: "Close validation evidence" }).click();
  await expect(row.getByText("Failed")).toBeVisible();
  await expect(row.getByText("2026-11-17")).toBeVisible();
  await expect(page.getByRole("row").filter({ hasText: "Windows service persistence" })
    .getByText("Not tested")).toBeVisible();
});

test("viewer cannot record validation and does not see admin test results", async ({ page, browser }) => {
  await connect(page, "admin");
  await coverage(page);
  await openValidation(page);
  await record(page, "passed", "2026-11-17", "admin-only");
  await page.getByRole("button", { name: "Close validation evidence" }).click();

  const viewerContext = await browser.newContext();
  try {
    const viewer = await viewerContext.newPage();
    await connect(viewer, "viewer");
    await coverage(viewer);
    const row = viewer.getByRole("row").filter({ hasText: "Scheduled task persistence" });
    await expect(row.getByText("Not tested")).toBeVisible();
    await openValidation(viewer);
    await expect(viewer.getByRole("button", { name: "Record test" })).toHaveCount(0);
  } finally {
    await viewerContext.close();
  }
});
