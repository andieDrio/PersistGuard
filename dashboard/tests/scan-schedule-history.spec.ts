import { expect, test } from "@playwright/test";
import { connect } from "./fixtures/connect";

const scheduleId = "0a27d2c2-e7ea-40d1-bbe1-a1b047bf36a4";
const jobId = "5b746050-eb06-414b-8cd0-2ab6bfda1b63";
const historyUrl = `/#scan-schedules?history=${scheduleId}`;

test("viewer opens a schedule's run history and follows the exact job outside the loaded list", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await connect(page, "viewer", "/#scan-schedules");
  await page.getByRole("link", { name: "Run history", exact: true }).press("Enter");
  await expect(page.getByRole("heading", { name: "Run history", exact: true })).toBeFocused();
  const runs = page.getByRole("region", { name: "Schedule runs" });
  const skipped = runs.getByRole("row", { name: /Skipped · unfinished scan/ });
  await expect(skipped).toBeVisible();
  await expect(skipped.getByRole("link")).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(390);

  const job = runs.getByRole("link", { name: "Scan #5b746050", exact: true });
  await expect(job).toHaveAttribute("href", `#scan-history?scan=${jobId}&schedule=${scheduleId}`);
  await expect(runs.getByRole("row", { name: /Scan #5b746050.*Partial/ }).getByRole("cell").first()).toHaveText("—");
  await job.click();
  const details = page.getByRole("complementary", { name: "Scan details" });
  await expect(details.getByText("Scan #5b746050")).toBeVisible();
  await expect(details.getByText("Recurring schedule")).toBeVisible();
  await expect(details.getByText("Fixture service finding")).toBeVisible();
  await expect(details.getByRole("button", { name: "Attach to case" })).toHaveCount(0);

  await page.getByRole("link", { name: "Back to run history" }).click();
  await runs.getByRole("link", { name: "Scan #a44dee07", exact: true }).click();
  await expect(details.getByText("Running", { exact: true })).toBeVisible();
  await expect(details.getByText("Results will appear after the agent uploads the inventory.")).toBeVisible();
});

test("direct run history links require a connected API and a visible schedule", async ({ page }) => {
  await page.goto(historyUrl);
  await expect(page.getByText("Connect the API to view run history.")).toBeVisible();
  await connect(page, "analyst", historyUrl);
  await expect(page.getByRole("main").getByRole("alert")).toHaveText("Scan schedule not found");
  await expect(page.getByRole("region", { name: "Schedule runs" })).toHaveCount(0);

  const otherSchedule = "17d61dbc-f345-4882-89fc-2f284941a28e";
  await page.evaluate(hash => { window.location.hash = hash; }, `scan-history?scan=${jobId}&schedule=${otherSchedule}`);
  await expect(page.getByRole("main").getByRole("alert")).toHaveText("This scan is unavailable for this schedule.");
  await expect(page.getByRole("complementary", { name: "Scan details" })).toHaveCount(0);
});
