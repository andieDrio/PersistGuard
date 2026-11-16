import { expect, test } from "@playwright/test";
import { connect } from "./fixtures/connect";

test.use({ timezoneId: "Asia/Manila" });

test("analyst creates, edits, pauses and resumes a recurring Windows scan", async ({ page }) => {
  await connect(page, "analyst");
  await page.getByRole("link", { name: "Scan history", exact: true }).click();
  await page.getByRole("link", { name: "Scan schedules", exact: true }).click();
  await expect(page.getByText("No scan schedules on this page.")).toBeVisible();
  await page.getByRole("button", { name: "Create schedule" }).click();
  const create = page.getByRole("dialog", { name: "Create scan schedule" });
  await create.getByLabel("Endpoint", { exact: true }).selectOption({ label: "Regression fixture (bca1da67)" });
  await create.getByLabel("Scan scope").selectOption({ label: "Windows Services" });
  await create.getByLabel("Repeat", { exact: true }).selectOption("weekly");
  await create.getByLabel("First run (local time)").fill("2038-02-08T09:30");
  const request = page.waitForRequest(entry => entry.method() === "POST" && entry.url().endsWith("/pg-api/scan-schedules"));
  await create.getByRole("button", { name: "Save schedule" }).click();
  expect((await request).postDataJSON()).toMatchObject({ frequency: "weekly", scan_type: "persistence_services_scan",
    next_run_at: "2038-02-08T01:30:00.000Z" });

  const row = page.getByRole("row", { name: /Regression fixture.*Windows Services/ });
  await expect(row.getByRole("cell", { name: "Weekly" })).toBeVisible();
  await row.getByRole("button", { name: "Edit", exact: true }).click();
  const edit = page.getByRole("dialog", { name: "Edit scan schedule" });
  await expect(edit.getByLabel("Next run (local time)")).toHaveValue("2038-02-08T09:30");
  await edit.getByLabel("Repeat", { exact: true }).selectOption("daily");
  await edit.getByRole("button", { name: "Save schedule" }).click();
  await expect(row.getByRole("cell", { name: "Daily" })).toBeVisible();

  await row.getByRole("button", { name: "Pause", exact: true }).click();
  await expect(row.getByRole("cell", { name: "Paused" })).toBeVisible();
  await row.getByRole("button", { name: "Resume", exact: true }).click();
  await expect(row.getByRole("button", { name: "Pause", exact: true })).toBeVisible();
});

test("viewer can read a schedule on mobile through its direct link", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/#scan-schedules");
  await expect(page.getByText("Connect the API to view scan schedules.")).toBeVisible();
  await connect(page, "viewer", "/#scan-schedules");
  const schedules = page.getByRole("region", { name: "Recurring Windows scans" });
  await expect(schedules.getByText("Skipped · unfinished scan")).toBeVisible();
  await expect(page.getByRole("button", { name: "Create schedule" })).toHaveCount(0);
  await expect(schedules.getByRole("button", { name: /Edit|Pause|Resume/ })).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(390);
});

test("admin can open and close the schedule editor using the keyboard", async ({ page }) => {
  await connect(page, "admin", "/#scan-schedules");
  const button = page.getByRole("button", { name: "Create schedule" });
  await button.press("Enter");
  const dialog = page.getByRole("dialog", { name: "Create scan schedule" });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByLabel("Repeat", { exact: true })).toHaveValue("daily");
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(button).toBeFocused();
});
