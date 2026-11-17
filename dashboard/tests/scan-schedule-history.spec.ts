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
  await details.getByRole("button", { name: "Coverage", exact: true }).press("Enter");
  await expect(details.getByText("FixtureService · Query configuration · Access denied", { exact: true })).toBeVisible();
  await expect(details.getByText("Read failed", { exact: true })).toBeVisible();
  await expect(details.getByText("Fixture coverage gap", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(390);

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

test("run history polls the current page and distinguishes temporary errors from lost access", async ({ page }) => {
  await page.clock.install();
  const alternateJob = "a44dee07-13cf-4f76-ad6f-ff1ceca374f8";
  const schedule = { id: scheduleId, hostname: "Regression fixture", scan_type: "persistence_services_scan" };
  const attemptedAt = "2026-11-17T01:30:04Z";
  const requestedOffsets: number[] = [];
  let hasRuns = false;
  let jobStatus = "queued";
  let failureStatus = 0;

  await page.route(url => url.pathname === `/pg-api/scan-schedules/${scheduleId}/runs`, route => {
    const offset = Number(new URL(route.request().url()).searchParams.get("offset"));
    requestedOffsets.push(offset);
    if (failureStatus) return route.fulfill({ status: failureStatus });
    const job = offset ? alternateJob : jobId;
    return route.fulfill({ json: {
      schedule, has_more: hasRuns && offset === 0,
      runs: hasRuns ? [{ id: job, scheduled_for: null, attempted_at: attemptedAt, outcome: "queued",
        job_id: job, job_status: jobStatus }] : [],
    } });
  });

  await connect(page, "viewer", historyUrl);
  const runs = page.getByRole("region", { name: "Schedule runs" });
  await expect(runs.getByText("This schedule has no runs yet.")).toBeVisible();
  hasRuns = true;
  await page.clock.runFor(5100);
  await expect(runs.getByRole("link", { name: "Scan #5b746050", exact: true })).toBeVisible();
  await runs.getByRole("button", { name: "Next page" }).click();
  await expect(runs.getByText("Page 2", { exact: true })).toBeVisible();
  const activeRun = runs.getByRole("row", { name: /Scan #a44dee07/ });
  await expect(activeRun).toContainText("Queued");
  const checkedAt = runs.getByText("Last status check").locator("time");
  const lastSuccess = await checkedAt.getAttribute("datetime");

  failureStatus = 503;
  await page.clock.runFor(5100);
  await expect(runs.getByRole("alert")).toContainText("Run history may be out of date.");
  await expect(activeRun).toBeVisible();
  await expect(checkedAt).toHaveAttribute("datetime", lastSuccess ?? "");

  failureStatus = 0;
  jobStatus = "completed";
  await page.clock.runFor(5100);
  await expect(activeRun).toContainText("Completed");
  await expect(runs.getByText("Page 2", { exact: true })).toBeVisible();
  await expect(runs.getByRole("alert")).toHaveCount(0);
  await expect(checkedAt).not.toHaveAttribute("datetime", lastSuccess ?? "");
  expect(requestedOffsets).toEqual([0, 0, 25, 25, 25]);

  failureStatus = 403;
  await page.clock.runFor(5100);
  await expect(page.getByRole("main").getByRole("alert")).toContainText("Access denied.");
  await expect(runs).toHaveCount(0);
  await expect(page.getByText("Regression fixture · Windows Services")).toHaveCount(0);
  await page.clock.runFor(10000);
  expect(requestedOffsets).toEqual([0, 0, 25, 25, 25, 25]);
});

test("source scan refreshes an active job and loads its coverage without leaving the selected tab", async ({ page }) => {
  await page.clock.install();
  const liveJob = "a44dee07-13cf-4f76-ad6f-ff1ceca374f8";
  const path = `**/pg-api/scan-jobs/${liveJob}`;
  let status = "queued";
  let failureStatus = 0;
  let statusChecks = 0;
  let assessmentChecks = 0;
  await page.route(path, route => {
    statusChecks++;
    if (failureStatus) return route.fulfill({ status: failureStatus });
    return route.fulfill({ json: { id: liveJob, schedule_id: scheduleId, endpoint_id: "bca1da67-0a54-48e8-b857-f037a467cf41",
      scan_type: "persistence_services_scan", status, created_at: "2026-11-17T01:30:04Z" } });
  });
  await page.route(`${path}/assessment`, route => {
    assessmentChecks++;
    return route.fulfill({ json: { baseline_job_id: null, status: "collected",
      collectors: { services: { status: "collected", coverage: [], assessments: [] } } } });
  });

  await connect(page, "viewer", historyUrl);
  await page.getByRole("link", { name: "Scan #a44dee07", exact: true }).click();
  const details = page.getByRole("complementary", { name: "Scan details" });
  await expect(details.getByText("Queued", { exact: true })).toBeVisible();
  const coverage = details.getByRole("button", { name: "Coverage", exact: true });
  await coverage.click();
  expect(assessmentChecks).toBe(0);

  failureStatus = 503;
  await page.clock.runFor(5100);
  const alert = page.getByRole("main").getByRole("alert");
  await expect(alert).toContainText("Scan status may be out of date.");
  await expect(details.getByText("Queued", { exact: true })).toBeVisible();

  failureStatus = 0;
  status = "completed";
  await page.clock.runFor(5100);
  await expect(details.getByText("Completed", { exact: true })).toBeVisible();
  await expect(details.getByText("Collected", { exact: true })).toBeVisible();
  await expect(coverage).toHaveAttribute("aria-pressed", "true");
  await expect(alert).toHaveCount(0);
  expect(assessmentChecks).toBe(1);
  await page.clock.runFor(10000);
  expect(statusChecks).toBe(3);

  failureStatus = 403;
  await page.getByRole("button", { name: "Refresh scan", exact: true }).click();
  await expect(alert).toContainText("Access denied.");
  await expect(details).toHaveCount(0);
});
