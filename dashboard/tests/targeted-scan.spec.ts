import { expect, test, type Page } from "@playwright/test";
import { connect } from "./fixtures/connect";

async function queueServicesScan(page: Page) {
  await page.getByRole("button", { name: "Queue scan", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Queue Windows scan" });
  await dialog.getByLabel("Endpoint", { exact: true }).selectOption({ label: "Regression fixture (bca1da67)" });
  const scope = dialog.getByLabel("Scan scope");
  await expect(scope).toHaveValue("persistence_full_scan");
  await scope.selectOption({ label: "Windows Services" });
  await dialog.getByRole("button", { name: "Queue scan", exact: true }).click();
  await expect(dialog).not.toBeVisible();
  await expect(page.getByRole("row", { name: /Windows Services.*Regression fixture.*Queued/ })).toBeVisible();
}

test("analyst can queue one Windows collector from Scan history", async ({ page }) => {
  await connect(page, "analyst", "/#scan-history");
  await queueServicesScan(page);
});

test("admin can see a missing heartbeat and queue a scan on mobile", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await connect(page, "admin", "/#scan-history");
  await page.route(/\/pg-api\/scan-targets\?query=/, route => route.fulfill({ json: {
    can_manage: true, can_onboard: true,
    endpoints: [{ id: "bca1da67-0a54-48e8-b857-f037a467cf41", hostname: "Regression fixture",
      last_seen: null, connected: false }],
  } }));
  await page.getByRole("button", { name: "Queue scan", exact: true }).press("Enter");
  const dialog = page.getByRole("dialog", { name: "Queue Windows scan" });
  await dialog.getByLabel("Endpoint", { exact: true }).selectOption({ label: "Regression fixture (bca1da67)" });
  const health = dialog.getByRole("status");
  await expect(health).toContainText("Disconnected");
  await expect(health).toContainText("Last heartbeat Never");
  await expect(health).toContainText("Queued scans wait for the agent to poll.");
  await dialog.getByLabel("Scan scope").selectOption({ label: "Windows Services" });
  await dialog.getByRole("button", { name: "Queue scan", exact: true }).click();
  await expect(page.getByRole("row", { name: /Windows Services.*Regression fixture.*Queued/ })).toBeVisible();
});

test("viewer cannot queue a scan from the direct Scan history link", async ({ page }) => {
  await connect(page, "viewer", "/#scan-history");
  await expect(page.getByRole("heading", { name: "Scan history", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Queue scan", exact: true })).toHaveCount(0);
});

test("Scan history updates the selected scan and loads coverage after the agent finishes", async ({ page }) => {
  await page.clock.install();
  await connect(page, "analyst", "/#scan-history");
  const jobId = "cd3c2b28-a25c-409f-a694-fc26e79331ac";
  const statusPath = `**/pg-api/scan-jobs/${jobId}`;
  let status = "unavailable";
  let statusChecks = 0;
  await page.route(statusPath, route => {
    statusChecks++;
    if (status === "unavailable") return route.fulfill({ status: 503 });
    return route.fulfill({ json: { id: jobId, status } });
  });
  await page.route(`${statusPath}/assessment`, route => route.fulfill({ json: {
    baseline_job_id: null, status: "collected",
    collectors: { services: { status: "collected", coverage: [], assessments: [] } },
  } }));

  await queueServicesScan(page);
  const search = page.getByRole("textbox", { name: "Search scans or endpoints" });
  await search.fill("Regression fixture");
  const details = page.getByRole("complementary", { name: "Scan details" });
  const coverage = details.getByRole("button", { name: "Coverage" });
  await coverage.click();
  await expect(details.getByText("Waiting for the Windows agent to pick up this scan.")).toBeVisible();

  await page.clock.runFor(5100);
  await expect(page.getByRole("main").getByRole("alert")).toContainText("Scan statuses may be out of date.");
  await expect(details.getByText("Queued", { exact: true })).toBeVisible();

  status = "running";
  await page.clock.runFor(5100);
  await expect(details.getByText("Running", { exact: true })).toBeVisible();
  await expect(page.getByText("Scan statuses may be out of date.")).toHaveCount(0);

  status = "completed";
  await page.clock.runFor(5100);
  await expect(details.getByText("Completed", { exact: true })).toBeVisible();
  await expect(details.getByText("Collected", { exact: true })).toBeVisible();
  await expect(coverage).toHaveAttribute("aria-pressed", "true");
  await expect(search).toHaveValue("Regression fixture");
  await expect(page.getByText("Last status check")).toBeVisible();

  await page.clock.runFor(10000);
  expect(statusChecks).toBe(3);
});
