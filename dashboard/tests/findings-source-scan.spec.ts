import { expect, test } from "@playwright/test";
import { connect } from "./fixtures/connect";

const scanId = "9d0be757-f8b9-4cbe-856e-dff4ba0c4e95";
const sourceLink = `/#scan-history?scan=${scanId}&source=services&artifact=0`;

test("an analyst can open exact evidence from a scan outside the loaded history", async ({ page }) => {
  await connect(page, "analyst");
  await page.getByRole("link", { name: "Scan history", exact: true }).click();
  await expect(page.getByText("No scans yet")).toBeVisible();
  await page.getByRole("link", { name: "Findings", exact: true }).click();
  const search = page.getByRole("textbox", { name: "Search across scan findings" });
  const severity = page.getByLabel("Severity across scan findings");
  await search.fill("service");
  await severity.selectOption("high");
  const link = page.getByRole("link", { name: "Open source scan #9d0be757 for Fixture service finding" });
  await expect(link).toHaveAttribute("href", sourceLink.slice(1));
  await link.press("Enter");

  const heading = page.getByRole("heading", { name: "Source scan", exact: true });
  const details = page.getByRole("complementary", { name: "Scan details" });
  await expect(heading).toBeFocused();
  await expect(details.getByText("Scan #9d0be757")).toBeVisible();
  await expect(details.getByText("Fixture service finding")).toBeVisible();
  await expect(details.getByText("HKLM\\SYSTEM\\CurrentControlSet\\Services\\SampleAgent", { exact: true })).toBeVisible();
  await expect(details.getByText("Fixture task finding")).toHaveCount(0);
  await expect(details.getByRole("button", { name: "Attach to case" })).toBeVisible();
  await details.getByRole("button", { name: "Show all findings" }).click();
  await expect(details.getByText("Fixture task finding")).toBeVisible();
  await details.getByRole("button", { name: "Coverage", exact: true }).click();
  await expect(details.getByText("Fixture coverage gap")).toBeVisible();

  await page.goBack();
  await expect(page.getByRole("heading", { name: "Findings", exact: true })).toBeVisible();
  await expect(search).toHaveValue("service");
  await expect(severity).toHaveValue("high");
  await expect(link).toBeVisible();
});

test("a viewer can open a bookmarked source scan on mobile after connecting", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(sourceLink);
  await expect(page.getByText("Connect the API to open this source scan.")).toBeVisible();
  await expect(page.getByText("Fixture service finding")).toHaveCount(0);
  await connect(page, "viewer", sourceLink);
  const details = page.getByRole("complementary", { name: "Scan details" });
  await expect(details.getByText("Fixture service finding")).toBeVisible();
  await expect(details.getByRole("button", { name: "Attach to case" })).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(390);
  await page.getByRole("link", { name: "Back to Findings" }).click();
  await expect(page.getByRole("heading", { name: "Findings", exact: true })).toBeVisible();
});

test("a stale finding or unavailable source scan shows its own error state", async ({ page }) => {
  await connect(page, "admin", sourceLink.replace("artifact=0", "artifact=5"));
  const details = page.getByRole("complementary", { name: "Scan details" });
  await expect(details.getByText("The linked finding is unavailable in the current assessment.")).toBeVisible();
  await expect(details.getByText("Fixture service finding")).toHaveCount(0);
  await details.getByRole("button", { name: "Show all findings" }).click();
  await expect(details.getByText("Fixture service finding")).toBeVisible();

  const unavailable = sourceLink.replace(scanId, "3000dd35-6299-44bd-83c7-4eb2550e30c3");
  await page.evaluate(href => { window.location.hash = href.slice(1); }, unavailable);
  await expect(page.getByRole("main").getByRole("alert")).toHaveText("This endpoint, scan, or assessment is unavailable.");
  await expect(details).toHaveCount(0);
});
