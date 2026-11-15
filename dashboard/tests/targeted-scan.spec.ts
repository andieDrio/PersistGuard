import { expect, test } from "@playwright/test";
import { connect } from "./fixtures/connect";

test("analyst can queue one Windows collector from Scan history", async ({ page }) => {
  await connect(page, "analyst");
  await page.getByRole("link", { name: "Scan history", exact: true }).click();
  await page.getByRole("button", { name: "Queue scan", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Queue Windows scan" });
  await dialog.getByLabel("Endpoint", { exact: true }).selectOption({ label: "Regression fixture (bca1da67)" });
  const scope = dialog.getByLabel("Scan scope");
  await expect(scope).toHaveValue("persistence_full_scan");
  await scope.selectOption({ label: "Windows Services" });
  await dialog.getByRole("button", { name: "Queue scan", exact: true }).click();
  await expect(dialog).not.toBeVisible();
  await expect(page.getByRole("row", { name: /Windows Services.*Regression fixture.*Queued/ })).toBeVisible();
});
