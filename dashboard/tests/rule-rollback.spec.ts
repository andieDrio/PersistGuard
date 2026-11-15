import { expect, test } from "@playwright/test";
import { connect } from "./fixtures/connect";

const ruleName = "Restore regression rule";

test("admin can cancel or restore a published version through the dashboard proxy", async ({ page }) => {
  await connect(page, "admin");
  await page.getByRole("link", { name: "Rules and Detection", exact: true }).click();
  await page.getByRole("button", { name: `Version history for ${ruleName}` }).click();
  const restoreV1 = page.getByRole("button", { name: "Restore v1", exact: true });
  const restoreV2 = page.getByRole("button", { name: "Restore v2", exact: true });
  await expect(page.getByText("Active v2", { exact: true })).toBeVisible();
  await expect(restoreV2).toBeDisabled();

  const isRollback = (url: string, method: string) =>
    method === "POST" && /^\/pg-api\/detection-rules\/[^/]+\/rollback$/.test(new URL(url).pathname);
  const requests: unknown[] = [];
  page.on("request", request => {
    if (isRollback(request.url(), request.method())) requests.push(request.postDataJSON());
  });

  const dialogPromise = page.waitForEvent("dialog");
  const dismissedClick = restoreV1.click();
  const dialog = await dialogPromise;
  await dialog.dismiss();
  await dismissedClick;
  expect(dialog.type()).toBe("confirm");
  expect(dialog.message()).toContain(`Restore published v1 for "${ruleName}"?`);
  await expect(page.getByText("Active v2", { exact: true })).toBeVisible();
  expect(requests).toHaveLength(0);

  page.once("dialog", confirmation => confirmation.accept());
  const responsePromise = page.waitForResponse(response => isRollback(response.url(), response.request().method()));
  await restoreV1.click();
  expect((await responsePromise).status()).toBe(200);
  expect(requests).toEqual([{ revision: 3, version: 1 }]);
  await expect(page.getByText("Published v1 restored and active. Existing history preserved.")).toBeVisible();
  await expect(page.getByText("Active v1", { exact: true })).toBeVisible();
  await expect(page.getByText("Draft v2", { exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "v1 · Active", exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "v2", exact: true })).toBeVisible();
  await expect(restoreV1).toBeDisabled();
  await expect(restoreV2).toBeEnabled();
});

test("a stale rollback shows the server error in version history", async ({ page }) => {
  const token = await connect(page, "admin");
  await page.getByRole("link", { name: "Rules and Detection", exact: true }).click();
  await page.getByRole("button", { name: `Version history for ${ruleName}` }).click();
  const restore = page.getByRole("button", { name: "Restore v1", exact: true });
  await expect(restore).toBeEnabled();

  const headers = { Authorization: `Bearer ${token}` };
  const list = await page.request.get("/pg-api/detection-rules", { headers });
  expect(list.ok()).toBeTruthy();
  const { id, revision } = (await list.json()).rules[0];
  const path = `/pg-api/detection-rules/${id}/rollback`;
  const concurrentRestore = await page.request.post(path, { headers, data: { version: 1, revision } });
  expect(concurrentRestore.status()).toBe(200);

  page.once("dialog", confirmation => confirmation.accept());
  await restore.click();
  await expect(page.getByRole("alert").filter({ hasText: "Rule revision has changed" })).toBeVisible();
  await expect(page.getByText("Active v2", { exact: true })).toBeVisible();
});

for (const role of ["analyst", "viewer"] as const) {
  test(`${role} can view published history without Restore controls`, async ({ page }) => {
    await connect(page, role);
    await page.getByRole("link", { name: "Rules and Detection", exact: true }).click();
    await page.getByRole("button", { name: `Version history for ${ruleName}` }).click();
    await expect(page.getByRole("cell", { name: "v2 · Active", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: /^Restore v/ })).toHaveCount(0);
  });
}
