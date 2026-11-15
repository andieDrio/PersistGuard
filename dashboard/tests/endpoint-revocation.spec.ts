import { expect, test } from "@playwright/test";
import { connect } from "./fixtures/connect";

test("admin can dismiss revocation or confirm it through the dashboard API proxy", async ({ page }) => {
  await connect(page, "admin");
  await page.getByRole("link", { name: "Endpoint onboarding" }).click();
  const approved = page.getByRole("button", { name: "Approved", exact: true });
  await approved.click();

  const revoke = page.getByRole("button", { name: "Revoke Regression fixture", exact: true });
  const dialog = page.getByRole("dialog", { name: "Revoke endpoint?" });
  const isRevocation = (url: string, method: string) =>
    method === "POST" && /^\/pg-api\/endpoints\/[^/]+\/revoke$/.test(new URL(url).pathname);
  const requests: string[] = [];
  page.on("request", request => {
    if (isRevocation(request.url(), request.method())) requests.push(request.url());
  });

  await revoke.click();
  await expect(dialog.getByText("Regression fixture", { exact: true })).toBeVisible();
  await dialog.getByRole("button", { name: "Back", exact: true }).click();
  await expect(dialog).not.toBeVisible();
  await expect(revoke).toBeVisible();
  expect(requests).toHaveLength(0);

  await revoke.click();
  const responsePromise = page.waitForResponse(response => isRevocation(response.url(), response.request().method()));
  await dialog.getByRole("button", { name: "Revoke endpoint", exact: true }).click();
  expect((await responsePromise).status()).toBe(200);
  await expect(page.getByRole("status").filter({ hasText: "Regression fixture was revoked." })).toBeVisible();
  await expect(page.getByRole("button", { name: "Revoked", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("row", { name: /Regression fixture.*Revoked/ })).toBeVisible();
  await expect(revoke).toHaveCount(0);
  await approved.click();
  await expect(page.getByText("No approved devices", { exact: true })).toBeVisible();
  expect(requests).toHaveLength(1);
});

for (const role of ["analyst", "viewer"] as const) {
  test(`${role} cannot open endpoint onboarding through a direct link`, async ({ page }) => {
    await connect(page, role);
    await page.goto("/#endpoint-onboarding");
    await expect(page.getByRole("heading", { name: "Endpoints", exact: true })).toBeVisible();
    await expect(page.getByRole("link", { name: "Endpoint onboarding" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: /^Revoke/ })).toHaveCount(0);
  });
}
