import { expect, test, type Page } from "@playwright/test";
import { connect } from "./fixtures/connect";

async function footerBounds(page: Page) {
  const footer = page.getByRole("contentinfo", { name: "PersistGuard footer" });
  const scrollArea = page.getByRole("region", { name: "PersistGuard workspace" });
  const [bounds, scrollBounds, viewport] = await Promise.all([
    footer.boundingBox(),
    scrollArea.boundingBox(),
    page.evaluate(() => ({ width: innerWidth, height: innerHeight, scrollY })),
  ]);
  expect(bounds).not.toBeNull();
  expect(scrollBounds).not.toBeNull();
  expect(bounds!.x).toBeCloseTo(0, 0);
  expect(bounds!.width).toBeCloseTo(viewport.width, 0);
  expect(bounds!.y + bounds!.height).toBeCloseTo(viewport.height, 0);
  expect(scrollBounds!.y + scrollBounds!.height).toBeCloseTo(bounds!.y, 0);
  expect(viewport.scrollY).toBe(0);
  return bounds;
}

test("admin can reach the last sidebar link on a short desktop", async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 540 });
  await connect(page, "admin");
  const sidebar = page.locator(".sidebar");
  const links = sidebar.locator(".side-body");
  const onboarding = page.getByRole("link", { name: "Endpoint onboarding", exact: true });
  await expect(onboarding).toBeAttached();
  await links.hover();
  await page.mouse.wheel(0, 500);
  await expect.poll(() => links.evaluate(el => el.scrollTop)).toBeGreaterThan(0);
  await expect(onboarding).toBeInViewport({ ratio: 1 });
  await onboarding.click();
  await expect(page.getByRole("heading", { name: "Endpoint onboarding", exact: true })).toBeVisible();
  expect((await sidebar.boundingBox())?.y).toBeCloseTo(0, 0);
  await footerBounds(page);
});

for (const [name, viewport] of [
  ["desktop", { width: 1366, height: 768 }],
  ["mobile", { width: 390, height: 844 }],
] as const) {
  test(`footer stays below the ${name} scrollbar at the end of Scan history`, async ({ page }) => {
    await page.setViewportSize(viewport);
    await page.goto("/");
    const footer = page.getByRole("contentinfo", { name: "PersistGuard footer" });
    await expect(page.getByRole("heading", { name: "Dashboard", exact: true })).toBeVisible();
    await expect(footer.getByText("Cybersecurity is everyone Responsibility")).toBeVisible();
    await expect(footer.getByText(/^Powered by: apm @ \d{4}$/)).toBeVisible();
    const shortPageFooter = await footerBounds(page);

    await page.getByRole("link", { name: "Scan history", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Scan history", exact: true })).toBeVisible();
    const scrollArea = page.getByRole("region", { name: "PersistGuard workspace" });
    await scrollArea.press("Home");
    await expect.poll(() => scrollArea.evaluate(el => el.scrollTop)).toBe(0);
    expect(await scrollArea.evaluate(el => el.scrollHeight - el.clientHeight)).toBeGreaterThan(0);
    await scrollArea.press("End");
    await expect.poll(() => scrollArea.evaluate(el =>
      Math.abs(el.scrollHeight - el.clientHeight - el.scrollTop),
    )).toBeLessThanOrEqual(1);
    expect(await footerBounds(page)).toEqual(shortPageFooter);

    const sidebar = await page.locator(".sidebar").boundingBox();
    const topbar = await page.locator(".topbar").boundingBox();
    expect(sidebar?.y).toBeCloseTo(0, 0);
    expect(topbar?.y).toBeCloseTo(name === "mobile" ? sidebar!.height : 0, 0);
  });
}
