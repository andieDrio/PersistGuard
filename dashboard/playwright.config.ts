import { defineConfig } from "@playwright/test";

const dashboardURL = "http://127.0.0.1:3416";
const fixtureURL = "http://127.0.0.1:3415";

export default defineConfig({
  testDir: "./tests",
  forbidOnly: Boolean(process.env.CI),
  workers: process.env.CI ? 1 : undefined,
  use: { baseURL: dashboardURL, trace: "retain-on-failure" },
  webServer: [
    {
      command: "node tests/fixtures/dashboard-api.mjs",
      url: `${fixtureURL}/healthz`,
      env: { DASHBOARD_FIXTURE_PORT: new URL(fixtureURL).port },
    },
    {
      command: `npm run build && npm run start -- --port ${new URL(dashboardURL).port}`,
      url: dashboardURL,
      env: { PERSISTGUARD_API_URL: fixtureURL },
      timeout: 120_000,
    },
  ],
});
