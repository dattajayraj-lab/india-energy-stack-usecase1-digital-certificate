import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  workers: 1,
  fullyParallel: false,
  reporter: [["list"]],
  expect: { timeout: 10_000 },
  use: {
    baseURL: "http://localhost:3000",
    actionTimeout: 10_000,
    trace: "retain-on-failure",
    permissions: ["clipboard-read", "clipboard-write"],
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    {
      command: "node e2e/start-api.mjs",
      url: "http://localhost:8000/health",
      reuseExistingServer: false,
      timeout: 60_000,
    },
    { command: "npm run start", url: "http://localhost:3000", reuseExistingServer: false, timeout: 60_000 },
  ],
});
