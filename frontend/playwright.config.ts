import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  fullyParallel: process.env.PLAYWRIGHT_SINGLE_PROCESS === "1",
  workers: process.env.PLAYWRIGHT_SINGLE_PROCESS === "1" ? 2 : 1,
  timeout: 45_000,
  use: {
    baseURL: process.env.SMCP_UI_URL || "http://localhost:5173",
    viewport: { width: 1440, height: 1000 },
    launchOptions: {
      executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || undefined,
      args:
        process.env.PLAYWRIGHT_SINGLE_PROCESS === "1"
          ? ["--single-process", "--no-zygote", "--disable-gpu", "--disable-setuid-sandbox"]
          : [],
    },
  },
});
