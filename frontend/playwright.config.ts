import { defineConfig } from '@playwright/test';
if (!process.env.E2E_BASE_URL || !process.env.E2E_ADMIN_PASSWORD) {
  throw new Error('Run python3 scripts/test-integration.py --browser; do not target the working application');
}
export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 30_000,
  reporter: 'list',
  use: {
    baseURL: process.env.E2E_BASE_URL,
    browserName: 'chromium',
    trace: 'off',
    screenshot: 'only-on-failure',
  },
});
