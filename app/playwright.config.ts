import { defineConfig } from '@playwright/test';

const baseURL = process.env.TEST_BASE_URL || 'http://127.0.0.1:3101';

export default defineConfig({
  testDir: './test',
  use: { baseURL, browserName: 'chromium' },
  webServer: { command: 'npm run dev -- --port 3101', url: baseURL, reuseExistingServer: !process.env.CI },
});
