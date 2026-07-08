// E2E config: serves web/ with the same zero-config static server the README
// recommends, so tests exercise exactly what a deploy ships.
const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './tests',
  timeout: 60_000,
  retries: process.env.CI ? 1 : 0,
  use: {
    baseURL: 'http://127.0.0.1:4173',
  },
  webServer: {
    command: 'python3 -m http.server 4173 --bind 127.0.0.1 --directory ../web',
    url: 'http://127.0.0.1:4173/',
    reuseExistingServer: !process.env.CI,
  },
  // All three engines: Mac users overwhelmingly arrive in Safari, and the
  // app leans on module workers, File.stream(), <dialog>, and a service
  // worker - exactly the surfaces that diverge between engines.
  projects: [
    { name: 'chromium', use: { browserName: 'chromium' } },
    { name: 'firefox', use: { browserName: 'firefox' } },
    { name: 'webkit', use: { browserName: 'webkit' } },
  ],
});
