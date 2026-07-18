// E2E config: serves web/ with the same zero-config static server the README
// recommends, so tests exercise exactly what a deploy ships.
const { defineConfig } = require('@playwright/test');

const portText = process.env.TRACE_E2E_PORT || '4173';
if (!/^\d+$/.test(portText)) {
  throw new Error('TRACE_E2E_PORT must be an integer from 1 to 65535.');
}
const port = Number(portText);
if (port < 1 || port > 65535) {
  throw new Error('TRACE_E2E_PORT must be an integer from 1 to 65535.');
}
const baseURL = `http://127.0.0.1:${port}`;

module.exports = defineConfig({
  testDir: './tests',
  timeout: 60_000,
  retries: process.env.CI ? 1 : 0,
  // Keep browser projects serial. Concurrent engines against the same single
  // local server produced nondeterministic same-URL navigation interruptions
  // in service-worker lifecycle tests; serial execution keeps the default and
  // CI command deterministic.
  workers: 1,
  use: {
    baseURL,
  },
  webServer: {
    command: `python3 -m http.server ${port} --bind 127.0.0.1 --directory ../web`,
    url: `${baseURL}/`,
    // A silently reused process may serve another checkout or stale assets.
    // Every run owns and tears down the exact server it validates.
    reuseExistingServer: false,
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
