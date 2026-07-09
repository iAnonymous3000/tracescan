// End-to-end tests through the real UI: demo scans, verdict rendering,
// report export, the hostile-archive inconclusive path, and the offline
// privacy claim (load once, go offline, scanning still works).
const { test, expect } = require('@playwright/test');
const fs = require('fs');

// Builds a minimal ustar archive in the page and hands it to the same
// handleFile the drop zone uses. Used for inputs no fixture should ship.
const buildTarInPage = ([entryCount]) => {
  function header(name, size) {
    const h = new Uint8Array(512);
    const enc = new TextEncoder();
    h.set(enc.encode(name), 0);
    h.set(enc.encode('0000644\0'), 100);
    h.set(enc.encode('0000000\0'), 108);
    h.set(enc.encode('0000000\0'), 116);
    h.set(enc.encode(size.toString(8).padStart(11, '0') + '\0'), 124);
    h.set(enc.encode('00000000000\0'), 136);
    h.set(enc.encode('        '), 148);
    h[156] = 48; // '0'
    h.set(enc.encode('ustar\0'), 257);
    h.set(enc.encode('00'), 263);
    let sum = 0;
    for (const b of h) sum += b;
    h.set(enc.encode(sum.toString(8).padStart(6, '0') + '\0 '), 148);
    return h;
  }
  const data = new TextEncoder().encode('{}\n{}');
  const padded = new Uint8Array(512);
  padded.set(data);
  const parts = [];
  for (let i = 0; i < entryCount; i++) {
    parts.push(header(`root/crashes_and_spins/p${i}.ips`, data.length));
    parts.push(padded);
  }
  parts.push(new Uint8Array(1024));
  window.__trace.handleFile(new File(parts, 'sysdiagnose_hostile.tar'));
};

test('clean demo produces the clear verdict', async ({ page }) => {
  await page.goto('/');
  await page.click('#demo-clean');
  await expect(page.locator('.verdict.clear')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('.verdict h2')).toHaveText('No known spyware traces found');
  // the honest-epistemics disclaimer must always accompany a clear verdict
  await expect(page.locator('.verdict.clear')).toContainText('not the same as "your phone is clean."');
});

test('infected demo produces the match verdict with helplines', async ({ page }) => {
  await page.goto('/');
  await page.click('#demo-infected');
  await expect(page.locator('.verdict.match')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('.help-block')).toContainText('Access Now');
  // all three artifact surfaces must contribute a match (incl. the iOS 26
  // rotated shutdown log with UUID-suffixed paths)
  const artifacts = page.locator('.finding:has(.sev.match) .artifact');
  await expect(artifacts.filter({ hasText: '.ips' })).toHaveCount(1);
  await expect(artifacts.filter({ hasText: 'ps.txt' })).toHaveCount(1);
  await expect(artifacts.filter({ hasText: 'shutdown.0.log' })).toHaveCount(1);
});

test('exported report records indicator provenance', async ({ page }) => {
  await page.goto('/');
  await page.click('#demo-infected');
  await expect(page.locator('.verdict.match')).toBeVisible({ timeout: 30_000 });
  const downloadPromise = page.waitForEvent('download');
  await page.click('#export-btn');
  const download = await downloadPromise;
  const report = JSON.parse(fs.readFileSync(await download.path(), 'utf8'));
  expect(report.tool.name).toBe('Trace');
  expect(report.stats.applicable_indicators).toBeGreaterThan(0);
  expect(report.indicator_provenance.length).toBeGreaterThan(0);
  for (const p of report.indicator_provenance) {
    expect(p.sha256).toMatch(/^[0-9a-f]{64}$/);
  }
});

test('an archive that trips scan limits is reported as inconclusive', async ({ page }) => {
  await page.goto('/');
  // wait for boot so __trace.handleFile takes the same path a drop would
  await expect(page.locator('#ioc-panel')).toBeVisible({ timeout: 30_000 });
  await page.evaluate(buildTarInPage, [4100]);
  await expect(page.locator('.verdict.inconclusive')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('.verdict.inconclusive')).toContainText('no verdict can be given');
});

test('dropping a file anywhere on the page scans it instead of navigating away', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('#ioc-panel')).toBeVisible({ timeout: 30_000 });
  await page.evaluate(async () => {
    const blob = await (await fetch('./fixtures/sysdiagnose_demo_clean.tar.gz')).blob();
    const dt = new DataTransfer();
    dt.items.add(new File([blob], 'sysdiagnose_demo_clean.tar.gz'));
    // target the footer: well outside the dropzone
    document.querySelector('.site-footer').dispatchEvent(
      new DragEvent('drop', { bubbles: true, cancelable: true, dataTransfer: dt })
    );
  });
  await expect(page.locator('.verdict.clear')).toBeVisible({ timeout: 30_000 });
});

test('an archive whose ps.txt cannot be parsed is inconclusive, never clear', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('#ioc-panel')).toBeVisible({ timeout: 30_000 });
  // a ps.txt with no header row parses to "unparsed": that surface was not
  // checked, so the scan must not render "no known spyware traces found"
  await page.evaluate(() => {
    function header(name, size) {
      const h = new Uint8Array(512);
      const enc = new TextEncoder();
      h.set(enc.encode(name), 0);
      h.set(enc.encode('0000644\0'), 100);
      h.set(enc.encode('0000000\0'), 108);
      h.set(enc.encode('0000000\0'), 116);
      h.set(enc.encode(size.toString(8).padStart(11, '0') + '\0'), 124);
      h.set(enc.encode('00000000000\0'), 136);
      h.set(enc.encode('        '), 148);
      h[156] = 48; // '0'
      h.set(enc.encode('ustar\0'), 257);
      h.set(enc.encode('00'), 263);
      let sum = 0;
      for (const b of h) sum += b;
      h.set(enc.encode(sum.toString(8).padStart(6, '0') + '\0 '), 148);
      return h;
    }
    const data = new TextEncoder().encode('no header row in this file');
    const padded = new Uint8Array(512);
    padded.set(data);
    window.__trace.handleFile(new File(
      [header('root/ps.txt', data.length), padded, new Uint8Array(1024)],
      'sysdiagnose_badps.tar'
    ));
  });
  await expect(page.locator('.verdict.inconclusive')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('.verdict.inconclusive')).toContainText('no verdict can be given');
  await expect(page.locator('.verdict.inconclusive')).toContainText('process listing');
});

test('an empty live indicator bundle is rejected for the bundled snapshot', async ({ page }) => {
  // "{"objects":[]}" is valid JSON and a valid-shaped bundle, but loading it
  // would scan with zero indicators; the reviewed floor must win
  await page.route('https://raw.githubusercontent.com/**', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: '{"objects":[]}' })
  );
  await page.goto('/');
  await expect(page.locator('#ioc-panel')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('#ioc-list .badge.live')).toHaveCount(0);
  await expect(page.locator('#ioc-list .badge.bundled')).toHaveCount(8);
  // and scanning with the snapshots still detects the seeded indicator
  await page.click('#demo-infected');
  await expect(page.locator('.verdict.match')).toBeVisible({ timeout: 30_000 });
});

test('a second file arriving mid-scan is ignored, not interleaved', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('#ioc-panel')).toBeVisible({ timeout: 30_000 });
  await page.evaluate(async () => {
    const clean = await (await fetch('./fixtures/sysdiagnose_demo_clean.tar.gz')).blob();
    const infected = await (await fetch('./fixtures/sysdiagnose_demo_infected.tar.gz')).blob();
    window.__trace.handleFile(new File([clean], 'sysdiagnose_demo_clean.tar.gz'));
    // racing second scan: must be refused while the first is in flight
    window.__trace.handleFile(new File([infected], 'sysdiagnose_demo_infected.tar.gz'));
  });
  await expect(page.locator('.verdict.clear')).toBeVisible({ timeout: 30_000 });
  const name = await page.evaluate(() => window.__trace.lastReport.source_file.name);
  expect(name).toBe('sysdiagnose_demo_clean.tar.gz');
});

test('scanning still works fully offline once the app is cached', async ({ page, context, browserName }) => {
  test.skip(
    browserName === 'webkit',
    'Playwright WebKit cannot emulate offline across a service-worker navigation (internal error on reload); the offline path is proven on chromium and firefox'
  );
  await page.goto('/');
  await page.evaluate(() => navigator.serviceWorker.ready);
  await context.setOffline(true);
  await page.reload();
  await page.click('#demo-clean');
  await expect(page.locator('.verdict.clear')).toBeVisible({ timeout: 30_000 });
  // offline means the live refresh failed and bundled snapshots were used
  await expect(page.locator('#ioc-list')).toContainText('snapshot');
  await context.setOffline(false);
});
