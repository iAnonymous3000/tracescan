// End-to-end tests through the real UI: demo scans, verdict rendering,
// report export, the hostile-archive inconclusive path, and the offline
// privacy claim (load once, go offline, scanning still works).
const { test, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');

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

test('pre-scan safety guidance discloses observable use and the iCloud trade-off', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('.safety-note')).toContainText('browser, router, or DNS records');
  await expect(page.locator('.safety-note')).toContainText('Private browsing does not hide network traffic');
  await expect(page.locator('.safety-note')).toContainText("Access Now's Digital Security Helpline");
  await page.locator('#capture-guide').evaluate((guide) => { guide.open = true; });
  await expect(page.locator('#capture-guide')).toContainText('uploads the archive to your iCloud account');
  await expect(page.locator('#capture-guide')).toContainText('phone-only scan');
});

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

test('results show and copy the engine-owned archive SHA-256', async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async (value) => { window.__traceCopiedText = value; },
      },
    });
  });
  await page.goto('/');
  await page.click('#demo-infected');
  await expect(page.locator('.verdict.match')).toBeVisible({ timeout: 30_000 });

  const reportHash = await page.evaluate(() => window.__trace.lastReport.source_file.sha256);
  expect(reportHash).toMatch(/^[0-9a-f]{64}$/);
  await expect(page.locator('#source-sha256')).toBeVisible();
  await expect(page.locator('#source-sha256')).toHaveText(reportHash);
  await expect(page.locator('#source-sha256-row')).toContainText(
    'exact archive bytes Trace analyzed'
  );

  await page.click('#copy-source-sha256');
  await expect.poll(() => page.evaluate(() => window.__traceCopiedText)).toBe(reportHash);
  await expect(page.locator('#copy-source-sha256-status')).toHaveText('Hash copied.');
});

test('archive SHA-256 is absent without a current report and after a later error', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('#source-sha256')).toHaveCount(0);

  await page.click('#demo-clean');
  await expect(page.locator('.verdict.clear')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('#source-sha256')).toBeVisible();

  await page.click('#rescan-btn');
  await expect(page.locator('#source-sha256')).toBeHidden();
  await page.evaluate(() => {
    window.__trace.disableWorker();
    const broken = new File(['not read'], 'sysdiagnose_unreadable.tar');
    Object.defineProperty(broken, 'stream', {
      value: () => { throw new Error('forced read failure'); },
    });
    window.__trace.handleFile(broken);
  });
  await expect(page.locator('.error-box')).toContainText('forced read failure');
  await expect(page.locator('#source-sha256')).toHaveCount(0);
  expect(await page.evaluate(() => window.__trace.lastReport)).toBeNull();
});

test('starting a new scan immediately removes the previous case-data DOM', async ({ page }) => {
  await page.goto('/');
  await page.click('#demo-infected');
  await expect(page.locator('.verdict.match')).toBeVisible({ timeout: 30_000 });
  expect(await page.locator('#results').evaluate((node) => node.childElementCount)).toBeGreaterThan(0);

  const state = await page.evaluate(() => {
    // Do not await: inspect the synchronous privacy cleanup before the scan's
    // first awaited operation resumes.
    window.__trace.handleFile(new File(['not an archive'], 'next-case.tar'));
    return {
      resultChildren: document.querySelector('#results').childElementCount,
      resultsHidden: document.querySelector('#results').hidden,
      scanningVisible: !document.querySelector('#scanning').hidden,
      report: window.__trace.lastReport,
    };
  });
  expect(state).toEqual({
    resultChildren: 0,
    resultsHidden: true,
    scanningVisible: true,
    report: null,
  });
});

test('readable report previews redactions and downloads self-contained HTML', async ({ page }) => {
  await page.goto('/');
  await page.click('#demo-infected');
  await expect(page.locator('.verdict.match')).toBeVisible({ timeout: 30_000 });
  const identity = await page.evaluate(() => ({
    hash: window.__trace.lastReport.source_file.sha256,
    name: window.__trace.lastReport.source_file.name,
    artifact: window.__trace.lastReport.findings[0].artifact,
  }));

  await page.click('#readable-btn');
  await expect(page.locator('#readable-dialog')).toBeVisible();
  await expect(page.locator('#readable-dialog')).toHaveAttribute(
    'aria-describedby',
    'readable-dialog-description'
  );
  const preview = page.locator('#readable-preview');
  await expect(preview).toContainText(identity.hash);
  await expect(preview).toContainText('redacted from this readable copy');
  await expect(preview).not.toContainText(identity.name);
  await expect(preview).not.toContainText(identity.artifact);
  await expect(preview.locator('summary', { hasText: 'Technical evidence' })).toHaveCount(0);

  await page.check('#readable-source-name');
  await page.check('#readable-technical');
  await expect(preview).toContainText(identity.name);
  await expect(preview).toContainText(identity.artifact);
  await expect(preview.locator('summary', { hasText: 'Technical evidence' }).first()).toBeVisible();
  await expect(preview.locator('.finding h3').first()).toHaveText('Finding 1: match');
  await expect(preview.locator('.finding').first()).toHaveAttribute(
    'aria-labelledby',
    'readable-finding-1'
  );
  await expect(preview.locator('summary').first()).toHaveText('Technical evidence for finding 1');
  await page.setViewportSize({ width: 320, height: 568 });
  const evidenceWidth = await preview.locator('pre').first().evaluate((node) => ({
    client: node.clientWidth,
    scroll: node.scrollWidth,
  }));
  expect(evidenceWidth.scroll).toBeLessThanOrEqual(evidenceWidth.client + 1);

  // Return to privacy-preserving defaults before creating the handoff copy.
  await page.uncheck('#readable-source-name');
  await page.uncheck('#readable-technical');
  const downloadPromise = page.waitForEvent('download');
  await page.click('#download-readable');
  const download = await downloadPromise;
  const html = fs.readFileSync(await download.path(), 'utf8');
  expect(html).toContain('<!doctype html>');
  expect(html).toContain(identity.hash);
  expect(html).not.toContain(identity.name);
  expect(html).not.toContain(identity.artifact);
  expect(html).not.toContain('<script');
  expect(html).toContain('not digitally signed');
  expect(html).toContain('redacted from this readable copy');
  expect(html).toContain('This readable HTML is a reduced convenience copy');
  expect(html).toContain('.verification a::after');
  expect(html).toContain('attr(href)');
});

test('readable report labels unpinned references and surfaces result limits early', async ({ page }) => {
  await page.goto('/');
  await page.click('#demo-clean');
  await expect(page.locator('.verdict.clear')).toBeVisible({ timeout: 30_000 });
  const result = await page.evaluate(async () => {
    const report = structuredClone(window.__trace.lastReport);
    report.tool.build_commit = null;
    report.tool.version = '0.7.3';
    report.scan_limits = ['finding retention cap reached'];
    report.missing_artifacts = [
      { kind: 'shutdown_logs' },
      { kind: 'crash_reports' },
      { kind: 'unified_logs' },
    ];
    const { readableReportDocument } = await import('./readable-report.js');
    const parsed = new DOMParser().parseFromString(
      readableReportDocument(report),
      'text/html'
    );
    const links = [...parsed.querySelectorAll('.verification a')].map((link) => ({
      text: link.textContent,
      href: link.getAttribute('href'),
    }));
    const pinnedReport = structuredClone(report);
    pinnedReport.tool.build_commit = 'a'.repeat(40);
    const pinned = new DOMParser().parseFromString(
      readableReportDocument(pinnedReport),
      'text/html'
    );
    return {
      header: parsed.querySelector('header').textContent,
      verification: parsed.querySelector('.verification').textContent,
      links,
      pinnedVerification: pinned.querySelector('.verification').textContent,
    };
  });
  expect(result.header).toContain('Processing or reporting was incomplete');
  expect(result.header).toContain('3 of Trace\'s 4 supported artifact families were absent');
  expect(result.verification).toContain('exact reproduction is impossible');
  expect(result.pinnedVerification).toContain(
    "compare the two JSON technical reports' source hash and size"
  );
  expect(result.links[0]).toEqual({
    text: 'Current responder guide (not revision-pinned)',
    href: 'https://github.com/iAnonymous3000/tracescan/blob/main/HELPLINE.md',
  });
  expect(result.links[1]).toEqual({
    text: 'Version-tag machine-readable contract (v0.7.3)',
    href: 'https://github.com/iAnonymous3000/tracescan/blob/v0.7.3/web/report.schema.json',
  });
});

test('readable report choices survive a click on dialog padding', async ({ page }) => {
  await page.goto('/');
  await page.click('#demo-clean');
  await expect(page.locator('.verdict.clear')).toBeVisible({ timeout: 30_000 });
  await page.click('#readable-btn');
  await page.check('#readable-source-name');
  await page.evaluate(() => {
    const dialog = document.querySelector('#readable-dialog');
    dialog.dispatchEvent(new MouseEvent('click', { bubbles: true }));
  });
  await expect(page.locator('#readable-dialog')).toBeVisible();
  await expect(page.locator('#readable-source-name')).toBeChecked();
});

test('readable report escapes report-controlled text', async ({ page }) => {
  await page.goto('/');
  await page.click('#demo-infected');
  await expect(page.locator('.verdict.match')).toBeVisible({ timeout: 30_000 });
  const result = await page.evaluate(async () => {
    const report = structuredClone(window.__trace.lastReport);
    const payload = '<img src=x onerror="window.__traceReadableXss = true">';
    report.source_file.name = payload;
    report.findings[0].summary = payload;
    report.findings[0].artifact = payload;
    report.findings[0].evidence = { payload };
    const { readableReportDocument } = await import('./readable-report.js');
    const html = readableReportDocument(report, {
      includeSourceName: true,
      includeDevice: true,
      includeTechnical: true,
    });
    const parsed = new DOMParser().parseFromString(html, 'text/html');
    return {
      images: parsed.querySelectorAll('img').length,
      scripts: parsed.querySelectorAll('script').length,
      literalPayloads: (parsed.body.textContent.match(/<img src=x/g) || []).length,
      hasRestrictiveCsp: html.includes("default-src 'none'"),
    };
  });
  expect(result.images).toBe(0);
  expect(result.scripts).toBe(0);
  expect(result.literalPayloads).toBeGreaterThanOrEqual(4);
  expect(result.hasRestrictiveCsp).toBe(true);
  expect(await page.evaluate(() => window.__traceReadableXss)).toBeUndefined();
});

test('a drop over the readable preview cannot replace the report being handed off', async ({ page }) => {
  await page.goto('/');
  await page.click('#demo-infected');
  await expect(page.locator('.verdict.match')).toBeVisible({ timeout: 30_000 });
  const infectedHash = await page.evaluate(() => window.__trace.lastReport.source_file.sha256);
  await page.click('#readable-btn');
  await expect(page.locator('#readable-preview')).toContainText(infectedHash);

  await page.evaluate(async () => {
    const clean = await (await fetch('./fixtures/sysdiagnose_demo_clean.tar.gz')).blob();
    const dt = new DataTransfer();
    dt.items.add(new File([clean], 'sysdiagnose_demo_clean.tar.gz'));
    document.querySelector('#readable-dialog').dispatchEvent(
      new DragEvent('drop', { bubbles: true, cancelable: true, dataTransfer: dt })
    );
  });

  await expect(page.locator('#readable-dialog')).toBeVisible();
  expect(await page.evaluate(() => window.__trace.lastReport.source_file.sha256)).toBe(infectedHash);
  const downloadPromise = page.waitForEvent('download');
  await page.click('#download-readable');
  const download = await downloadPromise;
  const html = fs.readFileSync(await download.path(), 'utf8');
  expect(html).toContain(infectedHash);
  expect(html).toContain('Traces matching known spyware were found');
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
  await expect(page.locator('.verdict.inconclusive')).toContainText('no conclusive negative result can be given');
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
  await expect(page.locator('.verdict.inconclusive')).toContainText('no conclusive negative result can be given');
  await expect(page.locator('.verdict.inconclusive')).toContainText('process listing');
});

test.describe('upstream indicator interception', () => {
  // page.route cannot reliably intercept requests once the service worker
  // has claimed the page (its cross-origin pass-through bypasses routing in
  // WebKit, racing sw activation); interception tests run without SW. The
  // mocked responses also carry ACAO like the real host, or WebKit rejects
  // the fulfilled cross-origin response and the test measures a network
  // failure instead of the code under test.
  test.use({ serviceWorkers: 'block' });

  test('an empty live indicator bundle is neither loaded nor announced', async ({ page }) => {
    // "{"objects":[]}" is valid JSON and a valid-shaped bundle, but it is
    // below every reviewed floor: it must not become an "update available"
    // notice, and scans must run on the snapshots regardless
    await page.route('https://raw.githubusercontent.com/**', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'access-control-allow-origin': '*' },
        body: '{"objects":[]}',
      })
    );
    await page.goto('/');
    await expect(page.locator('#ioc-panel')).toBeVisible({ timeout: 30_000 });
    await expect(page.locator('#ioc-list .badge.bundled')).toHaveCount(8);
    await expect(page.locator('#ioc-note')).not.toContainText('newer data');
    // and scanning with the snapshots still detects the seeded indicator
    await page.click('#demo-infected');
    await expect(page.locator('.verdict.match')).toBeVisible({ timeout: 30_000 });
  });

  test('live indicator data never reaches a scan, even when plausible', async ({ page }) => {
    // A live feed that swaps reviewed indicators for different ones while
    // preserving counts must not influence verdicts: scans always run on the
    // reviewed snapshots, and upstream changes only produce a notice
    const decoy = {
      objects: [
        { type: 'malware', name: 'Pegasus' },
        ...Array.from({ length: 2000 }, (_, i) => ({
          type: 'indicator', pattern: `[process:name='decoy${i}']`,
        })),
      ],
    };
    await page.route('https://raw.githubusercontent.com/**', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'access-control-allow-origin': '*' },
        body: JSON.stringify(decoy),
      })
    );
    await page.goto('/');
    await expect(page.locator('#ioc-panel')).toBeVisible({ timeout: 30_000 });
    // the plausible upstream change is announced, not loaded
    await expect(page.locator('#ioc-note')).toContainText('newer data');
    await expect(page.locator('#ioc-list .badge.bundled')).toHaveCount(8);
    // the infected demo still matches via the reviewed snapshot indicator
    await page.click('#demo-infected');
    await expect(page.locator('.verdict.match')).toBeVisible({ timeout: 30_000 });
    const provenance = await page.evaluate(() => window.__trace.lastReport.indicator_provenance);
    for (const p of provenance) {
      expect(p.loaded_from).toBe('bundled');
      expect(p.upstream).toBe('update-available');
    }
  });
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

test.describe('worker failure boundaries', () => {
  test.use({ serviceWorkers: 'block' });
  test.beforeEach(async ({ page }) => {
    // Keep lifecycle tests independent of the eight optional upstream
    // freshness checks, each of which deliberately permits a 6s timeout.
    await page.route('https://raw.githubusercontent.com/**', (route) => route.abort());
  });

  test('a synchronous worker startup failure falls back inline', async ({ page }) => {
    await page.addInitScript(() => {
      window.Worker = class {
        constructor() { throw new Error('worker unavailable'); }
      };
    });
    await page.goto('/');
    await page.click('#demo-clean');
    await expect(page.locator('.verdict.clear')).toBeVisible({ timeout: 30_000 });
    expect(await page.evaluate(() => window.__trace.lastReport.scanned_via)).toBe('inline');
  });

  test('an asynchronous worker startup failure falls back inline', async ({ page }) => {
    await page.addInitScript(() => {
      window.Worker = class extends EventTarget {
        constructor() {
          super();
          setTimeout(() => this.dispatchEvent(new ErrorEvent('error')), 0);
        }
        postMessage() {}
        terminate() {}
      };
    });
    await page.goto('/');
    await page.click('#demo-clean');
    await expect(page.locator('.verdict.clear')).toBeVisible({ timeout: 5_000 });
    expect(await page.evaluate(() => window.__trace.lastReport.scanned_via)).toBe('inline');
  });

  test('a silent worker startup times out and falls back inline', async ({ page, browserName }) => {
    test.skip(browserName !== 'chromium', 'one engine is sufficient for the startup deadline');
    await page.addInitScript(() => {
      window.Worker = class extends EventTarget {
        postMessage() {}
        terminate() {}
      };
    });
    await page.goto('/');
    await page.click('#demo-clean');
    await expect(page.locator('.verdict.clear')).toBeVisible({ timeout: 12_000 });
    expect(await page.evaluate(() => window.__trace.lastReport.scanned_via)).toBe('inline');
  });

  test('a structured scan error keeps the worker usable without inline reads', async ({ page }) => {
    await page.addInitScript(() => {
      const stream = File.prototype.stream;
      window.__traceFileStreamCalls = 0;
      window.__traceWorkerPosts = 0;
      File.prototype.stream = function (...args) {
        window.__traceFileStreamCalls += 1;
        return stream.apply(this, args);
      };
      window.Worker = class extends EventTarget {
        constructor() {
          super();
          setTimeout(() => this.dispatchEvent(new MessageEvent('message', {
            data: { type: 'ready' },
          })), 0);
        }
        postMessage(message) {
          if (message.type !== 'scan') return;
          window.__traceWorkerPosts += 1;
          setTimeout(() => this.dispatchEvent(new MessageEvent('message', {
            data: { type: 'error', id: message.id, message: 'scan rejected' },
          })), 0);
        }
        terminate() {}
      };
    });
    await page.goto('/');
    await page.click('#demo-clean');
    await expect(page.locator('.error-box')).toContainText('scan rejected');
    await page.click('#rescan-btn');
    // Returning to the landing page clears the prior case-data DOM.
    await expect(page.locator('#results')).toBeHidden();
    await page.click('#demo-clean');
    await expect(page.locator('#results')).toBeVisible();
    await expect(page.locator('.error-box')).toContainText('scan rejected');
    const counts = await page.evaluate(() => ({
      posts: window.__traceWorkerPosts,
      streams: window.__traceFileStreamCalls,
    }));
    expect(counts.posts).toBe(2);
    expect(counts.streams).toBe(0);
  });

  test('a worker crash during a scan never replays the file inline', async ({ page }) => {
    await page.addInitScript(() => {
      const stream = File.prototype.stream;
      window.__traceFileStreamCalls = 0;
      File.prototype.stream = function (...args) {
        window.__traceFileStreamCalls += 1;
        return stream.apply(this, args);
      };
      window.Worker = class extends EventTarget {
        constructor() {
          super();
          setTimeout(() => this.dispatchEvent(new MessageEvent('message', {
            data: { type: 'ready' },
          })), 0);
        }
        postMessage(message) {
          if (message.type === 'scan') {
            setTimeout(() => this.dispatchEvent(new ErrorEvent('error')), 0);
          }
        }
        terminate() {}
      };
    });
    await page.goto('/');
    await page.click('#demo-clean');
    await expect(page.locator('.error-box')).toContainText(
      'did not retry it on the main page',
      { timeout: 5_000 }
    );
    const state = await page.evaluate(() => ({
      streamCalls: window.__traceFileStreamCalls,
      report: window.__trace.lastReport,
      via: window.__trace.lastScanVia,
    }));
    expect(state.streamCalls).toBe(0);
    expect(state.report).toBeNull();
    expect(state.via).toBe('worker');

    // The failed state is terminal for this page: another user action must
    // not dispatch to the dead worker or silently switch to inline scanning.
    // The previous error DOM is cleared before the next scan begins.
    await page.click('#rescan-btn');
    await expect(page.locator('#results')).toBeHidden();
    await page.click('#demo-clean');
    await expect(page.locator('#results')).toBeVisible();
    await expect(page.locator('.error-box')).toContainText(
      'did not retry it on the main page'
    );
    expect(await page.evaluate(() => window.__traceFileStreamCalls)).toBe(0);
  });
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
  const schema = await page.evaluate(async () =>
    (await fetch('./report.schema.json')).json());
  expect(schema.properties.schema_version.const).toBe(3);
  // offline means the live refresh failed and bundled snapshots were used
  await expect(page.locator('#ioc-list')).toContainText('snapshot');
  await context.setOffline(false);
});

// Report v3 producer parity: the worker and inline producers must emit the
// exact field shape pinned by the Rust golden (which the native producer is
// held to in crates/trace-core/tests/report_v3.rs). Same flattening rules
// as that test: array indices normalize to [], and paths whose contents
// legitimately vary (evidence, details, by_kind) are opaque leaves.
const GOLDEN_FIELDS = path.join(__dirname, '../../crates/trace-core/tests/report_fields_v3.json');
const OPAQUE_PATHS = new Set(['/findings[]/evidence', '/artifacts[]/details', '/indicator_sets[]/by_kind']);

function fieldPaths(v, prefix, out) {
  if (OPAQUE_PATHS.has(prefix)) { out.add(prefix); return; }
  if (Array.isArray(v)) {
    if (!v.length) { out.add(prefix); return; }
    for (const x of v) fieldPaths(x, prefix + '[]', out);
  } else if (v !== null && typeof v === 'object') {
    const keys = Object.keys(v);
    if (!keys.length) { out.add(prefix); return; }
    for (const k of keys) fieldPaths(v[k], prefix + '/' + k, out);
  } else {
    out.add(prefix);
  }
}

test('worker and inline producers emit the golden report shape', async ({ page }) => {
  const golden = new Set(JSON.parse(fs.readFileSync(GOLDEN_FIELDS, 'utf8')));
  await page.goto('/');
  await expect(page.locator('#ioc-panel')).toBeVisible({ timeout: 30_000 });

  await page.click('#demo-infected');
  await expect(page.locator('.verdict.match')).toBeVisible({ timeout: 30_000 });
  const workerReport = await page.evaluate(() => window.__trace.lastReport);

  await page.evaluate(async () => {
    window.__trace.disableWorker();
    const blob = await (await fetch('./fixtures/sysdiagnose_demo_infected.tar.gz')).blob();
    window.__trace.handleFile(new File([blob], 'sysdiagnose_demo_infected.tar.gz'));
  });
  await page.waitForFunction(() => window.__trace.lastReport?.scanned_via === 'inline', null, { timeout: 30_000 });
  const inlineReport = await page.evaluate(() => window.__trace.lastReport);

  expect(workerReport.scanned_via).toBe('worker');
  expect(inlineReport.scanned_via).toBe('inline');
  for (const [producer, report] of [['worker', workerReport], ['inline', inlineReport]]) {
    expect(report.schema_version).toBe(3);
    const got = new Set();
    fieldPaths(report, '', got);
    const missing = [...golden].filter((p) => !got.has(p));
    const extra = [...got].filter((p) => !golden.has(p));
    expect(missing, `${producer} report is missing golden fields`).toEqual([]);
    expect(extra, `${producer} report has fields outside the golden shape`).toEqual([]);
  }
  // Same bytes, same engine-computed hash, regardless of producer.
  expect(workerReport.source_file.sha256).toMatch(/^[0-9a-f]{64}$/);
  expect(inlineReport.source_file.sha256).toBe(workerReport.source_file.sha256);
  // Engine-measured timing (its clock runs through parsing and assembly
  // inside finish; producers no longer supply readings).
  expect(typeof workerReport.duration_ms).toBe('number');
  expect(typeof inlineReport.duration_ms).toBe('number');
  expect(workerReport.generated_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
});

test('the report schema is served at its declared $id path', async ({ page }) => {
  await page.goto('/');
  const schema = await page.evaluate(async () =>
    (await fetch('./report.schema.json')).json());
  expect(schema.$id).toBe('https://tracescan.pages.dev/report.schema.json');
  expect(schema.properties.schema_version.const).toBe(3);
});

test('nullable source metadata renders as unavailable, never as null', async ({ page }) => {
  await page.goto('/');
  await page.click('#demo-clean');
  await expect(page.locator('.verdict.clear')).toBeVisible({ timeout: 30_000 });
  await page.evaluate(() => {
    const report = structuredClone(window.__trace.lastReport);
    report.source_file.name = null;
    report.source_file.size = null;
    window.__trace.renderReport(report);
  });
  const source = page.locator('#results > p.fine').first();
  await expect(source).toContainText('Unknown source file (size unavailable)');
  await expect(source).not.toContainText('null');
});
