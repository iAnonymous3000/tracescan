// End-to-end tests through the real UI: demo scans, verdict rendering,
// report export, the hostile-archive inconclusive path, and the offline
// privacy claim (load once, go offline, scanning still works).
const { test, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');

const BUNDLED_IOC_MANIFEST = path.join(__dirname, '../../web/iocs/manifest.json');
const CORUNA_IOC = path.join(__dirname, '../../web/iocs/coruna.stix2');
const EMPTY_BUNDLE_SHA256 = '736520c9db846d6eb9b018e064d7db14c108b04d27d92032fe34dd4a34710741';

function readBundledIocManifest() {
  return JSON.parse(fs.readFileSync(BUNDLED_IOC_MANIFEST, 'utf8'));
}

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

test('reduced-motion preference makes nonessential scanner motion static', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/');

  const styles = await page.evaluate(() => {
    const dropzone = getComputedStyle(document.querySelector('#dropzone'));
    const progress = getComputedStyle(document.querySelector('#progress'));
    return {
      reducedMotion: matchMedia('(prefers-reduced-motion: reduce)').matches,
      dropzoneTransition: dropzone.transitionDuration,
      progressAppearance: progress.appearance,
      progressAnimation: progress.animationName,
    };
  });

  expect(styles).toEqual({
    reducedMotion: true,
    dropzoneTransition: '0s',
    progressAppearance: 'none',
    progressAnimation: 'none',
  });
});

test('clean demo produces the clear verdict', async ({ page }) => {
  await page.goto('/');
  await page.click('#demo-clean');
  await expect(page.locator('.verdict.clear')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('.example-note')).toContainText(
    'Example result - no device was scanned.'
  );
  await expect(page.locator('.verdict h2')).toHaveText('No known spyware traces found');
  // the honest-epistemics disclaimer must always accompany a clear verdict
  await expect(page.locator('.verdict.clear')).toContainText('not the same as "your phone is clean."');
  // The verdict heading takes focus so a screen reader announces the outcome
  // rather than leaving it on an unnamed container.
  await expect(page.locator('.verdict h2')).toBeFocused();
  await expect(page.locator('#export-btn')).toContainText('includes identifying metadata');
  expect(await page.evaluate(() => {
    const actions = document.querySelector('.report-actions');
    const firstDetail = document.querySelector('#results .finding, #results .panel');
    return Boolean(actions && firstDetail
      && (actions.compareDocumentPosition(firstDetail) & Node.DOCUMENT_POSITION_FOLLOWING));
  })).toBe(true);
});

test('opt-in real capture passes through the browser UI', async ({ page, browserName }) => {
  const capture = process.env.TRACE_REAL_SYSDIAGNOSE;
  test.skip(!capture, 'set TRACE_REAL_SYSDIAGNOSE to a local sysdiagnose archive');
  test.skip(browserName !== 'chromium', 'one Chromium run is sufficient for this private release gate');
  if (!fs.existsSync(capture)) throw new Error(`real capture does not exist: ${capture}`);

  await page.goto('/');
  await page.waitForFunction(() => window.__trace?.ready === true, null, { timeout: 30_000 });
  await page.locator('#file-input').setInputFiles(capture);
  await expect(page.locator('.verdict.clear')).toBeVisible({ timeout: 180_000 });

  const summary = await page.evaluate(() => {
    const report = window.__trace.lastReport;
    const unified = report.artifacts.find((artifact) => artifact.kind === 'unified_log');
    return {
      verdict: report.verdict,
      scanLimits: report.scan_limits,
      missingArtifacts: report.missing_artifacts,
      applicable: report.stats.applicable_indicators,
      nonNoteFindings: report.findings.filter((finding) => finding.severity !== 'note').length,
      unifiedStatus: unified?.status,
      tracev3Failures: unified?.details?.tracev3_parse_failures,
      resolvedProcesses: unified?.details?.processes_resolved_to_path,
      seenProcesses: unified?.details?.processes_seen,
    };
  });
  expect(summary).toMatchObject({
    verdict: 'clear',
    scanLimits: [],
    missingArtifacts: [],
    applicable: 89,
    nonNoteFindings: 0,
    unifiedStatus: 'parsed',
    tracev3Failures: 0,
  });
  expect(summary.seenProcesses).toBeGreaterThan(50);
  expect(summary.resolvedProcesses * 100)
    .toBeGreaterThanOrEqual(summary.seenProcesses * 80);
});

test('a paired-device-only clear report describes its narrow evidence without saying only 0', async ({ page }) => {
  await page.goto('/');
  await page.click('#demo-clean');
  await expect(page.locator('.verdict.clear')).toBeVisible({ timeout: 30_000 });

  const readable = await page.evaluate(async () => {
    const report = structuredClone(window.__trace.lastReport);
    report.artifacts = [{
      path: 'root/logs/ProxiedDevice/watch.ips',
      kind: 'crash_log',
      status: 'parsed',
      details: { paired_device: true },
    }];
    report.stats.artifacts_found = 1;
    report.missing_artifacts = [
      { kind: 'shutdown_log', note: 'not present' },
      { kind: 'crash_log', note: 'not present' },
      { kind: 'ps_listing', note: 'not present' },
      { kind: 'unified_log', note: 'not present' },
    ];
    report.assurance.surfaces_examined = 0;
    for (const surface of report.assurance.surfaces) surface.state = 'absent';
    window.__trace.renderReport(report);
    const { readableReportDocument, readableReportFragment } =
      await import('./readable-report.js');
    return {
      fragment: readableReportFragment(report),
      document: readableReportDocument(report),
    };
  });

  const verdict = page.locator('.verdict.clear');
  await expect(verdict).toContainText(
    'none of the four primary artifact types were examined; this result rests only on paired-device crash reports'
  );
  await expect(verdict).not.toContainText('only 0');
  expect(readable.fragment).toContain('paired-device crash log');
  expect(readable.document).toContain('paired-device crash log');
});

test('unknown, missing, and null verdicts fail closed in both report renderers', async ({ page }) => {
  await page.goto('/');
  await page.click('#demo-clean');
  await expect(page.locator('.verdict.clear')).toBeVisible({ timeout: 30_000 });

  const results = await page.evaluate(async () => {
    const base = structuredClone(window.__trace.lastReport);
    const { readableReportDocument, readableReportFragment } =
      await import('./readable-report.js');
    const cases = ['unknown', 'missing', 'null'];
    const observed = [];
    for (const label of cases) {
      const report = structuredClone(base);
      if (label === 'unknown') report.verdict = 'future-verdict';
      if (label === 'missing') delete report.verdict;
      if (label === 'null') report.verdict = null;

      window.__trace.renderReport(report);
      const mainVerdict = document.querySelector('.verdict');
      const readable = new DOMParser().parseFromString(
        readableReportFragment(report),
        'text/html'
      );
      const readableDocument = new DOMParser().parseFromString(
        readableReportDocument(report),
        'text/html'
      );
      observed.push({
        label,
        mainClass: mainVerdict.className,
        mainTitle: mainVerdict.querySelector('h2').textContent,
        mainHasClear: mainVerdict.classList.contains('clear'),
        readableVerdict: readable.querySelector('.readable-report').dataset.verdict,
        readableTitle: readable.querySelector('h1').textContent,
        documentTitle: readableDocument.title,
      });
    }
    return observed;
  });

  for (const result of results) {
    expect(result.mainClass, result.label).toBe('verdict inconclusive');
    expect(result.mainTitle, result.label).toBe('Scan incomplete - result inconclusive');
    expect(result.mainHasClear, result.label).toBe(false);
    expect(result.readableVerdict, result.label).toBe('inconclusive');
    expect(result.readableTitle, result.label).toBe('Scan incomplete - result inconclusive');
    expect(result.documentTitle, result.label).toBe(
      'Trace report - Scan incomplete - result inconclusive'
    );
  }
});

test('infected demo produces the match verdict with helplines', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 568 });
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
  expect(await page.evaluate(() => ({
    viewport: window.innerWidth,
    document: document.documentElement.scrollWidth,
  }))).toEqual({ viewport: 320, document: 320 });
  const findingCount = await page.locator('.finding').count();
  await expect(page.locator('.finding[aria-labelledby]')).toHaveCount(findingCount);
  await expect(page.locator('.finding summary')).toHaveCount(findingCount);
  await expect(page.locator('[aria-label^="Indicator source for "]')).toHaveCount(8);
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
  await expect(page.locator('#scan-error-heading')).toBeFocused();
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
  await expect(preview.locator('.example-notice')).toContainText(
    'Example report - no device was scanned.'
  );
  await expect(preview).toContainText(identity.hash);
  await expect(preview).toContainText('No verdict-relevant scan limit was recorded.');
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
  expect(download.suggestedFilename()).toMatch(
    /^trace-example-readable-report-\d{8}T\d{6}Z-[0-9a-f]{8}\.html$/
  );
  const html = fs.readFileSync(await download.path(), 'utf8');
  expect(html).toContain('<!doctype html>');
  expect(html).toContain(identity.hash);
  expect(html).not.toContain(identity.name);
  expect(html).not.toContain(identity.artifact);
  expect(html).not.toContain('<script');
  expect(html).toContain('not digitally signed');
  expect(html).toContain('redacted from this readable copy');
  expect(html).toContain('This readable HTML is a reduced convenience copy');
  expect(html).toContain('No verdict-relevant scan limit was recorded.');
  expect(html).toContain('.verification a::after');
  expect(html).toContain('attr(href)');
  expect(html).toContain('<title>Example Trace report -');
  expect(html).toContain('Example report - no device was scanned.');
});

test('withholding device metadata strips it from technical details and evidence too', async ({ page }) => {
  await page.goto('/');
  const OS = 'iPhone OS 18.5 (22F76)';
  const TS = '2026-07-01 10:00:00.00 +0000';
  const result = await page.evaluate(async ({ os, ts }) => {
    const { readableReportDocument } = await import('./readable-report.js');
    const report = {
      schema_version: 4,
      verdict: 'clear',
      generated_at: '2026-07-17T00:00:00.000Z',
      tool: { name: 'Trace', version: '0.7.3', build_commit: null },
      source_file: { name: 'x.tar.gz', size: 100, sha256: 'a'.repeat(64) },
      device: { os_version: os, source: 'crashes_and_spins/a.ips', timestamp: ts },
      indicator_provenance: [],
      artifacts: [{
        path: 'crashes_and_spins/a.ips', kind: 'crash_log', status: 'parsed',
        details: { process: 'a', os_version: os, timestamp: ts, bug_type: '309' },
      }],
      missing_artifacts: [],
      findings: [{
        severity: 'note', kind: 'heuristic', artifact: 'crashes_and_spins/a.ips',
        summary: 'note', evidence: { timestamp: ts, process: 'a' },
      }],
      scan_limits: [],
      coverage: { examined: [], not_examined: [], note: '' },
    };
    return {
      // Device withheld but technical details on: the redaction promise must
      // still hold - the OS build and capture timestamp identify the device.
      withheld: readableReportDocument(report, { includeDevice: false, includeTechnical: true }),
      // Device included: the same fields are present.
      shown: readableReportDocument(report, { includeDevice: true, includeTechnical: true }),
    };
  }, { os: OS, ts: TS });
  expect(result.withheld).toContain('Device metadata redacted from this readable copy');
  expect(result.withheld).not.toContain(OS);
  expect(result.withheld).not.toContain(TS);
  expect(result.shown).toContain(OS);
  expect(result.shown).toContain(TS);
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

test('readable provenance reports partial and zero-applicable campaign coverage', async ({ page }) => {
  await page.goto('/');
  const result = await page.evaluate(async () => {
    const { readableReportFragment } = await import('./readable-report.js');
    const report = {
      indicator_sets: [
        {
          name: 'pegasus', campaign: 'Pegasus (NSO Group)',
          extracted: 1549, applicable: 81,
        },
        {
          name: 'wintego_helios', campaign: 'Wintego Helios',
          extracted: 175, applicable: 0,
        },
      ],
      // Deliberately reverse provenance order: coverage must join by stable
      // set identity, not by array position.
      indicator_provenance: [
        {
          name: 'wintego_helios', campaign: 'Wintego Helios',
          date: '2024-05-02', sha256: 'b'.repeat(64),
        },
        {
          name: 'pegasus', campaign: 'Pegasus (NSO Group)',
          date: '2021-07-18', sha256: 'a'.repeat(64),
        },
      ],
    };
    const parsed = new DOMParser().parseFromString(
      readableReportFragment(report),
      'text/html'
    );
    const provenance = parsed.querySelector('[aria-label="Indicator provenance"]');
    return {
      headers: [...provenance.querySelectorAll('th')].map((cell) => cell.textContent),
      rows: [...provenance.querySelectorAll('tbody tr')].map((row) =>
        [...row.cells].map((cell) => cell.textContent.trim())),
      note: provenance.nextElementSibling.textContent,
    };
  });

  expect(result.headers).toEqual([
    'Campaign', 'Applicable to negative process coverage', 'Snapshot date', 'Indicator SHA-256',
  ]);
  expect(result.rows).toEqual([
    ['Wintego Helios', '0 of 175', '2024-05-02', 'b'.repeat(64)],
    ['Pegasus (NSO Group)', '81 of 1549', '2021-07-18', 'a'.repeat(64)],
  ]);
  expect(result.note).toContain(
    'file-name and file-path indicators can still produce exact positive matches'
  );
  expect(result.note).toContain(
    'A count of 0 means this set contributes no reviewed negative process coverage'
  );
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
  expect(download.suggestedFilename()).toMatch(
    /^trace-example-technical-report-\d{8}T\d{6}Z-[0-9a-f]{8}\.json$/
  );
  const report = JSON.parse(fs.readFileSync(await download.path(), 'utf8'));
  expect(report.tool.name).toBe('Trace');
  expect(report.stats.applicable_indicators).toBeGreaterThan(0);
  expect(report.indicator_provenance.length).toBeGreaterThan(0);
  for (const p of report.indicator_provenance) {
    expect(p.sha256).toMatch(/^[0-9a-f]{64}$/);
  }

  const secondDownloadPromise = page.waitForEvent('download');
  await page.click('#export-btn');
  const secondDownload = await secondDownloadPromise;
  expect(secondDownload.suggestedFilename()).not.toBe(download.suggestedFilename());
});

test('indicator provenance renders source links only for absolute HTTPS URLs', async ({ page }) => {
  await page.goto('/');
  await page.click('#demo-clean');
  await expect(page.locator('.verdict.clear')).toBeVisible({ timeout: 30_000 });

  const result = await page.evaluate(() => {
    const base = structuredClone(window.__trace.lastReport);
    const originalUrl = base.indicator_provenance[0].url;
    const sources = [
      ['https', originalUrl],
      ['http', 'http://example.invalid/indicators.stix2'],
      ['javascript', 'javascript:window.__traceProvenanceExecuted=true'],
      ['data', 'data:text/html,unsafe'],
      ['relative', '/local-indicators.stix2'],
      ['malformed', 'not a URL'],
    ].map(([label, url]) => {
      const report = structuredClone(base);
      report.indicator_provenance[0].url = url;
      window.__trace.renderReport(report);
      const row = document.querySelector('#results .ioc-row');
      const link = row.querySelector('a');
      return {
        label,
        href: link?.getAttribute('href') ?? null,
        text: row.textContent,
      };
    });
    return { originalUrl, sources };
  });

  expect(result.sources[0]).toMatchObject({
    label: 'https',
    href: result.originalUrl,
  });
  for (const source of result.sources.slice(1)) {
    expect(source.href, source.label).toBeNull();
    expect(source.text, source.label).toContain('source unavailable');
  }
  expect(await page.evaluate(() => window.__traceProvenanceExecuted)).toBeUndefined();
});

test('main and readable reports cap artifact rows without changing the JSON report', async ({ page }) => {
  await page.goto('/');
  await page.click('#demo-clean');
  await expect(page.locator('.verdict.clear')).toBeVisible({ timeout: 30_000 });

  const result = await page.evaluate(async () => {
    const report = structuredClone(window.__trace.lastReport);
    const template = report.artifacts[0];
    report.artifacts = Array.from({ length: 245 }, (_, index) => ({
      ...structuredClone(template),
      path: `root/very-long-artifact-path-${index}.log`,
    }));
    report.missing_artifacts = [];
    window.__trace.renderReport(report);
    const { readableReportFragment } = await import('./readable-report.js');
    const parsed = new DOMParser().parseFromString(
      readableReportFragment(report, { includeTechnical: true }),
      'text/html'
    );
    const artifactSection = [...parsed.querySelectorAll('.report-section')].find(
      (section) => section.querySelector('h2')?.textContent === 'What Trace examined'
    );
    return {
      reportArtifacts: window.__trace.lastReport.artifacts.length,
      readableRows: artifactSection.querySelectorAll('tbody tr').length,
      readableText: parsed.body.textContent,
    };
  });

  await expect(page.locator('.artifacts tbody tr')).toHaveCount(200);
  await expect(page.locator('.panel', { hasText: 'What was examined' })).toContainText(
    'Showing the first 200 processed artifacts; 45 more remain'
  );
  expect(result.reportArtifacts).toBe(245);
  expect(result.readableRows).toBeLessThanOrEqual(204);
  expect(result.readableText).toContain(
    'This readable copy shows the first 200 processed artifacts. 45 additional artifacts remain'
  );
});

test('a zero-artifact invalid report still renders its missing-artifact inventory', async ({ page }) => {
  await page.goto('/');
  await page.click('#demo-clean');
  await expect(page.locator('.verdict.clear')).toBeVisible({ timeout: 30_000 });

  const readableText = await page.evaluate(async () => {
    const report = structuredClone(window.__trace.lastReport);
    report.verdict = 'invalid';
    report.artifacts = [];
    report.stats.artifacts_found = 0;
    report.missing_artifacts = [
      { kind: 'shutdown_log', note: 'No shutdown log was found.' },
      { kind: 'crash_log', note: 'No process-bearing crash report was found.' },
      { kind: 'ps_listing', note: 'No process listing was found.' },
      { kind: 'unified_log', note: 'No unified log was found.' },
    ];
    window.__trace.renderReport(report);
    const { readableReportFragment } = await import('./readable-report.js');
    return new DOMParser().parseFromString(
      readableReportFragment(report, { includeTechnical: true }),
      'text/html'
    ).body.textContent;
  });

  await expect(page.locator('.artifacts tbody tr')).toHaveCount(4);
  await expect(page.locator('.artifacts')).toContainText('not applicable');
  await expect(page.locator('.artifacts')).toContainText('No process-bearing crash report was found.');
  expect(readableText).toContain('No process-bearing crash report was found.');
});

test.describe('scanner readiness and optional freshness', () => {
  test.use({ serviceWorkers: 'block' });

  test('controls stay disabled until bundled indicators pass validation', async ({ page }) => {
    await page.route('**/iocs/manifest.json', async (route) => {
      await new Promise((resolve) => setTimeout(resolve, 500));
      await route.continue();
    });
    await page.route('https://raw.githubusercontent.com/**', (route) => route.abort());
    await page.goto('/');

    await expect(page.locator('#scanner-status')).toHaveClass(/preparing/);
    await expect(page.locator('#demo-clean')).toBeDisabled();
    await expect(page.locator('#file-input')).toBeDisabled();
    await expect(page.locator('#dropzone')).toHaveAttribute('aria-disabled', 'true');

    await expect(page.locator('#scanner-status')).toHaveClass(/ready/, { timeout: 30_000 });
    await expect(page.locator('#scanner-status')).toContainText('passed their integrity checks');
    await expect(page.locator('#demo-clean')).toBeEnabled();
    await expect(page.locator('#file-input')).toBeEnabled();
    await expect(page.locator('#dropzone')).toHaveAttribute('aria-disabled', 'false');
  });

  test('an invalid bundled roster is rejected before any indicator set is fetched', async ({ page }) => {
    let bundleRequests = 0;
    await page.route('**/iocs/*.stix2', async (route) => {
      bundleRequests += 1;
      await route.continue();
    });
    await page.route('**/iocs/manifest.json', (route) => {
      const manifest = readBundledIocManifest();
      [manifest.sets[0], manifest.sets[1]] = [manifest.sets[1], manifest.sets[0]];
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(manifest),
      });
    });
    await page.route('https://raw.githubusercontent.com/**', (route) => route.abort());
    await page.goto('/');

    await expect(page.locator('#scanner-status')).toHaveClass(/error/, { timeout: 30_000 });
    await expect(page.locator('#scanner-status')).toContainText(
      'bundled indicator manifest failed its reviewed roster and SHA-256 pin check'
    );
    expect(bundleRequests).toBe(0);
    expect(await page.evaluate(() => window.__trace.ready)).toBe(false);
    await expect(page.locator('#demo-clean')).toBeDisabled();
    await expect(page.locator('#file-input')).toBeDisabled();
  });

  test('a bundled indicator SHA-256 mismatch disables scanning', async ({ page }) => {
    await page.route('**/iocs/coruna.stix2', (route) => route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: `${fs.readFileSync(CORUNA_IOC, 'utf8')}\n`,
    }));
    await page.route('https://raw.githubusercontent.com/**', (route) => route.abort());
    await page.goto('/');

    await expect(page.locator('#scanner-status')).toHaveClass(/error/, { timeout: 30_000 });
    await expect(page.locator('#scanner-status')).toContainText(
      'Bundled indicator set "coruna" failed its reviewed SHA-256 check'
    );
    expect(await page.evaluate(() => window.__trace.ready)).toBe(false);
    await expect(page.locator('#demo-clean')).toBeDisabled();
    await expect(page.locator('#demo-infected')).toBeDisabled();
    await expect(page.locator('#file-input')).toBeDisabled();
  });

  test('slow optional upstream requests do not delay scanning', async ({ page }) => {
    await page.route('https://raw.githubusercontent.com/**', async (route) => {
      await new Promise((resolve) => setTimeout(resolve, 2_000));
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'access-control-allow-origin': '*' },
        body: '{"objects":[]}',
      });
    });
    await page.goto('/');
    await expect(page.locator('#demo-clean')).toBeEnabled({ timeout: 30_000 });
    expect(await page.evaluate(() => Promise.race([
      window.__trace.freshnessReady.then(() => 'done'),
      new Promise((resolve) => setTimeout(() => resolve('pending'), 50)),
    ]))).toBe('pending');
    await page.click('#demo-clean');
    await expect(page.locator('.verdict.clear')).toBeVisible({ timeout: 30_000 });
  });

  test('an oversized upstream body is treated as unknown', async ({ page }) => {
    await page.addInitScript(() => { window.__TRACE_TEST_UPSTREAM_MAX_BYTES = 64; });
    await page.route('https://raw.githubusercontent.com/**', (route) => route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: { 'access-control-allow-origin': '*' },
      body: JSON.stringify({ objects: [{ type: 'indicator', pattern: 'x'.repeat(200) }] }),
    }));
    await page.goto('/');
    await page.waitForFunction(() => window.__trace.ready);
    await page.evaluate(() => window.__trace.freshnessReady);
    await expect(page.locator('#ioc-list .freshness-unknown')).toHaveCount(8);
    await expect(page.locator('#ioc-note')).toContainText('freshness is currently unknown');
  });
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
    await page.waitForFunction(() => window.__trace.ready);
    await page.evaluate(() => window.__trace.freshnessReady);
    await expect(page.locator('#ioc-list .badge.bundled')).toHaveCount(8);
    await expect(page.locator('#ioc-list .freshness-unknown')).toHaveCount(8);
    await expect(page.locator('#ioc-note')).toContainText('freshness is currently unknown');
    await expect(page.locator('#ioc-note')).not.toContainText('content was detected');
    // and scanning with the snapshots still detects the seeded indicator
    await page.click('#demo-infected');
    await expect(page.locator('.verdict.match')).toBeVisible({ timeout: 30_000 });
  });

  test('a bundled indicator set below its reviewed floor disables scanning', async ({ page }) => {
    await page.route('**/iocs/manifest.json', (route) => {
      const manifest = readBundledIocManifest();
      manifest.sets.find((set) => set.name === 'coruna').sha256 = EMPTY_BUNDLE_SHA256;
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(manifest),
      });
    });
    await page.route('**/iocs/coruna.stix2', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: '{"objects":[]}',
      })
    );
    await page.route('https://raw.githubusercontent.com/**', (route) => route.abort());
    await page.goto('/');

    await expect(page.locator('#ioc-panel')).toBeVisible({ timeout: 30_000 });
    await expect(page.locator('#ioc-note')).toContainText(
      'Bundled indicator set "coruna" is below its reviewed floor'
    );
    expect(await page.evaluate(() => window.__trace.ready)).toBe(false);

    await expect(page.locator('#scanner-status')).toContainText(
      'Bundled indicator set "coruna" is below its reviewed floor'
    );
    await expect(page.locator('#scanner-status')).toHaveClass(/error/);
    await expect(page.locator('#demo-clean')).toBeDisabled();
    await expect(page.locator('#demo-infected')).toBeDisabled();
    await expect(page.locator('#file-input')).toBeDisabled();
    await expect(page.locator('#dropzone')).toHaveAttribute('aria-disabled', 'true');
    await expect(page.locator('.verdict.clear')).toHaveCount(0);
    expect(await page.evaluate(() => window.__trace.lastReport)).toBeNull();
  });

  test('the background worker independently rejects a set below its reviewed floor', async ({ page, browserName }) => {
    test.skip(browserName !== 'chromium', 'one engine is sufficient for the worker boundary');
    await page.route('https://raw.githubusercontent.com/**', (route) => route.abort());
    await page.goto('/');

    const message = await page.evaluate(() => new Promise((resolve, reject) => {
      const worker = new Worker('./worker.js', { type: 'module' });
      const timeout = setTimeout(() => {
        worker.terminate();
        reject(new Error('background worker did not respond'));
      }, 15_000);
      worker.addEventListener('error', (event) => {
        clearTimeout(timeout);
        worker.terminate();
        reject(new Error(event.message || 'background worker crashed'));
      });
      worker.addEventListener('message', (event) => {
        if (event.data?.type === 'ready') {
          worker.postMessage({
            type: 'scan',
            id: 77,
            file: new File([], 'reviewed-floor.tar'),
            sets: [{
              name: 'below-floor',
              text: '{"objects":[]}',
              meta: {},
              min_indicators: 1,
              min_applicable: 1,
            }],
          });
        } else if (event.data?.type === 'init-error') {
          clearTimeout(timeout);
          worker.terminate();
          reject(new Error(event.data.message));
        } else if (event.data?.type === 'error' && event.data.id === 77) {
          clearTimeout(timeout);
          worker.terminate();
          resolve(event.data.message);
        }
      });
    }));

    expect(message).toContain(
      'Bundled indicator set "below-floor" is below its reviewed floor in the background scanner.'
    );
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
    await page.waitForFunction(() => window.__trace.ready);
    await page.evaluate(() => window.__trace.freshnessReady);
    // A hash difference is announced neutrally, not claimed to be newer.
    await expect(page.locator('#ioc-note')).toContainText(
      'Different plausible upstream content was detected'
    );
    await expect(page.locator('#ioc-note')).toContainText(
      'does not prove that the upstream content is newer'
    );
    await expect(page.locator('#ioc-note')).not.toContainText('has published newer');
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

test.describe('scan intent and cancellation', () => {
  test.use({ serviceWorkers: 'block' });

  test('a delayed demo completion cannot overwrite a later real-file scan', async ({ page }) => {
    let releaseDemo;
    const heldDemo = new Promise((resolve) => { releaseDemo = resolve; });
    await page.route('**/fixtures/sysdiagnose_demo_clean.tar.gz', async (route) => {
      await heldDemo;
      await route.continue();
    });
    await page.route('https://raw.githubusercontent.com/**', (route) => route.abort());
    await page.goto('/');
    await page.click('#demo-clean');
    await expect(page.locator('#scanner-status')).toContainText('Loading the synthetic example');

    await page.evaluate(async () => {
      const infected = await (await fetch(
        './fixtures/sysdiagnose_demo_infected.tar.gz'
      )).blob();
      window.__trace.handleFile(new File([infected], 'real-case.tar.gz'));
    });
    await expect(page.locator('.verdict.match')).toBeVisible({ timeout: 30_000 });
    releaseDemo();
    await page.waitForTimeout(500);

    await expect(page.locator('.verdict.match')).toBeVisible();
    await expect(page.locator('.example-note')).toHaveCount(0);
    expect(await page.evaluate(() => window.__trace.lastReport.source_file.name)).toBe(
      'real-case.tar.gz'
    );
  });

  test('worker finalization is indeterminate and can be safely canceled', async ({ page }) => {
    await page.addInitScript(() => {
      window.Worker = class extends EventTarget {
        constructor() {
          super();
          setTimeout(() => this.dispatchEvent(new MessageEvent('message', {
            data: { type: 'ready' },
          })), 0);
        }
        postMessage(message) {
          if (message.type !== 'scan') return;
          setTimeout(() => this.dispatchEvent(new MessageEvent('message', {
            data: {
              type: 'progress',
              id: message.id,
              processed: Math.floor(message.file.size / 2),
            },
          })), 10);
          setTimeout(() => this.dispatchEvent(new MessageEvent('message', {
            data: { type: 'finalizing', id: message.id },
          })), 20);
        }
        terminate() {}
      };
    });
    await page.route('https://raw.githubusercontent.com/**', (route) => route.abort());
    await page.goto('/');
    await page.click('#demo-clean');
    await expect(page.locator('#scan-file')).toHaveText('sysdiagnose_demo_clean.tar.gz');
    await expect(page.locator('#scan-heading')).toHaveText('Analyzing evidence…');
    await expect(page.locator('#progress')).not.toHaveAttribute('value');
    await page.click('#cancel-scan');

    await expect(page.locator('#landing')).toBeVisible();
    await expect(page.locator('#scanner-status')).toContainText('Scan canceled');
    expect(await page.evaluate(() => window.__trace.lastReport)).toBeNull();
  });

  test('inline streaming cancellation discards the scan and report', async ({ page }) => {
    await page.addInitScript(() => {
      window.Worker = class { constructor() { throw new Error('worker unavailable'); } };
    });
    await page.route('https://raw.githubusercontent.com/**', (route) => route.abort());
    await page.goto('/');
    await page.evaluate(() => {
      const file = new File([new Uint8Array(4096)], 'slow-real-case.tar');
      Object.defineProperty(file, 'stream', {
        value: () => new ReadableStream({
          start(controller) {
            this.timer = setInterval(() => controller.enqueue(new Uint8Array(64)), 100);
          },
          cancel() {
            clearInterval(this.timer);
            window.__traceInlineStreamCanceled = true;
          },
        }),
      });
      window.__trace.handleFile(file);
    });
    await expect(page.locator('#scan-heading')).toHaveText('Reading archive…');
    await expect(page.locator('#progress-text')).toContainText(
      'Background isolation is unavailable'
    );
    await page.click('#cancel-scan');

    await expect(page.locator('#landing')).toBeVisible();
    await expect(page.locator('#scanner-status')).toContainText('Scan canceled');
    expect(await page.evaluate(() => ({
      report: window.__trace.lastReport,
      streamCanceled: window.__traceInlineStreamCanceled,
    }))).toEqual({ report: null, streamCanceled: true });
  });
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

  test('a silent in-flight worker times out, is recycled, and never replays inline', async ({ page, browserName }) => {
    test.skip(browserName !== 'chromium', 'one engine is sufficient for the scan deadline');
    await page.addInitScript(() => {
      const stream = File.prototype.stream;
      window.__TRACE_TEST_WORKER_TIMEOUT_MS = 50;
      window.__traceFileStreamCalls = 0;
      window.__traceWorkerConstructed = 0;
      window.__traceWorkerPosts = [];
      window.__traceWorkerTerminated = [];
      File.prototype.stream = function (...args) {
        window.__traceFileStreamCalls += 1;
        return stream.apply(this, args);
      };
      window.Worker = class extends EventTarget {
        constructor() {
          super();
          this.instance = ++window.__traceWorkerConstructed;
          setTimeout(() => this.dispatchEvent(new MessageEvent('message', {
            data: { type: 'ready' },
          })), 0);
        }
        postMessage(message) {
          if (message.type === 'scan') {
            window.__traceWorkerPosts.push(this.instance);
          }
        }
        terminate() {
          window.__traceWorkerTerminated.push(this.instance);
        }
      };
    });
    await page.goto('/');
    await page.click('#demo-clean');
    await expect(page.locator('.error-box')).toContainText(
      'did not retry it on the main page',
      { timeout: 5_000 }
    );
    await page.waitForFunction(() => window.__traceWorkerConstructed >= 2);
    const state = await page.evaluate(() => ({
      constructed: window.__traceWorkerConstructed,
      posts: window.__traceWorkerPosts,
      terminated: window.__traceWorkerTerminated,
      streams: window.__traceFileStreamCalls,
      report: window.__trace.lastReport,
      via: window.__trace.lastScanVia,
    }));
    expect(state.constructed).toBe(2);
    expect(state.posts).toEqual([1]);
    expect(state.terminated).toEqual([1]);
    expect(state.streams).toBe(0);
    expect(state.report).toBeNull();
    expect(state.via).toBe('worker');
  });

  test('a structured scan error replaces the worker without inline reads', async ({ page }) => {
    await page.addInitScript(() => {
      const stream = File.prototype.stream;
      window.__traceFileStreamCalls = 0;
      window.__traceWorkerConstructed = 0;
      window.__traceWorkerPosts = [];
      window.__traceWorkerTerminated = [];
      File.prototype.stream = function (...args) {
        window.__traceFileStreamCalls += 1;
        return stream.apply(this, args);
      };
      window.Worker = class extends EventTarget {
        constructor() {
          super();
          this.instance = ++window.__traceWorkerConstructed;
          setTimeout(() => this.dispatchEvent(new MessageEvent('message', {
            data: { type: 'ready' },
          })), 0);
        }
        postMessage(message) {
          if (message.type !== 'scan') return;
          window.__traceWorkerPosts.push(this.instance);
          setTimeout(() => this.dispatchEvent(new MessageEvent('message', {
            data: { type: 'error', id: message.id, message: 'scan rejected' },
          })), 0);
        }
        terminate() {
          window.__traceWorkerTerminated.push(this.instance);
        }
      };
    });
    await page.goto('/');
    await page.click('#demo-clean');
    await expect(page.locator('.error-box')).toContainText('scan rejected');
    await page.waitForFunction(() => window.__traceWorkerConstructed >= 2);
    await page.click('#rescan-btn');
    // Returning to the landing page clears the prior case-data DOM.
    await expect(page.locator('#results')).toBeHidden();
    await page.click('#demo-clean');
    await expect(page.locator('#results')).toBeVisible();
    await expect(page.locator('.error-box')).toContainText('scan rejected');
    await page.waitForFunction(() => window.__traceWorkerConstructed >= 3);
    const counts = await page.evaluate(() => ({
      constructed: window.__traceWorkerConstructed,
      posts: window.__traceWorkerPosts,
      terminated: window.__traceWorkerTerminated,
      streams: window.__traceFileStreamCalls,
    }));
    expect(counts.constructed).toBe(3);
    expect(counts.posts).toEqual([1, 2]);
    expect(counts.terminated).toEqual([1, 2]);
    expect(counts.streams).toBe(0);
  });

  test('a hard worker crash fails closed and the next scan uses a fresh worker', async ({ page }) => {
    await page.addInitScript(() => {
      const NativeWorker = window.Worker;
      const stream = File.prototype.stream;
      window.__traceFileStreamCalls = 0;
      window.__traceWorkerConstructed = 0;
      window.__traceWorkerPosts = [];
      window.__traceWorkerTerminated = [];
      window.__traceWorkerReadyMessages = 0;
      File.prototype.stream = function (...args) {
        window.__traceFileStreamCalls += 1;
        return stream.apply(this, args);
      };
      window.Worker = class extends EventTarget {
        constructor(...args) {
          super();
          this.instance = ++window.__traceWorkerConstructed;
          this.native = new NativeWorker(...args);
          this.native.addEventListener('message', (event) => {
            if (event.data?.type === 'ready') window.__traceWorkerReadyMessages += 1;
            this.dispatchEvent(new MessageEvent('message', { data: event.data }));
          });
          this.native.addEventListener('error', (event) => {
            this.dispatchEvent(new ErrorEvent('error', {
              message: event.message,
              filename: event.filename,
              lineno: event.lineno,
              colno: event.colno,
              error: event.error,
            }));
          });
          this.native.addEventListener('messageerror', () => {
            this.dispatchEvent(new MessageEvent('messageerror'));
          });
        }
        postMessage(message, ...rest) {
          if (message.type === 'scan') {
            window.__traceWorkerPosts.push(this.instance);
            if (this.instance === 1) {
              setTimeout(() => this.dispatchEvent(new ErrorEvent('error', {
                message: 'simulated worker crash',
              })), 0);
              return;
            }
          }
          this.native.postMessage(message, ...rest);
        }
        terminate() {
          window.__traceWorkerTerminated.push(this.instance);
          this.native.terminate();
        }
      };
    });
    await page.goto('/');
    await page.click('#demo-clean');
    await expect(page.locator('.error-box')).toContainText(
      'did not retry it',
      { timeout: 30_000 }
    );
    expect(await page.evaluate(() => window.__trace.lastReport)).toBeNull();
    await page.waitForFunction(() => window.__traceWorkerConstructed >= 2);
    await page.waitForFunction(() => window.__traceWorkerReadyMessages >= 2);

    await page.click('#rescan-btn');
    await page.click('#demo-clean');
    await expect(page.locator('.verdict.clear')).toBeVisible({ timeout: 30_000 });
    const state = await page.evaluate(() => ({
      constructed: window.__traceWorkerConstructed,
      posts: window.__traceWorkerPosts,
      terminated: window.__traceWorkerTerminated,
      streams: window.__traceFileStreamCalls,
      report: window.__trace.lastReport,
      via: window.__trace.lastScanVia,
    }));
    expect(state.constructed).toBe(2);
    expect(state.posts).toEqual([1, 2]);
    expect(state.terminated).toEqual([1]);
    expect(state.streams).toBe(0);
    expect(state.report.verdict).toBe('clear');
    expect(state.report.scanned_via).toBe('worker');
    expect(state.via).toBe('worker');
  });

  test('a failed replacement worker keeps the next retry fail closed', async ({ page }) => {
    await page.addInitScript(() => {
      const stream = File.prototype.stream;
      window.__traceFileStreamCalls = 0;
      window.__traceWorkerConstructed = 0;
      window.__traceWorkerPosts = [];
      window.__traceWorkerTerminated = [];
      File.prototype.stream = function (...args) {
        window.__traceFileStreamCalls += 1;
        return stream.apply(this, args);
      };
      window.Worker = class extends EventTarget {
        constructor() {
          super();
          this.instance = ++window.__traceWorkerConstructed;
          setTimeout(() => this.dispatchEvent(new MessageEvent('message', {
            data: this.instance === 1
              ? { type: 'ready' }
              : { type: 'init-error', message: 'replacement failed' },
          })), 0);
        }
        postMessage(message) {
          if (message.type !== 'scan') return;
          window.__traceWorkerPosts.push(this.instance);
          setTimeout(() => this.dispatchEvent(new ErrorEvent('error', {
            message: 'simulated worker crash',
          })), 0);
        }
        terminate() {
          window.__traceWorkerTerminated.push(this.instance);
        }
      };
    });
    await page.goto('/');
    await page.click('#demo-clean');
    await expect(page.locator('.error-box')).toContainText(
      'did not retry it on the main page',
      { timeout: 10_000 }
    );
    await page.waitForFunction(() =>
      window.__traceWorkerConstructed === 2
        && window.__traceWorkerTerminated.includes(2));

    await page.click('#rescan-btn');
    await page.click('#demo-clean');
    await expect(page.locator('.error-box')).toContainText(
      'background scanner could not be restarted',
      { timeout: 10_000 }
    );
    const state = await page.evaluate(() => ({
      constructed: window.__traceWorkerConstructed,
      posts: window.__traceWorkerPosts,
      terminated: window.__traceWorkerTerminated,
      streams: window.__traceFileStreamCalls,
      report: window.__trace.lastReport,
      via: window.__trace.lastScanVia,
    }));
    expect(state.constructed).toBe(2);
    expect(state.posts).toEqual([1]);
    expect(state.terminated).toEqual([1, 2]);
    expect(state.streams).toBe(0);
    expect(state.report).toBeNull();
    expect(state.via).toBe('worker');
    await expect(page.locator('.verdict')).toHaveCount(0);
  });

  test('a malformed worker object report is rejected without an inline replay', async ({ page }) => {
    await page.addInitScript(() => {
      const stream = File.prototype.stream;
      window.__traceFileStreamCalls = 0;
      window.__traceWorkerConstructed = 0;
      window.__traceWorkerTerminated = [];
      File.prototype.stream = function (...args) {
        window.__traceFileStreamCalls += 1;
        return stream.apply(this, args);
      };
      window.Worker = class extends EventTarget {
        constructor() {
          super();
          this.instance = ++window.__traceWorkerConstructed;
          setTimeout(() => this.dispatchEvent(new MessageEvent('message', {
            data: { type: 'ready' },
          })), 0);
        }
        postMessage(message) {
          if (message.type !== 'scan') return;
          setTimeout(() => this.dispatchEvent(new MessageEvent('message', {
            data: {
              type: 'report',
              id: message.id,
              report: {
                schema_version: 4,
                tool: { name: 'Trace' },
                verdict: 'clear',
                scanned_via: 'worker',
              },
            },
          })), 0);
        }
        terminate() {
          window.__traceWorkerTerminated.push(this.instance);
        }
      };
    });
    await page.goto('/');
    await page.click('#demo-clean');
    await expect(page.locator('.error-box')).toContainText(
      'did not retry it on the main page'
    );
    await page.waitForFunction(() => window.__traceWorkerConstructed >= 2);
    const state = await page.evaluate(() => ({
      constructed: window.__traceWorkerConstructed,
      terminated: window.__traceWorkerTerminated,
      streams: window.__traceFileStreamCalls,
      report: window.__trace.lastReport,
      via: window.__trace.lastScanVia,
    }));
    expect(state.constructed).toBe(2);
    expect(state.terminated).toEqual([1]);
    expect(state.streams).toBe(0);
    expect(state.report).toBeNull();
    expect(state.via).toBe('worker');
  });

  test('inconsistent clear envelopes proxied from a real worker fail closed', async ({ page, browserName }) => {
    test.skip(browserName !== 'chromium', 'one engine is sufficient for the worker envelope boundary');
    await page.addInitScript(() => {
      const NativeWorker = window.Worker;
      const pageFileStream = File.prototype.stream;
      window.__traceEnvelopeVariant = 'bytes_read';
      window.__traceEnvelopeMutations = [];
      window.__tracePageFileStreamCalls = 0;
      File.prototype.stream = function (...args) {
        window.__tracePageFileStreamCalls += 1;
        return pageFileStream.apply(this, args);
      };

      window.Worker = class extends EventTarget {
        constructor(...args) {
          super();
          this.nativeWorker = new NativeWorker(...args);
          this.nativeWorker.addEventListener('message', (event) => {
            const data = structuredClone(event.data);
            if (data?.type === 'report') {
              const variant = window.__traceEnvelopeVariant;
              window.__traceEnvelopeMutations.push({
                variant,
                originalVerdict: data.report.verdict,
                originalSchema: data.report.schema_version,
                originalSha256: data.report.source_file.sha256,
              });
              if (variant === 'bytes_read') {
                data.report.stats.bytes_read += 1;
              } else if (variant === 'match_finding') {
                data.report.findings.push({
                  severity: 'match',
                  artifact: 'proxy-only',
                  summary: 'A Clear envelope cannot contain a match.',
                  indicator: null,
                  evidence: {},
                });
              } else if (variant === 'parsed_partial') {
                data.report.artifacts[0].status = 'parsed_partial';
              } else if (variant === 'missing_vs_absent') {
                data.report.missing_artifacts = [];
              } else if (variant === 'invalid_artifact_shape') {
                data.report.artifacts = [{ status: 'parsed' }];
              } else if (variant === 'missing_primary_artifacts') {
                data.report.artifacts = [structuredClone(
                  data.report.artifacts.find((artifact) => artifact.kind === 'crash_log')
                )];
              } else if (variant === 'provenance_url') {
                data.report.indicator_provenance[0].url = 'https://example.invalid/decoy';
              }
            }
            this.dispatchEvent(new MessageEvent('message', { data }));
          });
          this.nativeWorker.addEventListener('error', (event) => {
            this.dispatchEvent(new ErrorEvent('error', {
              message: event.message,
              error: event.error,
            }));
          });
          this.nativeWorker.addEventListener('messageerror', () => {
            this.dispatchEvent(new MessageEvent('messageerror'));
          });
        }
        postMessage(...args) {
          this.nativeWorker.postMessage(...args);
        }
        terminate() {
          this.nativeWorker.terminate();
        }
      };
    });
    await page.goto('/');

    const variants = [
      'bytes_read',
      'match_finding',
      'parsed_partial',
      'missing_vs_absent',
      'invalid_artifact_shape',
      'missing_primary_artifacts',
      'provenance_url',
    ];
    for (const [index, variant] of variants.entries()) {
      if (index > 0) {
        await page.click('#rescan-btn');
        await expect(page.locator('#results')).toBeHidden();
      }
      await page.evaluate((nextVariant) => {
        window.__traceEnvelopeVariant = nextVariant;
      }, variant);
      await page.click('#demo-clean');
      await expect(page.locator('.error-box')).toContainText(
        'did not retry it on the main page',
        { timeout: 10_000 }
      );
      await expect(page.locator('.verdict.clear')).toHaveCount(0);
      const state = await page.evaluate(() => ({
        report: window.__trace.lastReport,
        via: window.__trace.lastScanVia,
        mutations: window.__traceEnvelopeMutations.length,
      }));
      expect(state.report, variant).toBeNull();
      expect(state.via, variant).toBe('worker');
      expect(state.mutations, variant).toBe(index + 1);
    }

    const proxyState = await page.evaluate(() => ({
      mutations: window.__traceEnvelopeMutations,
      pageFileStreamCalls: window.__tracePageFileStreamCalls,
    }));
    expect(proxyState.pageFileStreamCalls).toBe(0);
    expect(proxyState.mutations.map((entry) => entry.variant)).toEqual(variants);
    for (const entry of proxyState.mutations) {
      expect(entry.originalVerdict, entry.variant).toBe('clear');
      expect(entry.originalSchema, entry.variant).toBe(4);
      expect(entry.originalSha256, entry.variant).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  test('downgraded match verdicts proxied from a real infected worker fail closed', async ({ page, browserName }) => {
    test.skip(browserName !== 'chromium', 'one engine is sufficient for verdict precedence');
    await page.addInitScript(() => {
      const NativeWorker = window.Worker;
      const pageFileStream = File.prototype.stream;
      window.__traceDowngradedVerdict = 'inconclusive';
      window.__traceDowngradeMutations = [];
      window.__tracePageFileStreamCalls = 0;
      File.prototype.stream = function (...args) {
        window.__tracePageFileStreamCalls += 1;
        return pageFileStream.apply(this, args);
      };

      window.Worker = class extends EventTarget {
        constructor(...args) {
          super();
          this.nativeWorker = new NativeWorker(...args);
          this.nativeWorker.addEventListener('message', (event) => {
            const data = structuredClone(event.data);
            if (data?.type === 'report') {
              window.__traceDowngradeMutations.push({
                requested: window.__traceDowngradedVerdict,
                original: data.report.verdict,
                hadMatch: data.report.findings.some((finding) => finding.severity === 'match'),
              });
              data.report.verdict = window.__traceDowngradedVerdict;
            }
            this.dispatchEvent(new MessageEvent('message', { data }));
          });
          this.nativeWorker.addEventListener('error', (event) => {
            this.dispatchEvent(new ErrorEvent('error', {
              message: event.message,
              error: event.error,
            }));
          });
          this.nativeWorker.addEventListener('messageerror', () => {
            this.dispatchEvent(new MessageEvent('messageerror'));
          });
        }
        postMessage(...args) {
          this.nativeWorker.postMessage(...args);
        }
        terminate() {
          this.nativeWorker.terminate();
        }
      };
    });
    await page.goto('/');

    for (const [index, verdict] of ['inconclusive', 'invalid'].entries()) {
      if (index > 0) {
        await page.click('#rescan-btn');
        await expect(page.locator('#results')).toBeHidden();
      }
      await page.evaluate((nextVerdict) => {
        window.__traceDowngradedVerdict = nextVerdict;
      }, verdict);
      await page.click('#demo-infected');
      await expect(page.locator('.error-box')).toContainText(
        'did not retry it on the main page',
        { timeout: 10_000 }
      );
      await expect(page.locator('.verdict')).toHaveCount(0);
      const state = await page.evaluate(() => ({
        report: window.__trace.lastReport,
        via: window.__trace.lastScanVia,
        mutations: window.__traceDowngradeMutations.length,
      }));
      expect(state.report, verdict).toBeNull();
      expect(state.via, verdict).toBe('worker');
      expect(state.mutations, verdict).toBe(index + 1);
    }

    const proxyState = await page.evaluate(() => ({
      mutations: window.__traceDowngradeMutations,
      pageFileStreamCalls: window.__tracePageFileStreamCalls,
    }));
    expect(proxyState.pageFileStreamCalls).toBe(0);
    expect(proxyState.mutations).toEqual([
      { requested: 'inconclusive', original: 'match', hadMatch: true },
      { requested: 'invalid', original: 'match', hadMatch: true },
    ]);
  });

  test('a coherent inconclusive truncated-artifact report from a real worker is accepted', async ({ page, browserName }) => {
    test.skip(browserName !== 'chromium', 'one engine is sufficient for artifact status acceptance');
    await page.addInitScript(() => {
      const NativeWorker = window.Worker;
      window.__traceTruncatedOriginal = null;
      window.Worker = class extends EventTarget {
        constructor(...args) {
          super();
          this.nativeWorker = new NativeWorker(...args);
          this.nativeWorker.addEventListener('message', (event) => {
            const data = structuredClone(event.data);
            if (data?.type === 'report') {
              const artifact = data.report.artifacts.find(
                (candidate) => candidate.kind === 'crash_log'
              ) || data.report.artifacts[0];
              window.__traceTruncatedOriginal = {
                verdict: data.report.verdict,
                status: artifact.status,
                surface: artifact.kind,
              };
              artifact.status = 'truncated';
              data.report.scan_limits = [
                'Proxy regression: one retained artifact exceeded its size limit.',
              ];
              data.report.assurance.complete = false;
              data.report.assurance.surfaces.find(
                (surface) => surface.kind === artifact.kind
              ).state = 'partial';
              data.report.verdict = 'inconclusive';
            }
            this.dispatchEvent(new MessageEvent('message', { data }));
          });
          this.nativeWorker.addEventListener('error', (event) => {
            this.dispatchEvent(new ErrorEvent('error', {
              message: event.message,
              error: event.error,
            }));
          });
          this.nativeWorker.addEventListener('messageerror', () => {
            this.dispatchEvent(new MessageEvent('messageerror'));
          });
        }
        postMessage(...args) {
          this.nativeWorker.postMessage(...args);
        }
        terminate() {
          this.nativeWorker.terminate();
        }
      };
    });
    await page.goto('/');
    await page.click('#demo-clean');

    const verdict = page.locator('.verdict.inconclusive');
    await expect(verdict).toBeVisible({ timeout: 10_000 });
    await expect(verdict).toContainText(
      'Proxy regression: one retained artifact exceeded its size limit.'
    );
    await expect(page.locator('.error-box')).toHaveCount(0);
    await expect(page.locator('.verdict.clear')).toHaveCount(0);
    await expect(page.locator('.artifacts')).toContainText('truncated');

    const state = await page.evaluate(() => ({
      original: window.__traceTruncatedOriginal,
      report: window.__trace.lastReport,
      via: window.__trace.lastScanVia,
    }));
    expect(state.original.verdict).toBe('clear');
    expect(state.original.status).toBe('parsed');
    expect(state.via).toBe('worker');
    expect(state.report.verdict).toBe('inconclusive');
    expect(state.report.assurance.complete).toBe(false);
    expect(state.report.scan_limits).toHaveLength(1);
    expect(state.report.artifacts.find(
      (artifact) => artifact.kind === state.original.surface
    ).status).toBe('truncated');
    expect(state.report.assurance.surfaces.find(
      (surface) => surface.kind === state.original.surface
    ).state).toBe('partial');
  });

  test('a coherent metadata-only crash report preserves inventory without claiming crash coverage', async ({ page, browserName }) => {
    test.skip(browserName !== 'chromium', 'one engine is sufficient for crash-surface validation');
    await page.addInitScript(() => {
      const NativeWorker = window.Worker;
      window.Worker = class extends EventTarget {
        constructor(...args) {
          super();
          this.nativeWorker = new NativeWorker(...args);
          this.nativeWorker.addEventListener('message', (event) => {
            const data = structuredClone(event.data);
            if (data?.type === 'report') {
              data.report.artifacts = [{
                path: 'root/crashes_and_spins/metadata-only.ips',
                kind: 'crash_log',
                status: 'parsed',
                details: {
                  paired_device: false,
                  detection_relevant: false,
                  processes: 0,
                },
              }];
              delete data.report.device;
              data.report.findings = [];
              data.report.stats.artifacts_found = 1;
              data.report.scan_limits = [
                'No primary process-bearing iPhone detection surface was available.',
              ];
              data.report.verdict = 'inconclusive';
              data.report.assurance.complete = false;
              data.report.assurance.surfaces_examined = 0;
              for (const surface of data.report.assurance.surfaces) {
                surface.state = 'absent';
              }
              data.report.missing_artifacts = data.report.assurance.surfaces.map(
                (surface) => ({
                  kind: surface.kind,
                  note: surface.kind === 'crash_log'
                    ? 'Metadata-only reports do not provide crash detection coverage.'
                    : `No ${surface.kind} was found.`,
                })
              );
            }
            this.dispatchEvent(new MessageEvent('message', { data }));
          });
          this.nativeWorker.addEventListener('error', (event) => {
            this.dispatchEvent(new ErrorEvent('error', {
              message: event.message,
              error: event.error,
            }));
          });
          this.nativeWorker.addEventListener('messageerror', () => {
            this.dispatchEvent(new MessageEvent('messageerror'));
          });
        }
        postMessage(...args) { this.nativeWorker.postMessage(...args); }
        terminate() { this.nativeWorker.terminate(); }
      };
    });
    await page.goto('/');
    await page.click('#demo-clean');

    await expect(page.locator('.verdict.inconclusive')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('.error-box')).toHaveCount(0);
    await expect(page.locator('.artifacts')).toContainText('metadata-only.ips');
    await expect(page.locator('.artifacts')).toContainText(
      'Metadata-only reports do not provide crash detection coverage.'
    );
    expect(await page.evaluate(() => ({
      verdict: window.__trace.lastReport.verdict,
      examined: window.__trace.lastReport.assurance.surfaces_examined,
      crash: window.__trace.lastReport.assurance.surfaces.find(
        (surface) => surface.kind === 'crash_log'
      ).state,
    }))).toEqual({ verdict: 'inconclusive', examined: 0, crash: 'absent' });
  });

  test('a parsed-partial metadata-only report does not degrade complete crash coverage', async ({ page, browserName }) => {
    test.skip(browserName !== 'chromium', 'one engine is sufficient for crash-surface validation');
    await page.addInitScript(() => {
      const NativeWorker = window.Worker;
      window.Worker = class extends EventTarget {
        constructor(...args) {
          super();
          this.nativeWorker = new NativeWorker(...args);
          this.nativeWorker.addEventListener('message', (event) => {
            const data = structuredClone(event.data);
            if (data?.type === 'report') {
              data.report.artifacts.push({
                path: 'root/crashes_and_spins/metadata-only-partial.ips',
                kind: 'crash_log',
                status: 'parsed_partial',
                details: {
                  paired_device: false,
                  detection_relevant: false,
                  processes: 0,
                },
              });
              data.report.stats.artifacts_found += 1;
              data.report.scan_limits = [
                '1 crash or diagnostic .ips file(s) could not be fully parsed; parts of their contents were not checked against indicators.',
              ];
              data.report.verdict = 'inconclusive';
              data.report.assurance.complete = false;
            }
            this.dispatchEvent(new MessageEvent('message', { data }));
          });
          this.nativeWorker.addEventListener('error', (event) => {
            this.dispatchEvent(new ErrorEvent('error', {
              message: event.message,
              error: event.error,
            }));
          });
          this.nativeWorker.addEventListener('messageerror', () => {
            this.dispatchEvent(new MessageEvent('messageerror'));
          });
        }
        postMessage(...args) { this.nativeWorker.postMessage(...args); }
        terminate() { this.nativeWorker.terminate(); }
      };
    });
    await page.goto('/');
    await page.click('#demo-clean');

    await expect(page.locator('.verdict.inconclusive')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('.error-box')).toHaveCount(0);
    await expect(page.locator('.artifacts')).toContainText('metadata-only-partial.ips');
    expect(await page.evaluate(() => ({
      verdict: window.__trace.lastReport.verdict,
      complete: window.__trace.lastReport.assurance.complete,
      crash: window.__trace.lastReport.assurance.surfaces.find(
        (surface) => surface.kind === 'crash_log'
      ).state,
      metadataStatus: window.__trace.lastReport.artifacts.find(
        (artifact) => artifact.path.endsWith('metadata-only-partial.ips')
      ).status,
    }))).toEqual({
      verdict: 'inconclusive',
      complete: false,
      crash: 'complete',
      metadataStatus: 'parsed_partial',
    });
  });

  test('required fields and partial-processing invariants on real worker reports fail closed', async ({ page, browserName }) => {
    test.skip(browserName !== 'chromium', 'one engine is sufficient for complete-envelope invariants');
    await page.addInitScript(() => {
      const NativeWorker = window.Worker;
      const pageFileStream = File.prototype.stream;
      window.__traceInvariantVariant = 'indicator_set_fields';
      window.__traceInvariantMutations = [];
      window.__tracePageFileStreamCalls = 0;
      File.prototype.stream = function (...args) {
        window.__tracePageFileStreamCalls += 1;
        return pageFileStream.apply(this, args);
      };

      window.Worker = class extends EventTarget {
        constructor(...args) {
          super();
          this.nativeWorker = new NativeWorker(...args);
          this.nativeWorker.addEventListener('message', (event) => {
            const data = structuredClone(event.data);
            if (data?.type === 'report') {
              const variant = window.__traceInvariantVariant;
              window.__traceInvariantMutations.push({
                variant,
                originalVerdict: data.report.verdict,
                originalHadMatch: data.report.findings.some(
                  (finding) => finding.severity === 'match'
                ),
              });
              if (variant === 'indicator_set_fields') {
                delete data.report.indicator_sets[0].campaign;
                delete data.report.indicator_sets[0].by_kind;
              } else if (variant === 'tool_version') {
                delete data.report.tool.version;
              } else if (variant === 'note_ioc_match') {
                const finding = data.report.findings.find(
                  (candidate) => candidate.kind === 'ioc_match' && candidate.indicator
                );
                finding.severity = 'note';
              } else if (variant === 'match_missing_indicator') {
                const finding = data.report.findings.find(
                  (candidate) => candidate.kind === 'ioc_match' && candidate.indicator
                );
                delete finding.indicator;
              } else if (variant === 'indicator_attribution') {
                const finding = data.report.findings.find(
                  (candidate) => candidate.kind === 'ioc_match' && candidate.indicator
                );
                finding.indicator.set = 'proxy-decoy-set';
                finding.indicator.campaign = 'Proxy decoy campaign';
              } else if (variant === 'absent_crash_with_retained_evidence') {
                data.report.assurance.surfaces.find(
                  (surface) => surface.kind === 'crash_log'
                ).state = 'absent';
                data.report.missing_artifacts.push({
                  kind: 'crash_log',
                  note: 'Proxy contradiction: crash evidence was retained.',
                });
              } else if (variant === 'complete_unified_without_artifact') {
                data.report.assurance.surfaces.find(
                  (surface) => surface.kind === 'unified_log'
                ).state = 'complete';
                data.report.missing_artifacts = data.report.missing_artifacts.filter(
                  (missing) => missing.kind !== 'unified_log'
                );
              } else if (variant === 'relabel_primary_crash_as_paired') {
                const artifact = data.report.artifacts.find(
                  (candidate) => candidate.kind === 'crash_log'
                    && candidate.details.paired_device === false
                );
                artifact.details.paired_device = true;
                data.report.assurance.surfaces.find(
                  (surface) => surface.kind === 'crash_log'
                ).state = 'absent';
                data.report.missing_artifacts.push({
                  kind: 'crash_log',
                  note: 'Proxy contradiction: primary crash evidence was relabeled as paired.',
                });
              } else if (variant === 'partial_match_without_limit') {
                const artifact = data.report.artifacts.find(
                  (candidate) => candidate.kind === 'crash_log'
                ) || data.report.artifacts[0];
                artifact.status = 'truncated';
                data.report.assurance.surfaces.find(
                  (surface) => surface.kind === artifact.kind
                ).state = 'partial';
                data.report.scan_limits = [];
                data.report.assurance.complete = true;
              } else if (variant === 'paired_only_clear_without_limit'
                  || variant === 'metadata_only_clear_without_limit') {
                const paired = variant === 'paired_only_clear_without_limit';
                data.report.artifacts = [{
                  path: paired
                    ? 'root/logs/ProxiedDevice/watch.ips'
                    : 'root/crashes_and_spins/metadata-only.ips',
                  kind: 'crash_log',
                  status: 'parsed',
                  details: {
                    paired_device: paired,
                    detection_relevant: paired,
                    processes: paired ? 1 : 0,
                  },
                }];
                delete data.report.device;
                data.report.findings = [];
                data.report.stats.artifacts_found = 1;
                data.report.scan_limits = [];
                data.report.verdict = 'clear';
                data.report.assurance.complete = true;
                data.report.assurance.surfaces_examined = 0;
                for (const surface of data.report.assurance.surfaces) {
                  surface.state = 'absent';
                }
                data.report.missing_artifacts = data.report.assurance.surfaces.map(
                  (surface) => ({
                    kind: surface.kind,
                    note: `Proxy forged missing ${surface.kind}.`,
                  })
                );
              }
            }
            this.dispatchEvent(new MessageEvent('message', { data }));
          });
          this.nativeWorker.addEventListener('error', (event) => {
            this.dispatchEvent(new ErrorEvent('error', {
              message: event.message,
              error: event.error,
            }));
          });
          this.nativeWorker.addEventListener('messageerror', () => {
            this.dispatchEvent(new MessageEvent('messageerror'));
          });
        }
        postMessage(...args) {
          this.nativeWorker.postMessage(...args);
        }
        terminate() {
          this.nativeWorker.terminate();
        }
      };
    });
    await page.goto('/');

    const variants = [
      'indicator_set_fields',
      'tool_version',
      'note_ioc_match',
      'match_missing_indicator',
      'indicator_attribution',
      'absent_crash_with_retained_evidence',
      'complete_unified_without_artifact',
      'relabel_primary_crash_as_paired',
      'partial_match_without_limit',
      'paired_only_clear_without_limit',
      'metadata_only_clear_without_limit',
    ];
    for (const [index, variant] of variants.entries()) {
      if (index > 0) {
        await page.click('#rescan-btn');
        await expect(page.locator('#results')).toBeHidden();
      }
      await page.evaluate((nextVariant) => {
        window.__traceInvariantVariant = nextVariant;
      }, variant);
      await page.click('#demo-infected');
      await expect(page.locator('.error-box')).toContainText(
        'did not retry it on the main page',
        { timeout: 10_000 }
      );
      await expect(page.locator('.verdict')).toHaveCount(0);
      const state = await page.evaluate(() => ({
        report: window.__trace.lastReport,
        via: window.__trace.lastScanVia,
        mutations: window.__traceInvariantMutations.length,
      }));
      expect(state.report, variant).toBeNull();
      expect(state.via, variant).toBe('worker');
      expect(state.mutations, variant).toBe(index + 1);
    }

    const proxyState = await page.evaluate(() => ({
      mutations: window.__traceInvariantMutations,
      pageFileStreamCalls: window.__tracePageFileStreamCalls,
    }));
    expect(proxyState.pageFileStreamCalls).toBe(0);
    expect(proxyState.mutations.map((entry) => entry.variant)).toEqual(variants);
    for (const entry of proxyState.mutations) {
      expect(entry.originalVerdict, entry.variant).toBe('match');
      expect(entry.originalHadMatch, entry.variant).toBe(true);
    }
  });

});

test('a waiting release is announced and blocks new scans without activating itself', async ({ page, browserName }) => {
  test.skip(browserName !== 'chromium', 'service-worker lifecycle mocks are exercised once in Chromium');
  await page.addInitScript(() => {
    const waiting = new EventTarget();
    waiting.state = 'installed';
    waiting.postMessage = (message) => { waiting.messages.push(message); };
    waiting.messages = [];
    const registration = new EventTarget();
    registration.waiting = waiting;
    registration.installing = null;
    registration.updateCalls = 0;
    registration.update = async () => {
      registration.updateCalls += 1;
      return registration;
    };
    const serviceWorker = new EventTarget();
    serviceWorker.controller = { scriptURL: 'https://example.invalid/trace-old/sw.js' };
    serviceWorker.ready = Promise.resolve(registration);
    serviceWorker.register = async (url, options) => {
      registration.registerArgs = { url, options };
      return registration;
    };
    Object.defineProperty(navigator, 'serviceWorker', {
      configurable: true,
      value: serviceWorker,
    });
    window.__traceServiceWorkerMock = { registration, serviceWorker, waiting };
  });

  await page.goto('/');
  await expect(page.locator('#scanner-status')).toHaveClass(/ready/, { timeout: 30_000 });
  await expect(page.locator('#update-notice')).toBeVisible();
  await expect(page.locator('#update-message')).toContainText('Close every Trace tab and window');
  await expect(page.locator('#update-message')).toContainText('Reloading this tab alone');
  await expect(page.locator('#update-announcer')).toContainText('New scans are disabled');
  await expect(page.locator('#file-input')).toBeDisabled();
  await expect(page.locator('#demo-clean')).toBeDisabled();

  const lifecycle = await page.evaluate(() => ({
    registerArgs: window.__traceServiceWorkerMock.registration.registerArgs,
    updateReady: window.__trace.updateReady,
    messages: window.__traceServiceWorkerMock.waiting.messages,
  }));
  expect(lifecycle.registerArgs).toEqual({
    url: './sw.js',
    options: { updateViaCache: 'none' },
  });
  expect(lifecycle.updateReady).toBe(true);
  expect(lifecycle.messages).toEqual([]);
});

test('an existing waiting release wins the race with a delayed register check', async ({ page, browserName }) => {
  test.skip(browserName !== 'chromium', 'service-worker lifecycle mocks are exercised once in Chromium');
  await page.addInitScript(() => {
    const waiting = new EventTarget();
    waiting.state = 'installed';
    const registration = new EventTarget();
    registration.waiting = waiting;
    registration.installing = null;
    registration.update = async () => registration;
    const serviceWorker = new EventTarget();
    serviceWorker.controller = { scriptURL: 'https://example.invalid/trace-old/sw.js' };
    serviceWorker.ready = Promise.resolve(registration);
    serviceWorker.register = () => new Promise(() => {});
    Object.defineProperty(navigator, 'serviceWorker', {
      configurable: true,
      value: serviceWorker,
    });
  });

  await page.goto('/');
  await expect(page.locator('#scanner-status')).toHaveClass(/ready/, { timeout: 30_000 });
  await expect(page.locator('#update-notice')).toBeVisible();
  await expect(page.locator('#file-input')).toBeDisabled();
  expect(await page.evaluate(() => window.__trace.updateReady)).toBe(true);
});

test('an update already installing when registration resolves is still observed', async ({ page, browserName }) => {
  test.skip(browserName !== 'chromium', 'service-worker lifecycle mocks are exercised once in Chromium');
  await page.addInitScript(() => {
    const installing = new EventTarget();
    installing.state = 'installing';
    const registration = new EventTarget();
    registration.waiting = null;
    registration.installing = installing;
    registration.update = async () => registration;
    const serviceWorker = new EventTarget();
    serviceWorker.controller = { scriptURL: 'https://example.invalid/trace-old/sw.js' };
    serviceWorker.ready = Promise.resolve(registration);
    serviceWorker.register = async () => registration;
    Object.defineProperty(navigator, 'serviceWorker', {
      configurable: true,
      value: serviceWorker,
    });
    window.__traceServiceWorkerMock = { installing, registration };
  });

  await page.goto('/');
  await expect(page.locator('#scanner-status')).toHaveClass(/ready/, { timeout: 30_000 });
  await page.evaluate(() => {
    const { installing, registration } = window.__traceServiceWorkerMock;
    installing.state = 'installed';
    registration.waiting = installing;
    installing.dispatchEvent(new Event('statechange'));
  });
  await expect(page.locator('#update-notice')).toBeVisible();
  await expect(page.locator('#file-input')).toBeDisabled();
  expect(await page.evaluate(() => window.__trace.updateReady)).toBe(true);
});

test('an update discovered during a scan never interrupts or reloads that scan', async ({ page, browserName }) => {
  test.skip(browserName !== 'chromium', 'service-worker lifecycle mocks are exercised once in Chromium');
  await page.addInitScript(() => {
    const installing = new EventTarget();
    installing.state = 'installing';
    const registration = new EventTarget();
    registration.waiting = null;
    registration.installing = null;
    registration.update = async () => registration;
    const serviceWorker = new EventTarget();
    serviceWorker.controller = { scriptURL: 'https://example.invalid/trace-old/sw.js' };
    serviceWorker.ready = Promise.resolve(registration);
    serviceWorker.register = async () => registration;
    Object.defineProperty(navigator, 'serviceWorker', {
      configurable: true,
      value: serviceWorker,
    });
    window.__traceServiceWorkerMock = { installing, registration, serviceWorker };
  });

  await page.goto('/');
  await expect(page.locator('#scanner-status')).toHaveClass(/ready/, { timeout: 30_000 });
  await page.evaluate(() => {
    window.__trace.disableWorker();
    const bytes = new Uint8Array([1, 2, 3, 4]);
    const delayedFile = {
      name: 'sysdiagnose_delayed.tar.gz',
      size: bytes.byteLength,
      stream() {
        return new ReadableStream({
          start(controller) {
            window.__releaseDelayedArchive = () => {
              controller.enqueue(bytes);
              controller.close();
            };
          },
        });
      },
    };
    void window.__trace.handleFile(delayedFile);
  });
  await expect(page.locator('#scan-heading')).toHaveText('Reading archive…', { timeout: 10_000 });

  await page.evaluate(() => {
    const { installing, registration } = window.__traceServiceWorkerMock;
    registration.installing = installing;
    registration.dispatchEvent(new Event('updatefound'));
    installing.state = 'installed';
    registration.waiting = installing;
    installing.dispatchEvent(new Event('statechange'));
  });

  await expect(page.locator('#update-notice')).toBeVisible();
  await expect(page.locator('#update-message')).toContainText(
    'This scan will finish with the currently loaded release'
  );
  await expect(page.locator('#scanning')).toBeVisible();
  await expect(page.locator('#scan-heading')).toHaveText('Reading archive…');

  await page.click('#cancel-scan');
  await expect(page.locator('#landing')).toBeVisible({ timeout: 10_000 });
  await expect(page.locator('#update-notice')).toBeVisible();
  await expect(page.locator('#update-notice')).toBeFocused();
  await expect(page.locator('#file-input')).toBeDisabled();
  expect(await page.evaluate(() => window.__trace.updateReady)).toBe(true);
});

test('the first service-worker install is not mislabeled as an update', async ({ page, browserName }) => {
  test.skip(browserName !== 'chromium', 'service-worker lifecycle mocks are exercised once in Chromium');
  await page.addInitScript(() => {
    const installing = new EventTarget();
    installing.state = 'installing';
    const registration = new EventTarget();
    registration.waiting = null;
    registration.installing = null;
    registration.update = async () => registration;
    const serviceWorker = new EventTarget();
    serviceWorker.controller = null;
    serviceWorker.ready = Promise.resolve(registration);
    serviceWorker.register = async () => registration;
    Object.defineProperty(navigator, 'serviceWorker', {
      configurable: true,
      value: serviceWorker,
    });
    window.__traceServiceWorkerMock = { installing, registration };
  });

  await page.goto('/');
  await expect(page.locator('#scanner-status')).toHaveClass(/ready/, { timeout: 30_000 });
  await page.evaluate(() => {
    const { installing, registration } = window.__traceServiceWorkerMock;
    registration.installing = installing;
    registration.dispatchEvent(new Event('updatefound'));
    installing.state = 'installed';
    registration.waiting = installing;
    installing.dispatchEvent(new Event('statechange'));
  });
  await expect(page.locator('#update-notice')).toBeHidden();
  await expect(page.locator('#file-input')).toBeEnabled();
  expect(await page.evaluate(() => window.__trace.updateReady)).toBe(false);
});

test('the active worker never serves an asset from a different Trace cache', async ({ page, browserName }) => {
  test.skip(browserName !== 'chromium', 'CacheStorage generation isolation is exercised once in Chromium');
  await page.goto('/?offline-shell-proof=1');
  await page.evaluate(() => navigator.serviceWorker.ready);
  await page.reload();
  await expect(page.locator('#scanner-status')).toHaveClass(/ready/, { timeout: 30_000 });
  const probe = await page.evaluate(async () => {
    const probeUrl = new URL('./__trace_waiting_cache_probe__', location.href).href;
    const traceCacheName = (await caches.keys()).find((name) => name.startsWith('trace-'));
    const traceCache = await caches.open(traceCacheName);
    const traceKeys = await traceCache.keys();
    const unqualifiedGlobalMatch = await caches.match(new URL('./main.js', location.href).href);
    const foreignCache = await caches.open('trace-future-test-only');
    await foreignCache.put(probeUrl, new Response('future-release-bytes', {
      status: 200,
      headers: { 'content-type': 'text/plain' },
    }));
    try {
      const response = await fetch(probeUrl);
      return {
        status: response.status,
        text: await response.text(),
        traceCacheName,
        everyKeyIsReleaseQualified: traceKeys.every((request) =>
          new URL(request.url).searchParams.get('__trace_release') === traceCacheName
        ),
        unqualifiedGlobalMatch: Boolean(unqualifiedGlobalMatch),
      };
    } finally {
      await caches.delete('trace-future-test-only');
    }
  });
  expect(probe.status).toBe(404);
  expect(probe.text).not.toContain('future-release-bytes');
  expect(probe.traceCacheName).toBe('trace-v1');
  expect(probe.everyKeyIsReleaseQualified).toBe(true);
  expect(probe.unqualifiedGlobalMatch).toBe(false);
});

test('scanning still works fully offline once the app is cached', async ({ page, context, browserName }) => {
  test.skip(
    browserName === 'webkit',
    'Playwright WebKit cannot emulate offline across a service-worker navigation (internal error on reload); the offline path is proven on chromium and firefox'
  );
  await page.goto('/?offline-shell-proof=1');
  await page.evaluate(() => navigator.serviceWorker.ready);
  await context.setOffline(true);
  await page.reload();
  await page.click('#demo-clean');
  await expect(page.locator('.verdict.clear')).toBeVisible({ timeout: 30_000 });
  const schema = await page.evaluate(async () =>
    (await fetch('./report.schema.json')).json());
  expect(schema.properties.schema_version.const).toBe(4);
  // offline means the live refresh failed and bundled snapshots were used
  await expect(page.locator('#ioc-list')).toContainText('snapshot');
  await context.setOffline(false);
});

// Report v4 producer parity: the worker and inline producers must emit the
// exact field shape pinned by the Rust golden (which the native producer is
// held to in crates/trace-core/tests/report_v4.rs). Same flattening rules
// as that test: array indices normalize to [], and paths whose contents
// legitimately vary (evidence, details, by_kind) are opaque leaves.
const GOLDEN_FIELDS = path.join(__dirname, '../../crates/trace-core/tests/report_fields_v4.json');
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
    expect(report.schema_version).toBe(4);
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
  expect(schema.properties.schema_version.const).toBe(4);
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
