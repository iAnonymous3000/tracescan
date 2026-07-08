import init, { Scanner } from './pkg/trace_core.js';

const $ = (sel) => document.querySelector(sel);

const state = {
  stix: [],          // { name, source, url, text, loaded_from, date, stats }
  scanner: null,     // pre-warmed Scanner with indicators loaded
  ready: null,       // resolves once WASM + indicators are loaded
  lastReport: null,
  lastScanVia: null, // 'worker' | 'inline'
};

/* ---------- utilities ---------- */

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function fmtBytes(n) {
  if (n >= 1 << 30) return (n / (1 << 30)).toFixed(2) + ' GB';
  if (n >= 1 << 20) return (n / (1 << 20)).toFixed(1) + ' MB';
  if (n >= 1 << 10) return (n / (1 << 10)).toFixed(0) + ' KB';
  return n + ' B';
}

async function fetchWithTimeout(url, ms) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { signal: ctrl.signal, cache: 'no-store' });
  } finally {
    clearTimeout(t);
  }
}

// Identifies the exact indicator revision a scan used; "live" plus a date is
// not provenance. Null only in non-secure contexts, where subtle is absent.
async function sha256hex(text) {
  if (!crypto?.subtle) return null;
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

function showSection(name) {
  for (const id of ['landing', 'scanning', 'results']) {
    $('#' + id).hidden = id !== name;
  }
  $('#about').hidden = name === 'scanning';
}

/* ---------- indicator loading ---------- */

async function loadIndicators() {
  const manifest = await (await fetch('./iocs/manifest.json')).json();
  for (const set of manifest.sets) {
    let text = null;
    let loaded_from = 'bundled';
    let date = manifest.bundled_date;
    let etag = null;
    let last_modified = null;
    try {
      const r = await fetchWithTimeout(set.url, 6000);
      if (r.ok) {
        text = await r.text();
        JSON.parse(text); // sanity: don't accept a non-JSON error page
        loaded_from = 'live';
        date = new Date().toISOString().slice(0, 10);
        etag = r.headers.get('etag');
        last_modified = r.headers.get('last-modified');
      }
    } catch { /* offline or blocked - bundled snapshot below */ }
    if (!text) {
      text = await (await fetch(set.file)).text();
    }
    const sha256 = await sha256hex(text);
    state.stix.push({ ...set, text, loaded_from, date, sha256, etag, last_modified });
  }
}

function newScanner() {
  const s = new Scanner();
  for (const set of state.stix) {
    set.stats = JSON.parse(s.load_stix(set.name, set.text));
  }
  return s;
}

function renderIocPanel() {
  const rows = state.stix.map((s) => `
    <div class="ioc-row">
      <span><span class="campaign">${esc(s.stats.campaign)}</span>
        <span class="badge ${s.loaded_from}">${s.loaded_from === 'live' ? 'live · ' + esc(s.date) : 'snapshot · ' + esc(s.date)}</span></span>
      <span class="meta">${s.stats.extracted} indicators, ${s.stats.applicable} checkable here · ${esc(s.source)}${s.sha256 ? ` · <code title="SHA-256 of the indicator file used: ${esc(s.sha256)}">sha256:${esc(s.sha256.slice(0, 12))}…</code>` : ''}</span>
    </div>`).join('');
  $('#ioc-list').innerHTML = rows;
  const total = state.stix.reduce((a, s) => a + s.stats.extracted, 0);
  const applicable = state.stix.reduce((a, s) => a + s.stats.applicable, 0);
  $('#ioc-note').textContent =
    `${applicable} of ${total} loaded indicators are process or file names that can appear in sysdiagnose artifacts. ` +
    `The rest are mostly domains, URLs and emails, which live in artifacts (browsing history, messages) found in device backups - this version does not read those, and results never imply they were checked.`;
  $('#ioc-panel').hidden = false;
}

/* ---------- scanning ---------- */

let worker = null;

function initWorker() {
  try {
    worker = new Worker('./worker.js', { type: 'module' });
  } catch {
    worker = null; // very old browser: fall back to inline scanning
  }
}

function updateProgress(processed, total) {
  $('#progress').value = total ? Math.round((processed / total) * 100) : 0;
  $('#progress-text').textContent = `${fmtBytes(processed)} of ${fmtBytes(total)} read`;
}

function scanWithWorker(file) {
  return new Promise((resolve, reject) => {
    const w = worker;
    const onMsg = (e) => {
      const m = e.data;
      if (m.type === 'progress') {
        updateProgress(m.processed, file.size);
      } else if (m.type === 'report') {
        cleanup();
        resolve(m.report);
      } else if (m.type === 'error') {
        cleanup();
        reject(new Error(m.message));
      }
    };
    const onErr = () => {
      cleanup();
      worker = null; // future scans use the inline path
      reject(new Error('The background scanner failed. Reload the page and try again.'));
    };
    const cleanup = () => {
      w.removeEventListener('message', onMsg);
      w.removeEventListener('error', onErr);
    };
    w.addEventListener('message', onMsg);
    w.addEventListener('error', onErr);
    w.postMessage({
      type: 'scan',
      file,
      sets: state.stix.map((s) => ({ name: s.name, text: s.text })),
    });
  });
}

async function scanInline(file) {
  const scanner = state.scanner ?? newScanner();
  state.scanner = null;
  try {
    const reader = file.stream().getReader();
    let processed = 0;
    let n = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      scanner.push(value);
      processed += value.byteLength;
      updateProgress(processed, file.size);
      if (++n % 2 === 0) await new Promise((r) => setTimeout(r, 0));
    }
    return JSON.parse(scanner.finish());
  } finally {
    try { state.scanner = newScanner(); } catch { /* keep last error visible */ }
  }
}

async function handleFile(file) {
  showSection('scanning');
  updateProgress(0, file.size);
  try {
    // A file dropped before the indicator sets finish loading must wait:
    // scanning with an empty set would produce a hollow "clear".
    await state.ready;
    let report;
    if (worker) {
      state.lastScanVia = 'worker';
      report = await scanWithWorker(file);
    } else {
      state.lastScanVia = 'inline';
      report = await scanInline(file);
    }
    report.generated_at = new Date().toISOString();
    report.source_file = { name: file.name, size: file.size };
    report.scanned_via = state.lastScanVia;
    report.indicator_provenance = state.stix.map((s) => ({
      name: s.name, campaign: s.stats.campaign, loaded_from: s.loaded_from, date: s.date, url: s.url,
      sha256: s.sha256, etag: s.etag, last_modified: s.last_modified,
    }));
    state.lastReport = report;
    renderReport(report);
  } catch (err) {
    renderError(err);
  }
}

/* ---------- rendering results ---------- */

function verdictOf(report) {
  const limited = (report.scan_limits || []).length > 0;
  if (report.stats.artifacts_found === 0 && !limited) return 'invalid';
  if (report.findings.some((f) => f.severity === 'match')) return 'match';
  if (report.findings.some((f) => f.severity === 'suspicious')) return 'suspicious';
  // A partially analyzed archive with nothing found must never read as
  // "no traces found" - only a full pass earns the clear verdict.
  if (limited) return 'inconclusive';
  return 'clear';
}

const HELP_BLOCK = `
  <div class="help-block">
    <h3>What to do right now</h3>
    <ul>
      <li><strong>Do not reset, wipe, or update the phone yet</strong> - that can destroy the evidence an expert needs.</li>
      <li><strong>Keep this sysdiagnose file</strong> somewhere safe, and export the report below.</li>
      <li><strong>Contact specialists</strong> (free, confidential):
        <ul>
          <li><a href="https://www.accessnow.org/help/" target="_blank" rel="noopener noreferrer">Access Now Digital Security Helpline</a> - 24/7, multiple languages</li>
          <li><a href="https://securitylab.amnesty.org/get-help/" target="_blank" rel="noopener noreferrer">Amnesty International Security Lab</a> - forensic support for civil society</li>
        </ul>
      </li>
      <li>If you fear your device is being watched, consider making contact <strong>from a different device</strong>.</li>
    </ul>
  </div>`;

function verdictHtml(report) {
  const v = verdictOf(report);
  const applicable = report.stats.applicable_indicators;
  const noteCount = report.findings.filter((f) => f.severity === 'note').length;
  const limits = report.scan_limits || [];
  const limitNote = limits.length
    ? `<p><strong>Note: this scan was incomplete.</strong> The archive hit safety limits and parts of it were not analyzed (details under "Scan limits reached" below).</p>`
    : '';
  if (v === 'match') {
    return `<div class="verdict match">
      <h2>Traces matching known spyware were found</h2>
      <p>This file contains entries that exactly match published indicators of mercenary spyware. That is a serious signal, and it deserves expert eyes - but it is not final proof on its own.</p>
      ${limitNote}
      <p>Please follow the steps below. You are not alone in this, and help is free.</p>
    </div>` + HELP_BLOCK;
  }
  if (v === 'suspicious') {
    return `<div class="verdict suspicious">
      <h2>No indicator matches - but anomalies worth expert review</h2>
      <p>Nothing matched a published indicator, but the scan found patterns that public research has associated with spyware infections. This is <strong>not a detection</strong>; these anomalies sometimes have benign causes.</p>
      ${limitNote}
      <p>If you have independent reasons to be concerned, the helplines below can look deeper. Keep this file either way.</p>
    </div>` + HELP_BLOCK;
  }
  if (v === 'inconclusive') {
    return `<div class="verdict inconclusive">
      <h2>Scan incomplete - result inconclusive</h2>
      <p>This archive could not be fully analyzed, so <strong>no verdict can be given</strong>. Nothing matched in the parts that were read, but a partial scan must not be presented as "no traces found".</p>
      <ul>${limits.map((l) => `<li>${esc(l)}</li>`).join('')}</ul>
      <p>This is unusual: a real sysdiagnose never comes close to these limits. Try capturing and scanning a fresh sysdiagnose. If this happens again, contact <a href="https://www.accessnow.org/help/" target="_blank" rel="noopener noreferrer">Access Now's helpline</a> (free, confidential) and mention the file could not be scanned.</p>
    </div>`;
  }
  if (v === 'invalid') {
    return `<div class="verdict invalid">
      <h2>This doesn't look like a sysdiagnose archive</h2>
      <p>None of the expected artifacts (shutdown.log, crash logs, ps.txt) were found inside. Make sure you're scanning a file named like <code>sysdiagnose_….tar.gz</code>, captured following the guide on the start page.</p>
    </div>`;
  }
  const missing = report.missing_artifacts || [];
  const coverageNote = missing.length
    ? `<p><strong>Coverage note:</strong> ${missing.length} of the 3 artifact types this tool reads ${missing.length > 1 ? 'were' : 'was'} not present in this archive (${missing.map((m) => esc(m.kind.replace(/_/g, ' '))).join(', ')}), so ${missing.length > 1 ? 'those surfaces' : 'that surface'} could not be checked. Details are in the table below.</p>`
    : '';
  return `<div class="verdict clear">
    <h2>No known spyware traces found</h2>
    <p>None of the ${applicable} applicable public indicators appeared in the artifacts this tool reads${noteCount ? `, though ${noteCount} informational note${noteCount > 1 ? 's are' : ' is'} listed below` : ''}.</p>
    ${coverageNote}
    <p><strong>This is not the same as "your phone is clean."</strong> It means: no publicly documented implant left its known traces in these artifacts. Spyware that is new, undocumented, or leaves traces elsewhere would not appear here. If you face real risk, treat this as one data point and consider expert help - <a href="https://www.accessnow.org/help/" target="_blank" rel="noopener noreferrer">Access Now's helpline</a> is free.</p>
  </div>`;
}

function findingsHtml(report) {
  if (!report.findings.length) return '';
  const cards = report.findings.map((f) => {
    const ind = f.indicator
      ? `<div><span class="ind-chip">indicator: <code>${esc(f.indicator.value)}</code></span>
         <span class="ind-chip">campaign: ${esc(f.indicator.campaign)}</span>
         <span class="ind-chip">source: ${esc(f.indicator.set)}</span></div>`
      : '';
    return `<div class="finding">
      <div class="head"><span class="sev ${esc(f.severity)}">${esc(f.severity)}</span>
      <span class="artifact">${esc(f.artifact)}</span></div>
      <p class="summary">${esc(f.summary)}</p>
      ${ind}
      <details><summary>Technical evidence</summary><pre>${esc(JSON.stringify(f.evidence, null, 2))}</pre></details>
    </div>`;
  }).join('');
  return `<h2>Findings (${report.findings.length})</h2>${cards}`;
}

function artifactsHtml(report) {
  if (!report.artifacts.length) return '';
  const rows = report.artifacts.map((a) => `
    <tr>
      <td>${esc(a.kind)}</td>
      <td class="path">${esc(a.path)}</td>
      <td>${esc(a.status)}</td>
      <td>${esc(Object.entries(a.details || {})
        .filter(([, v]) => v !== null)
        .map(([k, v]) => `${k}: ${v}`).join(', '))}</td>
    </tr>`).join('');
  const missingRows = (report.missing_artifacts || []).map((m) => `
    <tr>
      <td>${esc(m.kind)}</td>
      <td class="path">–</td>
      <td>not found</td>
      <td>${esc(m.note)}</td>
    </tr>`).join('');
  return `<div class="panel"><h2>What was examined (${report.artifacts.length} artifacts, ${report.stats.archive_entries} files in archive)</h2>
    <table class="artifacts"><thead><tr><th>Kind</th><th>Path</th><th>Status</th><th>Details</th></tr></thead>
    <tbody>${rows}${missingRows}</tbody></table></div>`;
}

function limitsHtml(report) {
  const limits = report.scan_limits || [];
  // The inconclusive verdict already lists the reasons in the banner itself.
  if (!limits.length || verdictOf(report) === 'inconclusive') return '';
  return `<div class="panel"><h2>Scan limits reached</h2>
    <ul>${limits.map((l) => `<li>${esc(l)}</li>`).join('')}</ul>
    <p class="fine">Parts of the archive were not analyzed. A real sysdiagnose never comes close to these limits; findings above are unaffected, but absence of further findings is not meaningful for the unanalyzed parts.</p>
  </div>`;
}

function coverageHtml(report) {
  const li = (items) => items.map((x) => `<li>${esc(x)}</li>`).join('');
  return `<div class="panel">
    <h2>Honest limits of this scan</h2>
    <div class="coverage-cols">
      <div><h3>Examined</h3><ul>${li(report.coverage.examined)}</ul></div>
      <div><h3>Not examined</h3><ul>${li(report.coverage.not_examined)}</ul></div>
    </div>
    <p class="fine">${esc(report.coverage.note)}</p>
  </div>`;
}

function provenanceHtml(report) {
  const rows = (report.indicator_provenance || []).map((p) => `
    <div class="ioc-row">
      <span><span class="campaign">${esc(p.campaign)}</span>
        <span class="badge ${esc(p.loaded_from)}">${p.loaded_from === 'live' ? 'live · ' : 'snapshot · '}${esc(p.date)}</span></span>
      <span class="meta">${p.sha256 ? `<code title="SHA-256 of the indicator file used: ${esc(p.sha256)}">sha256:${esc(p.sha256.slice(0, 12))}…</code> · ` : ''}<a href="${esc(p.url)}" target="_blank" rel="noopener noreferrer">source</a></span>
    </div>`).join('');
  return `<div class="panel"><h2>Indicators used</h2>${rows}
    <p class="fine">The hash identifies the exact indicator revision this scan used; it is recorded in the exported report. Public indicators inherit a time lag: new campaigns appear here only after researchers publish them. A scan can only be as current as the open ecosystem.</p></div>`;
}

function renderReport(report) {
  const device = report.device
    ? `<p class="fine">Device: ${esc(report.device.os_version)} (from ${esc(report.device.source)}) · file: ${esc(report.source_file.name)} (${fmtBytes(report.source_file.size)})</p>`
    : `<p class="fine">File: ${esc(report.source_file.name)} (${fmtBytes(report.source_file.size)})</p>`;
  $('#results').innerHTML =
    verdictHtml(report) +
    device +
    findingsHtml(report) +
    limitsHtml(report) +
    artifactsHtml(report) +
    coverageHtml(report) +
    provenanceHtml(report) +
    `<div class="actions">
      <button class="btn" id="export-btn">Export report (JSON)</button>
      <button class="btn secondary" id="rescan-btn">Scan another file</button>
    </div>
    <p class="fine">The exported report contains scan results and device metadata only - never the archive itself. Share it with a helpline to speed up triage.</p>`;
  $('#export-btn').addEventListener('click', exportReport);
  $('#rescan-btn').addEventListener('click', () => showSection('landing'));
  showSection('results');
  // Move focus to the verdict so screen readers announce the outcome.
  $('#results').focus();
}

function renderError(err) {
  $('#results').innerHTML = `<div class="error-box">
    <h2>Couldn't scan that file</h2>
    <p>${esc(err?.message || err)}</p>
    <p>Make sure you're choosing the original <code>sysdiagnose_….tar.gz</code> file, not an unpacked folder or a renamed copy. Nothing was uploaded; you can simply try again.</p>
  </div>
  <div class="actions"><button class="btn secondary" id="rescan-btn">Back</button></div>`;
  $('#rescan-btn').addEventListener('click', () => showSection('landing'));
  showSection('results');
}

function exportReport() {
  if (!state.lastReport) return;
  const blob = new Blob([JSON.stringify(state.lastReport, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `trace-report-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  // Revoking synchronously can cancel the download in some browsers.
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/* ---------- wiring ---------- */

function wireUi() {
  const dz = $('#dropzone');
  const input = $('#file-input');

  dz.addEventListener('click', (e) => {
    if (e.target.tagName !== 'LABEL') input.click();
  });
  dz.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
  });
  // The dropzone only handles its highlight; the actual drop (anywhere on
  // the page) is handled once, at the document level below.
  dz.addEventListener('dragover', () => dz.classList.add('dragover'));
  dz.addEventListener('dragleave', () => dz.classList.remove('dragover'));
  dz.addEventListener('drop', () => dz.classList.remove('dragover'));
  input.addEventListener('change', () => {
    if (input.files?.[0]) handleFile(input.files[0]);
    input.value = '';
  });

  // A file dropped outside the dropzone must never navigate the tab away
  // (the browser default), which would silently destroy the session. Any
  // drop on the page is treated as intent to scan.
  document.addEventListener('dragover', (e) => e.preventDefault());
  document.addEventListener('drop', (e) => {
    e.preventDefault();
    const file = e.dataTransfer?.files?.[0];
    if (file && $('#scanning').hidden) handleFile(file);
  });

  const dialog = $('#prove-dialog');
  $('#prove-it').addEventListener('click', () => dialog.showModal());
  dialog.addEventListener('click', (e) => {
    if (e.target === dialog) dialog.close();
  });

  const demo = (path, name) => async () => {
    const blob = await (await fetch(path)).blob();
    handleFile(new File([blob], name));
  };
  $('#demo-clean').addEventListener('click',
    demo('./fixtures/sysdiagnose_demo_clean.tar.gz', 'sysdiagnose_demo_clean.tar.gz'));
  $('#demo-infected').addEventListener('click',
    demo('./fixtures/sysdiagnose_demo_infected.tar.gz', 'sysdiagnose_demo_infected.tar.gz'));

  const setOnlineState = () => {
    const off = !navigator.onLine;
    $('#offline-dot').classList.toggle('offline', off);
    $('#privacy-text').textContent = off
      ? 'You are offline - and scanning still works. That is the proof: nothing here depends on a server.'
      : 'Analysis runs entirely in this browser tab. There is no upload - no server ever sees your file.';
  };
  window.addEventListener('online', setOnlineState);
  window.addEventListener('offline', setOnlineState);
  setOnlineState();
}

async function boot() {
  wireUi();
  initWorker();
  // The service worker only caches the app shell; it does not depend on the
  // indicator sets, so register it regardless of how the rest of boot goes.
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('./sw.js').catch(() => { /* non-fatal */ });
  }
  state.ready = (async () => {
    await init();
    await loadIndicators();
    state.scanner = newScanner();
    renderIocPanel();
  })();
  try {
    await state.ready;
  } catch (err) {
    // Scans awaiting state.ready will surface the same failure; this makes
    // it visible before anyone drops a file.
    $('#ioc-note').textContent =
      `The scanner failed to start (${err?.message || err}). Reload the page to try again; scanning is unavailable until this succeeds.`;
    $('#ioc-panel').hidden = false;
  }
}

// Exposed for end-to-end tests; handleFile is the same path the UI uses.
window.__trace = {
  handleFile,
  get lastReport() { return state.lastReport; },
  get lastScanVia() { return state.lastScanVia; },
  get ready() { return state.scanner !== null; },
};

boot();
