import init, { Scanner } from './pkg/trace_core.js';

const $ = (sel) => document.querySelector(sel);

const state = {
  stix: [],          // { name, source, url, text, loaded_from, date, stats }
  scanner: null,     // pre-warmed Scanner with indicators loaded
  ready: null,       // resolves once WASM + indicators are loaded
  lastReport: null,
  lastScanVia: null, // 'worker' | 'inline'
  scanning: false,   // a scan is in flight; new files are ignored until done
};

/* ---------- utilities ---------- */

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function fmtBytes(n) {
  if (!Number.isFinite(n) || n < 0) return 'size unavailable';
  if (n >= 1 << 30) return (n / (1 << 30)).toFixed(2) + ' GB';
  if (n >= 1 << 20) return (n / (1 << 20)).toFixed(1) + ' MB';
  if (n >= 1 << 10) return (n / (1 << 10)).toFixed(0) + ' KB';
  return n + ' B';
}

// The timeout covers the body read too: a server that sends headers and
// then stalls the body must not hang startup indefinitely.
async function fetchTextWithTimeout(url, ms) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    const r = await fetch(url, { signal: ctrl.signal, cache: 'no-store' });
    if (!r.ok) return null;
    return await r.text();
  } catch {
    return null; // offline, blocked, or timed out
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

// Returning from results, keyboard focus lands on the next action instead
// of being lost on the removed button.
function backToLanding() {
  showSection('landing');
  $('#dropzone').focus();
}

/* ---------- indicator loading ---------- */

// Scans use only the bundled, reviewed indicator snapshots. Live upstream
// data never reaches a verdict: a count-based check cannot tell a
// legitimate update from a feed that swapped reviewed indicators for
// unreviewed ones, so the upstream fetch is used solely to announce that
// an update has been published (it ships here through the weekly reviewed
// snapshot process). A live file only counts as a real update when it is
// a plausible bundle that still meets the set's reviewed floor.
function isPlausibleUpdate(set, text) {
  try {
    if (!Array.isArray(JSON.parse(text).objects)) return false;
    const probe = new Scanner();
    try {
      const stats = JSON.parse(probe.load_stix(set.name, text));
      return stats.extracted >= (set.min_indicators ?? 1)
        && stats.applicable >= (set.min_applicable ?? 0);
    } finally {
      probe.free();
    }
  } catch {
    return false;
  }
}

async function loadIndicators() {
  // 'no-cache' forces revalidation: dev servers without Cache-Control
  // otherwise leave heuristically cached stale copies in play. In
  // production the service worker answers these before HTTP caching
  // matters, so this only costs a conditional request on first load.
  const manifest = await (await fetch('./iocs/manifest.json', { cache: 'no-cache' })).json();
  // Upstream checks run in parallel: on a network that silently drops the
  // requests, sequential 6-second timeouts would stall the panel.
  state.stix = await Promise.all(manifest.sets.map(async (set) => {
    const text = await (await fetch(set.file, { cache: 'no-cache' })).text();
    const sha256 = await sha256hex(text);
    // 'current' | 'update-available' | 'unknown' (offline or unreachable)
    let upstream = 'unknown';
    const live = await fetchTextWithTimeout(set.url, 6000);
    if (live !== null) {
      const liveSha = await sha256hex(live);
      upstream = liveSha !== sha256 && isPlausibleUpdate(set, live)
        ? 'update-available'
        : 'current';
    }
    // Catalog metadata recorded as provenance in the report envelope; the
    // engine hashes the set text itself, so nothing here is trusted.
    const meta = {
      date: manifest.bundled_date, url: set.url, source: set.source,
      loaded_from: 'bundled', upstream,
    };
    return { ...set, text, loaded_from: 'bundled', date: manifest.bundled_date, sha256, upstream, meta };
  }));
}

function newScanner() {
  const s = new Scanner();
  for (const set of state.stix) {
    set.stats = JSON.parse(s.load_stix_with_meta(set.name, set.text, JSON.stringify(set.meta)));
  }
  return s;
}

function renderIocPanel() {
  const rows = state.stix.map((s) => `
    <div class="ioc-row">
      <span><span class="campaign">${esc(s.stats.campaign)}</span>
        <span class="badge bundled">reviewed snapshot · ${esc(s.date)}</span></span>
      <span class="meta">${s.stats.extracted} indicators, ${s.stats.applicable} checkable here · ${esc(s.source)}${s.sha256 ? ` · <code title="SHA-256 of the indicator file used: ${esc(s.sha256)}">sha256:${esc(s.sha256.slice(0, 12))}…</code>` : ''}</span>
    </div>`).join('');
  $('#ioc-list').innerHTML = rows;
  const total = state.stix.reduce((a, s) => a + s.stats.extracted, 0);
  const applicable = state.stix.reduce((a, s) => a + s.stats.applicable, 0);
  const updates = state.stix.filter((s) => s.upstream === 'update-available').length;
  const updateNote = updates
    ? ` Upstream has published newer data for ${updates} indicator set${updates > 1 ? 's' : ''}; scans use the reviewed snapshots, and updates ship here after review (typically within a week).`
    : '';
  $('#ioc-note').textContent =
    `${applicable} of ${total} loaded indicators are process and file names or paths that can be checked against the process activity in sysdiagnose artifacts (file indicators match only when a process ran from that file - there is no filesystem listing to check). ` +
    `The rest are mostly domains, URLs and emails, which live in artifacts (browsing history, messages) found in device backups - this version does not read those, and results never imply they were checked.` +
    updateNote;
  $('#ioc-panel').hidden = false;
}

/* ---------- scanning ---------- */

let worker = null;
let workerState = 'unavailable'; // unavailable | starting | ready | scanning | failed
let workerReady = Promise.resolve(false);
const WORKER_STARTUP_TIMEOUT_MS = 8_000;
const WORKER_SCAN_FAILURE =
  'The background scanner stopped while reading this file. Trace did not retry it on the main page because doing so could freeze or crash the tab. Keep the original file, reload this page, and contact a digital security helpline if the problem repeats.';

function initWorker() {
  try {
    const w = new Worker('./worker.js', { type: 'module' });
    worker = w;
    workerState = 'starting';
    workerReady = new Promise((resolve) => {
      let settled = false;
      let timeout;
      const cleanup = () => {
        w.removeEventListener('message', onMsg);
        w.removeEventListener('error', onErr);
        clearTimeout(timeout);
      };
      const finish = (available) => {
        if (settled) return;
        settled = true;
        cleanup();
        if (available && worker === w) {
          workerState = 'ready';
        } else {
          if (worker === w) worker = null;
          workerState = 'unavailable';
          w.terminate();
        }
        resolve(available);
      };
      const onMsg = (e) => {
        if (e.data?.type === 'ready') finish(true);
        if (e.data?.type === 'init-error') finish(false);
      };
      const onErr = () => finish(false);
      w.addEventListener('message', onMsg);
      w.addEventListener('error', onErr);
      timeout = setTimeout(() => finish(false), WORKER_STARTUP_TIMEOUT_MS);
    });
  } catch {
    worker = null; // very old browser: fall back to inline scanning
    workerState = 'unavailable';
    workerReady = Promise.resolve(false);
  }
}

function updateProgress(processed, total) {
  $('#progress').value = total ? Math.round((processed / total) * 100) : 0;
  $('#progress-text').textContent = `${fmtBytes(processed)} of ${fmtBytes(total)} read`;
}

// Monotonic scan id: every worker message carries the id of the scan it
// belongs to, and listeners drop anything else. Without this, two scans
// racing (or a stale message from an aborted one) could attach findings
// to the wrong file - an evidence-provenance failure.
let scanSeq = 0;

function scanWithWorker(file) {
  return new Promise((resolve, reject) => {
    const w = worker;
    if (!w || workerState !== 'ready') {
      reject(new Error('The background scanner is not ready.'));
      return;
    }
    const id = ++scanSeq;
    const restoreReady = () => {
      if (worker === w && workerState === 'scanning') workerState = 'ready';
    };
    const onMsg = (e) => {
      const m = e.data;
      if (m.id !== id) return; // not this scan's message
      if (m.type === 'progress') {
        updateProgress(m.processed, file.size);
      } else if (m.type === 'report') {
        cleanup();
        restoreReady();
        resolve(m.report);
      } else if (m.type === 'error') {
        cleanup();
        restoreReady();
        reject(new Error(m.message));
      }
    };
    const onErr = () => {
      cleanup();
      if (worker === w) worker = null;
      workerState = 'failed';
      w.terminate();
      reject(new Error(WORKER_SCAN_FAILURE));
    };
    const cleanup = () => {
      w.removeEventListener('message', onMsg);
      w.removeEventListener('error', onErr);
    };
    w.addEventListener('message', onMsg);
    w.addEventListener('error', onErr);
    workerState = 'scanning';
    try {
      w.postMessage({
        type: 'scan',
        id,
        file,
        sets: state.stix.map((s) => ({ name: s.name, text: s.text, meta: s.meta })),
      });
    } catch (err) {
      cleanup();
      restoreReady();
      reject(err);
    }
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
    // The report envelope is assembled entirely in Rust; the producer only
    // supplies the file's declared identity. Timing comes from the engine
    // itself (its injected clock runs through parsing and assembly inside
    // finish, which a reading taken here would miss).
    scanner.set_scan_meta(JSON.stringify({
      source_name: file.name,
      source_size: file.size,
      scanned_via: 'inline',
    }));
    return JSON.parse(scanner.finish());
  } finally {
    try { state.scanner = newScanner(); } catch { /* keep last error visible */ }
  }
}

async function handleFile(file) {
  // One scan at a time: a second file racing the first (double-clicked
  // demo button, scripted calls) must not interleave results.
  if (state.scanning) return;
  state.scanning = true;
  showSection('scanning');
  updateProgress(0, file.size);
  try {
    // A file dropped before the indicator sets finish loading must wait:
    // scanning with an empty set would produce a hollow "clear".
    await state.ready;
    if (workerState === 'starting') await workerReady;
    if (workerState === 'failed') throw new Error(WORKER_SCAN_FAILURE);
    let report;
    if (worker && workerState === 'ready') {
      state.lastScanVia = 'worker';
      report = await scanWithWorker(file);
    }
    if (!report) {
      state.lastScanVia = 'inline';
      report = await scanInline(file);
    }
    // Schema v3: the report arrives complete from Rust - no fields are
    // appended here. What the UI renders is exactly what exports.
    state.lastReport = report;
    renderReport(report);
  } catch (err) {
    renderError(err);
  } finally {
    state.scanning = false;
  }
}

/* ---------- rendering results ---------- */

// The Rust engine owns the verdict: every safety consideration (parser
// health, scan limits, artifact presence) already funnels into it there.
// Rendering must never re-derive safety semantics from other report fields.
// A report without one is from an unknown source; inconclusive, never clear.
function verdictOf(report) {
  return report.verdict || 'inconclusive';
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
      <p>None of the expected artifacts (shutdown.log, crash logs, ps.txt, unified system logs) were found inside. Make sure you're scanning a file named like <code>sysdiagnose_….tar.gz</code>, captured following the guide on the start page.</p>
    </div>`;
  }
  const missing = report.missing_artifacts || [];
  // A one- or two-surface scan is a much narrower look than a full
  // sysdiagnose; the banner must not read identically to a four-surface
  // scan.
  const narrow = missing.length >= 2
    ? `<p><strong>This was a narrow scan.</strong> Most of this tool's detection surfaces were not present in the archive, so this result rests on ${4 - missing.length === 1 ? 'a single artifact type' : 'only ' + (4 - missing.length) + ' artifact types'}. A complete, freshly captured sysdiagnose gives a much stronger result.</p>`
    : '';
  const coverageNote = missing.length
    ? `${narrow}<p><strong>Coverage note:</strong> ${missing.length} of the 4 artifact types this tool reads ${missing.length > 1 ? 'were' : 'was'} not present in this archive (${missing.map((m) => esc(m.kind.replace(/_/g, ' '))).join(', ')}), so ${missing.length > 1 ? 'those surfaces' : 'that surface'} could not be checked. Details are in the table below.</p>`
    : '';
  return `<div class="verdict clear">
    <h2>No known spyware traces found</h2>
    <p>None of the ${applicable} applicable public indicators appeared in the artifacts this tool reads${noteCount ? `, though ${noteCount} informational note${noteCount > 1 ? 's are' : ' is'} listed below` : ''}.</p>
    ${coverageNote}
    <p><strong>This is not the same as "your phone is clean."</strong> It means: no publicly documented implant left its known traces in these artifacts. Spyware that is new, undocumented, or leaves traces elsewhere would not appear here. If you face real risk, treat this as one data point and consider expert help - <a href="https://www.accessnow.org/help/" target="_blank" rel="noopener noreferrer">Access Now's helpline</a> is free.</p>
  </div>`;
}

// DOM cards for findings are capped: a hostile archive can produce
// thousands, and rendering them all would hang the tab. The exported JSON
// always carries the full list.
const MAX_RENDERED_FINDINGS = 200;

function findingsHtml(report) {
  if (!report.findings.length) return '';
  const cards = report.findings.slice(0, MAX_RENDERED_FINDINGS).map((f) => {
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
  const omitted = report.findings.length - Math.min(report.findings.length, MAX_RENDERED_FINDINGS);
  const more = omitted > 0
    ? `<p class="fine">Showing the first ${MAX_RENDERED_FINDINGS} findings (sorted most severe first); ${omitted} more are in the exported report.</p>`
    : '';
  return `<h2>Findings (${report.findings.length})</h2>${cards}${more}`;
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
    <div class="table-scroll"><table class="artifacts"><thead><tr><th>Kind</th><th>Path</th><th>Status</th><th>Details</th></tr></thead>
    <tbody>${rows}${missingRows}</tbody></table></div></div>`;
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
        <span class="badge bundled">reviewed snapshot · ${esc(p.date)}</span></span>
      <span class="meta">${p.sha256 ? `<code title="SHA-256 of the indicator file used: ${esc(p.sha256)}">sha256:${esc(p.sha256.slice(0, 12))}…</code> · ` : ''}<a href="${esc(p.url)}" target="_blank" rel="noopener noreferrer">source</a></span>
    </div>`).join('');
  return `<div class="panel"><h2>Indicators used</h2>${rows}
    <p class="fine">Scans use only reviewed snapshot indicators; the hash identifies the exact revision this scan used and is recorded in the exported report. Public indicators inherit a time lag: new campaigns appear here only after researchers publish them and the snapshots are reviewed. A scan can only be as current as the open ecosystem.</p></div>`;
}

function renderReport(report) {
  const source = report.source_file || {};
  const sourceName = source.name == null || source.name === ''
    ? 'Unknown source file'
    : source.name;
  const sourceLabel = `${esc(sourceName)} (${fmtBytes(source.size)})`;
  const device = report.device
    ? `<p class="fine">Device: ${esc(report.device.os_version)} (from ${esc(report.device.source)}) · file: ${sourceLabel}</p>`
    : `<p class="fine">File: ${sourceLabel}</p>`;
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
  $('#rescan-btn').addEventListener('click', backToLanding);
  showSection('results');
  // Move focus to the verdict so screen readers announce the outcome.
  $('#results').focus();
}

function renderError(err) {
  $('#results').innerHTML = `<div class="error-box" role="alert">
    <h2>Couldn't scan that file</h2>
    <p>${esc(err?.message || err)}</p>
    <p>Make sure you're choosing the original <code>sysdiagnose_….tar.gz</code> file, not an unpacked folder or a renamed copy. Nothing was uploaded; you can simply try again.</p>
  </div>
  <div class="actions"><button class="btn secondary" id="rescan-btn">Back</button></div>`;
  $('#rescan-btn').addEventListener('click', backToLanding);
  showSection('results');
  // Same focus treatment as a successful scan, so screen readers announce
  // the failure instead of leaving focus stranded on <body>.
  $('#results').focus();
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

  // A failed fixture fetch must surface, not die as a silent rejection
  // leaving the button apparently dead.
  const demo = (path, name) => async () => {
    try {
      const r = await fetch(path);
      if (!r.ok) throw new Error(`the demo file could not be loaded (HTTP ${r.status})`);
      handleFile(new File([await r.blob()], name));
    } catch (err) {
      renderError(err);
    }
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
  renderReport,
  // For producer-parity tests: forces the inline path, exactly what a
  // browser without worker support gets.
  disableWorker() {
    worker?.terminate();
    worker = null;
    workerState = 'unavailable';
    workerReady = Promise.resolve(false);
  },
};

boot();
