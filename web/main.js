import init, { Scanner } from './pkg/trace_core.js';

const $ = (sel) => document.querySelector(sel);

const state = {
  stix: [],        // { name, source, url, text, loaded_from, date, stats }
  scanner: null,   // pre-warmed Scanner with indicators loaded
  lastReport: null,
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
    try {
      const r = await fetchWithTimeout(set.url, 6000);
      if (r.ok) {
        text = await r.text();
        JSON.parse(text); // sanity: don't accept a non-JSON error page
        loaded_from = 'live';
        date = new Date().toISOString().slice(0, 10);
      }
    } catch { /* offline or blocked - bundled snapshot below */ }
    if (!text) {
      text = await (await fetch(set.file)).text();
    }
    state.stix.push({ ...set, text, loaded_from, date });
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
      <span class="meta">${s.stats.extracted} indicators, ${s.stats.applicable} checkable here · ${esc(s.source)}</span>
    </div>`).join('');
  $('#ioc-list').innerHTML = rows;
  const total = state.stix.reduce((a, s) => a + s.stats.extracted, 0);
  const applicable = state.stix.reduce((a, s) => a + s.stats.applicable, 0);
  $('#ioc-note').textContent =
    `${applicable} of ${total} loaded indicators are process or file names that can appear in sysdiagnose artifacts. ` +
    `The rest are domains, URLs and emails, which live in artifacts (browsing history, messages) found in device backups - this version does not read those, and results never imply they were checked.`;
  $('#ioc-panel').hidden = false;
}

/* ---------- scanning ---------- */

async function handleFile(file) {
  showSection('scanning');
  const progress = $('#progress');
  const ptext = $('#progress-text');
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
      progress.value = file.size ? Math.round((processed / file.size) * 100) : 0;
      ptext.textContent = `${fmtBytes(processed)} of ${fmtBytes(file.size)} read`;
      if (++n % 2 === 0) await new Promise((r) => setTimeout(r, 0));
    }
    const report = JSON.parse(scanner.finish());
    report.generated_at = new Date().toISOString();
    report.source_file = { name: file.name, size: file.size };
    report.indicator_provenance = state.stix.map((s) => ({
      name: s.name, campaign: s.stats.campaign, loaded_from: s.loaded_from, date: s.date, url: s.url,
    }));
    state.lastReport = report;
    renderReport(report);
  } catch (err) {
    renderError(err);
  } finally {
    try { state.scanner = newScanner(); } catch { /* keep last error visible */ }
  }
}

/* ---------- rendering results ---------- */

function verdictOf(report) {
  if (report.stats.artifacts_found === 0) return 'invalid';
  if (report.findings.some((f) => f.severity === 'match')) return 'match';
  if (report.findings.some((f) => f.severity === 'suspicious')) return 'suspicious';
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
          <li><a href="https://www.accessnow.org/help/" rel="noopener">Access Now Digital Security Helpline</a> - 24/7, multiple languages</li>
          <li><a href="https://securitylab.amnesty.org/get-help/" rel="noopener">Amnesty International Security Lab</a> - forensic support for civil society</li>
        </ul>
      </li>
      <li>If you fear your device is being watched, consider making contact <strong>from a different device</strong>.</li>
    </ul>
  </div>`;

function verdictHtml(report) {
  const v = verdictOf(report);
  const applicable = report.stats.applicable_indicators;
  const noteCount = report.findings.filter((f) => f.severity === 'note').length;
  if (v === 'match') {
    return `<div class="verdict match">
      <h2>Traces matching known spyware were found</h2>
      <p>This file contains entries that exactly match published indicators of mercenary spyware. That is a serious signal, and it deserves expert eyes - but it is not final proof on its own.</p>
      <p>Please follow the steps below. You are not alone in this, and help is free.</p>
    </div>` + HELP_BLOCK;
  }
  if (v === 'suspicious') {
    return `<div class="verdict suspicious">
      <h2>No indicator matches - but anomalies worth expert review</h2>
      <p>Nothing matched a published indicator, but the scan found patterns that public research has associated with spyware infections. This is <strong>not a detection</strong>; these anomalies sometimes have benign causes.</p>
      <p>If you have independent reasons to be concerned, the helplines below can look deeper. Keep this file either way.</p>
    </div>` + HELP_BLOCK;
  }
  if (v === 'invalid') {
    return `<div class="verdict invalid">
      <h2>This doesn't look like a sysdiagnose archive</h2>
      <p>None of the expected artifacts (shutdown.log, crash logs, ps.txt) were found inside. Make sure you're scanning a file named like <code>sysdiagnose_….tar.gz</code>, captured following the guide on the start page.</p>
    </div>`;
  }
  return `<div class="verdict clear">
    <h2>No known spyware traces found</h2>
    <p>None of the ${applicable} applicable public indicators appeared in the artifacts this tool reads${noteCount ? `, though ${noteCount} informational note${noteCount > 1 ? 's are' : ' is'} listed below` : ''}.</p>
    <p><strong>This is not the same as "your phone is clean."</strong> It means: no publicly documented implant left its known traces in these artifacts. Spyware that is new, undocumented, or leaves traces elsewhere would not appear here. If you face real risk, treat this as one data point and consider expert help - <a href="https://www.accessnow.org/help/" rel="noopener">Access Now's helpline</a> is free.</p>
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
  return `<div class="panel"><h2>What was examined (${report.artifacts.length} artifacts, ${report.stats.archive_entries} files in archive)</h2>
    <table class="artifacts"><thead><tr><th>Kind</th><th>Path</th><th>Status</th><th>Details</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
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
      <span class="meta"><a href="${esc(p.url)}" rel="noopener">source</a></span>
    </div>`).join('');
  return `<div class="panel"><h2>Indicators used</h2>${rows}
    <p class="fine">Public indicators inherit a time lag: new campaigns appear here only after researchers publish them. A scan can only be as current as the open ecosystem.</p></div>`;
}

function renderReport(report) {
  const device = report.device
    ? `<p class="fine">Device: ${esc(report.device.os_version)} (from ${esc(report.device.source)}) · file: ${esc(report.source_file.name)} (${fmtBytes(report.source_file.size)})</p>`
    : `<p class="fine">File: ${esc(report.source_file.name)} (${fmtBytes(report.source_file.size)})</p>`;
  $('#results').innerHTML =
    verdictHtml(report) +
    device +
    findingsHtml(report) +
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
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `trace-report-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
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
  dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('dragover'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('dragover'));
  dz.addEventListener('drop', (e) => {
    e.preventDefault();
    dz.classList.remove('dragover');
    const file = e.dataTransfer?.files?.[0];
    if (file) handleFile(file);
  });
  input.addEventListener('change', () => {
    if (input.files?.[0]) handleFile(input.files[0]);
    input.value = '';
  });

  $('#prove-it').addEventListener('click', () => $('#prove-dialog').showModal());

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
  await init();
  await loadIndicators();
  state.scanner = newScanner();
  renderIocPanel();
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('./sw.js').catch(() => { /* non-fatal */ });
  }
}

// Exposed for end-to-end tests; handleFile is the same path the UI uses.
window.__trace = {
  handleFile,
  get lastReport() { return state.lastReport; },
  get ready() { return state.scanner !== null; },
};

boot();
