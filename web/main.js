import init, { Scanner } from './pkg/trace_core.js';
import { readableReportDocument, readableReportFragment, esc } from './readable-report.js';
import {
  hasExpectedBundledSetRoster,
  meetsReviewedFloor,
} from './indicator-floor.js';
import {
  isCompleteReportEnvelope,
  isNonnegativeInteger,
  isPairedDeviceArtifactPath,
} from './report-validator.js';

const $ = (sel) => document.querySelector(sel);
const observedInstallingWorkers = new WeakSet();
const observedServiceWorkerRegistrations = new WeakSet();

const state = {
  stix: [],          // { name, source, url, text, loaded_from, date, stats }
  ready: null,       // resolves once WASM + bundled indicators are validated
  freshnessReady: Promise.resolve(), // optional upstream check; never gates scanning
  indicatorsReady: false,
  cacheReady: false,
  lastReport: null,
  lastReportContext: null, // UI-only context; never added to the report contract
  readableReport: null, // report snapshot currently owned by the readable-export dialog
  readableContext: null,
  lastScanVia: null, // 'worker' | 'inline'
  scanning: false,   // a scan is in flight; new files are ignored until done
  demoLoading: false,
  serviceWorkerRegistration: null,
  waitingWorker: null, // a complete newer release waiting for every old client to close
  activeScan: null,
  scanIntent: 0,
};

/* ---------- utilities ---------- */

// esc() and meetsReviewedFloor() are imported above so their single definition
// is shared with the readable export and the scan worker respectively.

function fmtBytes(n) {
  if (!Number.isFinite(n) || n < 0) return 'size unavailable';
  if (n >= 1 << 30) return (n / (1 << 30)).toFixed(2) + ' GB';
  if (n >= 1 << 20) return (n / (1 << 20)).toFixed(1) + ' MB';
  if (n >= 1 << 10) return (n / (1 << 10)).toFixed(0) + ' KB';
  return n + ' B';
}

function httpsHref(value) {
  if (typeof value !== 'string') return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' ? url.href : null;
  } catch {
    return null;
  }
}

const UPSTREAM_BODY_LIMIT = Number.isSafeInteger(globalThis.__TRACE_TEST_UPSTREAM_MAX_BYTES)
  && globalThis.__TRACE_TEST_UPSTREAM_MAX_BYTES > 0
  ? globalThis.__TRACE_TEST_UPSTREAM_MAX_BYTES
  : 8 * 1024 * 1024;
const UPSTREAM_CONCURRENCY = 2;

// The timeout covers the body read too, and the byte ceiling prevents an
// optional freshness check from retaining an unbounded upstream response.
async function fetchTextWithTimeout(url, ms, maxBytes = UPSTREAM_BODY_LIMIT) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    const r = await fetch(url, { signal: ctrl.signal, cache: 'no-store' });
    if (!r.ok) return null;
    const declared = Number(r.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > maxBytes) return null;
    if (!r.body) {
      const text = await r.text();
      return new TextEncoder().encode(text).byteLength <= maxBytes ? text : null;
    }
    const reader = r.body.getReader();
    const decoder = new TextDecoder();
    let total = 0;
    let text = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        return null;
      }
      text += decoder.decode(value, { stream: true });
    }
    return text + decoder.decode();
  } catch {
    return null; // offline, blocked, or timed out
  } finally {
    clearTimeout(t);
  }
}

// Identifies the exact indicator revision a scan used; "live" plus a date is
// not provenance. Null only in non-secure contexts, where subtle is absent.
async function sha256hex(value) {
  if (!globalThis.crypto?.subtle) return null;
  const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value;
  const digest = await globalThis.crypto.subtle.digest(
    'SHA-256',
    bytes
  );
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

async function mapWithConcurrency(items, limit, mapper) {
  const results = new Array(items.length);
  let next = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const index = next++;
      if (index >= items.length) return;
      results[index] = await mapper(items[index], index);
    }
  });
  await Promise.all(runners);
  return results;
}

function showSection(name) {
  for (const id of ['landing', 'scanning', 'results']) {
    $('#' + id).hidden = id !== name;
  }
  $('#about').hidden = name === 'scanning';
}

function updateLandingControls() {
  const enabled = state.indicatorsReady && !state.scanning && !state.demoLoading
    && !state.waitingWorker;
  $('#file-input').disabled = !enabled;
  $('#demo-clean').disabled = !enabled;
  $('#demo-infected').disabled = !enabled;
  $('#dropzone').setAttribute('aria-disabled', String(!enabled));
  refreshUpdateNotice();
}

function refreshUpdateNotice() {
  const notice = $('#update-notice');
  if (!notice) return;
  if (!state.waitingWorker) {
    notice.hidden = true;
    $('#update-announcer').textContent = '';
    return;
  }
  notice.hidden = false;
  const common = ' Close every Trace tab and window, then reopen Trace. Reloading this tab alone may leave the older release active.';
  if (state.scanning || state.demoLoading) {
    $('#update-message').textContent =
      `This scan will finish with the currently loaded release. After it finishes, save any report you need.${common}`;
  } else if (state.lastReport) {
    $('#update-message').textContent =
      `Save this result if you need it; results exist only in this tab.${common} Do that before scanning another file.`;
  } else {
    $('#update-message').textContent =
      `Reopen Trace before scanning so the page, scanner, indicators, and offline cache all come from one release.${common}`;
  }
}

function markWaitingRelease(worker) {
  // On a first-ever visit there is no older controlled page to update. The
  // initial worker activates normally, so presenting an update warning would
  // be both wrong and needlessly disable scanning.
  if (!navigator.serviceWorker?.controller || !worker) return;
  const firstAnnouncement = !state.waitingWorker;
  state.waitingWorker = worker;
  updateLandingControls();
  if (firstAnnouncement) {
    $('#update-announcer').textContent =
      'A newer Trace release is ready. New scans are disabled. Finish or save current work, close every Trace tab and window, then reopen Trace.';
  }
}

function observeInstallingRelease(registration, installing) {
  if (!installing || observedInstallingWorkers.has(installing)) return;
  observedInstallingWorkers.add(installing);
  const onStateChange = () => {
    if (installing.state === 'installed') {
      markWaitingRelease(registration.waiting || installing);
    } else if (installing.state === 'redundant' && state.waitingWorker === installing) {
      state.waitingWorker = null;
      updateLandingControls();
    }
  };
  installing.addEventListener('statechange', onStateChange);
  // register() can resolve while an update is already installing. Observe its
  // current state as well as later transitions so that race cannot be missed.
  onStateChange();
}

function observeServiceWorkerRegistration(registration) {
  state.serviceWorkerRegistration = registration;
  if (registration.waiting) markWaitingRelease(registration.waiting);
  observeInstallingRelease(registration, registration.installing);
  if (observedServiceWorkerRegistrations.has(registration)) return;
  observedServiceWorkerRegistrations.add(registration);
  registration.addEventListener('updatefound', () => {
    observeInstallingRelease(registration, registration.installing);
  });
}

function requestServiceWorkerUpdate() {
  const registration = state.serviceWorkerRegistration;
  if (!navigator.onLine || typeof registration?.update !== 'function') return;
  registration.update().catch(() => { /* advisory while online; scanning remains local */ });
}

function setScannerStatus(kind, message) {
  const status = $('#scanner-status');
  status.classList.remove('preparing', 'ready', 'error');
  status.classList.add(kind);
  status.textContent = message;
  status.setAttribute('role', kind === 'error' ? 'alert' : 'status');
  updateLandingControls();
  setOnlineState();
}

function setOnlineState() {
  const text = $('#privacy-text');
  if (!text) return;
  const offline = !navigator.onLine;
  $('#offline-dot').classList.toggle('offline', offline);
  if (offline && state.indicatorsReady) {
    text.textContent = state.cacheReady
      ? 'You are offline. The scanner and reviewed indicators are loaded in this tab, and the app shell is ready for an offline reload. This does not authenticate code already loaded.'
      : 'You are offline. The scanner and reviewed indicators are loaded in this tab, so this open page can scan locally. Offline reload readiness has not been confirmed, and offline status does not authenticate loaded code.';
  } else if (offline) {
    text.textContent = 'You are offline before the scanner and reviewed indicators finished loading. Scanning is unavailable until those bundled assets load.';
  } else {
    const readiness = state.indicatorsReady
      ? 'The scanner and reviewed indicators are ready.'
      : 'The scanner is still preparing.';
    const cache = state.cacheReady
      ? ' The app shell is ready for an offline reload.'
      : ' Offline reload readiness has not yet been confirmed.';
    text.textContent = `Analysis is designed to run entirely in this browser tab. Trace has no upload endpoint, and its intended code sends no archive bytes. ${readiness}${cache}`;
  }
}

// Returning from results, keyboard focus lands on the next action instead
// of being lost on the removed button.
function backToLanding() {
  // Results can contain sensitive case metadata. Once the person leaves the
  // result view, do not retain an exportable report behind the landing page.
  state.lastReport = null;
  state.lastReportContext = null;
  $('#results').replaceChildren();
  showSection('landing');
  if (state.indicatorsReady) {
    setScannerStatus('ready', 'Scanner ready. Bundled, reviewed indicators passed their integrity checks.');
  }
  (state.waitingWorker ? $('#update-notice') : $('#dropzone')).focus();
}

/* ---------- indicator loading ---------- */

// Scans use only the bundled, reviewed indicator snapshots. Live upstream
// data never reaches a verdict: a count-based check cannot tell a legitimate
// change from a rollback or lateral rewrite. The upstream fetch therefore
// reports only whether plausible content differs from the reviewed snapshot;
// it never claims that the different content is chronologically newer.
function isPlausibleUpdate(set, text) {
  try {
    if (!Array.isArray(JSON.parse(text).objects)) return false;
    const probe = new Scanner();
    try {
      const stats = JSON.parse(probe.load_stix(set.name, text));
      return meetsReviewedFloor(set, stats);
    } finally {
      probe.free();
    }
  } catch {
    return false;
  }
}

async function loadBundledIndicators() {
  // 'no-cache' forces revalidation: dev servers without Cache-Control
  // otherwise leave heuristically cached stale copies in play. In
  // production the service worker answers these before HTTP caching
  // matters, so this only costs a conditional request on first load.
  const manifestResponse = await fetch('./iocs/manifest.json', { cache: 'no-cache' });
  if (!manifestResponse.ok) {
    throw new Error(
      `The bundled indicator manifest could not be loaded (HTTP ${manifestResponse.status}).`
    );
  }
  const manifest = await manifestResponse.json();
  if (!hasExpectedBundledSetRoster(manifest?.sets)) {
    throw new Error(
      'The bundled indicator manifest failed its reviewed roster and SHA-256 pin check.'
    );
  }
  state.stix = await Promise.all(manifest.sets.map(async (set) => {
    const response = await fetch(set.file, { cache: 'no-cache' });
    if (!response.ok) {
      throw new Error(
        `Bundled indicator set "${set.name}" could not be loaded (HTTP ${response.status}).`
      );
    }
    const bytes = await response.arrayBuffer();
    const sha256 = await sha256hex(bytes);
    if (sha256 === null || sha256 !== set.sha256) {
      throw new Error(
        `Bundled indicator set "${set.name}" failed its reviewed SHA-256 check.`
      );
    }
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    // Catalog metadata recorded as provenance in the report envelope; the
    // engine hashes the set text itself too, so the recorded identity is
    // independently bound to the exact bytes verified here.
    const meta = {
      date: manifest.bundled_date, url: set.url, source: set.source,
      loaded_from: 'bundled', upstream: 'unknown',
    };
    return {
      ...set,
      text,
      loaded_from: 'bundled',
      date: manifest.bundled_date,
      sha256,
      upstream: 'unknown',
      meta,
    };
  }));
}

// Freshness is advisory and must never delay or weaken a scan. Responses are
// fetched with bounded concurrency and a byte ceiling, then statuses are
// committed together so a scan snapshots one coherent provenance state.
async function refreshIndicatorFreshness() {
  const statuses = await mapWithConcurrency(
    state.stix,
    UPSTREAM_CONCURRENCY,
    async (set) => {
      const live = await fetchTextWithTimeout(set.url, 6000);
      if (live === null || set.sha256 === null) return 'unknown';
      const liveSha = await sha256hex(live);
      if (liveSha === null) return 'unknown';
      if (liveSha === set.sha256) return 'current';
      return isPlausibleUpdate(set, live) ? 'update-available' : 'unknown';
    }
  );
  for (let i = 0; i < state.stix.length; i++) {
    state.stix[i].upstream = statuses[i];
    state.stix[i].meta = { ...state.stix[i].meta, upstream: statuses[i] };
  }
  renderIocPanel();
}

function newScanner(sets = state.stix) {
  const s = new Scanner();
  try {
    for (const set of sets) {
      const stats = JSON.parse(
        s.load_stix_with_meta(set.name, set.text, JSON.stringify(set.meta))
      );
      // The bundled snapshots are the detection floor. CI protects the
      // repository copies, but the browser must also reject a partial,
      // stale, or damaged deployed asset instead of scanning with one
      // campaign silently missing.
      if (!meetsReviewedFloor(set, stats)) {
        throw new Error(
          `Bundled indicator set "${set.name}" is below its reviewed floor ` +
          `(${stats.extracted} indicators/${stats.applicable} applicable; expected at least ` +
          `${set.min_indicators}/${set.min_applicable}). Scanning is unavailable.`
        );
      }
      set.stats = stats;
    }
    return s;
  } catch (err) {
    s.free();
    throw err;
  }
}

function renderIocPanel() {
  const rows = state.stix.map((s) => {
    const freshnessClass = s.upstream === 'current'
      ? 'freshness-current'
      : s.upstream === 'update-available' ? 'freshness-update' : 'freshness-unknown';
    const freshnessLabel = s.upstream === 'current'
      ? 'upstream matched'
      : s.upstream === 'update-available' ? 'upstream content differs' : 'freshness unchecked';
    return `
    <div class="ioc-row">
      <span><span class="campaign">${esc(s.stats.campaign)}</span>
        <span class="badge bundled">reviewed snapshot · ${esc(s.date)}</span>
        <span class="badge ${freshnessClass}">${freshnessLabel}</span></span>
      <span class="meta">${s.stats.extracted} indicators, ${s.stats.applicable} reviewed for negative process coverage · ${esc(s.source)}${s.sha256 ? ` · <code title="SHA-256 of the indicator file used: ${esc(s.sha256)}">sha256:${esc(s.sha256.slice(0, 12))}…</code>` : ''}</span>
    </div>`;
  }).join('');
  $('#ioc-list').innerHTML = rows;
  const total = state.stix.reduce((a, s) => a + s.stats.extracted, 0);
  const applicable = state.stix.reduce((a, s) => a + s.stats.applicable, 0);
  const differences = state.stix.filter((s) => s.upstream === 'update-available').length;
  const unknown = state.stix.filter((s) => s.upstream === 'unknown').length;
  const freshnessNote = differences
    ? ` Different plausible upstream content was detected for ${differences} indicator set${differences > 1 ? 's' : ''}. This does not prove that the upstream content is newer; it may be a rollback or rewrite and requires review. Scans continue to use the dated, reviewed snapshots.`
    : unknown
      ? ` Upstream freshness is currently unknown for ${unknown} indicator set${unknown > 1 ? 's' : ''}; scans still use the dated, reviewed snapshots shown above.`
      : ' The published upstream files matched all reviewed snapshots at this check.';
  $('#ioc-note').textContent =
    `${applicable} of ${total} loaded indicators establish reviewed negative coverage over the process identities Trace observes. Other safe file-name and file-path indicators remain available for exact positive matches against observed process basenames or canonical executable paths, treating Apple /var, /tmp, and /etc aliases as equivalent to /private/... for comparison (and matching descendants when an indicator is a directory ending in /). Trace does not inspect a filesystem listing, so those other file indicators cannot establish negative coverage. ` +
    `The rest are mostly domains, URLs and emails, which live in artifacts (browsing history, messages) found in device backups - this version does not read those, and results never imply they were checked.` +
    freshnessNote;
  $('#ioc-panel').hidden = false;
}

/* ---------- scanning ---------- */

let worker = null;
let workerState = 'unavailable'; // unavailable | starting | ready | scanning
let workerReady = Promise.resolve(false);
// Inline scanning is an availability fallback only for browsers where the
// background worker could not be started before any archive was handed to it.
// Once a scan has reached a worker, a failed replacement must never turn the
// next explicit retry into a main-thread replay of the same potentially
// hostile bytes.
let workerRequiredForRetry = false;
const WORKER_STARTUP_TIMEOUT_MS = 8_000;
const WORKER_SCAN_INACTIVITY_TIMEOUT_MS = Number.isSafeInteger(
  globalThis.__TRACE_TEST_WORKER_TIMEOUT_MS
) && globalThis.__TRACE_TEST_WORKER_TIMEOUT_MS > 0
  ? globalThis.__TRACE_TEST_WORKER_TIMEOUT_MS
  : 45_000;
// finish() is a single blocking WASM call (parse, match, verdict assembly)
// that emits no heartbeats, so once the worker signals it has entered that
// phase the streaming inactivity window no longer applies. This deadline is
// sized for worst-case finalization on a capped-size input; it is generous
// because failing here rejects a valid scan of a healthy worker.
const WORKER_SCAN_FINALIZE_TIMEOUT_MS = 120_000;
const WORKER_SCAN_FAILURE =
  'The background scanner stopped while reading this file. Trace did not retry it on the main page because doing so could freeze or crash the tab. A fresh background scanner is preparing; go back and choose the file again. Keep the original file and contact a digital security helpline if the problem repeats.';
const WORKER_RESTART_FAILURE =
  'The background scanner could not be restarted. Trace did not retry this file on the main page because doing so could freeze or crash the tab. Reload the page before trying again. Keep the original file and contact a digital security helpline if the problem repeats.';

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

// Discard a worker whose WASM instance may be poisoned and start a fresh
// one for the next scan. Guarded on identity so a slower callback cannot
// tear down a worker that has already been replaced.
function recycleWorker(expected) {
  if (worker !== expected) return;
  workerRequiredForRetry = true;
  worker = null;
  try {
    expected.terminate();
  } catch {
    /* already gone */
  }
  initWorker();
}

class ScanCancelledError extends Error {
  constructor() {
    super('Scan canceled.');
    this.name = 'ScanCancelledError';
  }
}

function snapshotIndicatorSets() {
  return state.stix.map((set) => ({
    ...set,
    meta: { ...set.meta },
    stats: { ...set.stats, by_kind: { ...set.stats.by_kind } },
  }));
}

function setScanPhase(phase, file, control) {
  const heading = $('#scan-heading');
  const progress = $('#progress');
  const progressText = $('#progress-text');
  const cancel = $('#cancel-scan');
  $('#scan-file').textContent = file.name;
  if (phase === 'preparing') {
    heading.textContent = 'Preparing scanner…';
    progress.removeAttribute('value');
    progress.setAttribute('aria-label', 'Preparing scanner');
    progressText.textContent = 'Waiting for the validated scanner and indicator snapshots.';
    cancel.disabled = false;
  } else if (phase === 'reading') {
    heading.textContent = 'Reading archive…';
    progress.value = 0;
    progress.setAttribute('aria-label', 'Archive read progress');
    progressText.textContent = control.via === 'inline'
      ? 'Background isolation is unavailable, so this fallback scan is reading in the page. The tab may pause during analysis.'
      : `0 B of ${fmtBytes(file.size)} read`;
    cancel.disabled = false;
  } else if (phase === 'analyzing') {
    heading.textContent = 'Analyzing evidence…';
    progress.removeAttribute('value');
    progress.setAttribute('aria-label', 'Analyzing evidence');
    progressText.textContent = control.via === 'inline'
      ? 'The archive is read. Trace is analyzing artifacts in the page; this blocking fallback phase cannot be interrupted safely.'
      : 'The archive is read. Trace is matching indicators and preparing the report.';
    cancel.disabled = control.via === 'inline';
  } else {
    heading.textContent = 'Canceling scan…';
    progress.removeAttribute('value');
    progress.setAttribute('aria-label', 'Canceling scan');
    progressText.textContent = 'Discarding this scan. No report will be created.';
    cancel.disabled = true;
  }
  if (control.phase !== phase) {
    control.phase = phase;
    $('#scan-live').textContent = `${heading.textContent} ${progressText.textContent}`;
  }
}

function updateProgress(processed, total, control) {
  const percent = total ? Math.min(100, Math.round((processed / total) * 100)) : 0;
  $('#progress').value = percent;
  const fallback = control.via === 'inline'
    ? ' Background isolation is unavailable; analysis will run in this page and may briefly pause the tab.'
    : '';
  $('#progress-text').textContent =
    `${fmtBytes(processed)} of ${fmtBytes(total)} read (${percent}%).${fallback}`;
  const announcement = Math.floor(percent / 25) * 25;
  if (announcement >= 25 && announcement < 100
      && announcement > control.lastAnnouncedProgress) {
    control.lastAnnouncedProgress = announcement;
    $('#scan-live').textContent = `Reading archive: ${announcement}% complete.`;
  }
}

// Monotonic scan id: every worker message carries the id of the scan it
// belongs to, and listeners drop anything else. Without this, two scans
// racing (or a stale message from an aborted one) could attach findings
// to the wrong file - an evidence-provenance failure.
let scanSeq = 0;

function scanWithWorker(file, expectedSets, control) {
  return new Promise((resolve, reject) => {
    const w = worker;
    if (!w || workerState !== 'ready') {
      reject(new Error('The background scanner is not ready.'));
      return;
    }
    const id = ++scanSeq;
    let inactivityTimeout;
    let settled = false;
    function cleanup() {
      w.removeEventListener('message', onMsg);
      w.removeEventListener('error', onErr);
      w.removeEventListener('messageerror', onMessageError);
      clearTimeout(inactivityTimeout);
      if (control.cancel === cancel) control.cancel = null;
    }
    const restoreReady = () => {
      if (worker === w && workerState === 'scanning') workerState = 'ready';
    };
    const finishReject = (error, disposition = 'restore') => {
      if (settled) return;
      settled = true;
      cleanup();
      if (disposition === 'recycle') recycleWorker(w);
      else restoreReady();
      reject(error);
    };
    const finishResolve = (report) => {
      if (settled) return;
      settled = true;
      cleanup();
      restoreReady();
      resolve(report);
    };
    const failClosed = () => {
      finishReject(new Error(WORKER_SCAN_FAILURE), 'recycle');
    };
    const armInactivityTimeout = () => {
      clearTimeout(inactivityTimeout);
      inactivityTimeout = setTimeout(failClosed, WORKER_SCAN_INACTIVITY_TIMEOUT_MS);
    };
    const onMsg = (e) => {
      const m = e.data;
      if (!m || typeof m !== 'object' || m.id !== id) return; // not this scan's message
      if (m.type === 'progress') {
        if (!isNonnegativeInteger(m.processed) || m.processed > file.size) {
          failClosed();
          return;
        }
        armInactivityTimeout();
        updateProgress(m.processed, file.size, control);
      } else if (m.type === 'finalizing') {
        // Streaming is done and the worker is now inside the blocking finish()
        // call, which cannot post progress until it returns. Swap the
        // inactivity window for a single finalize deadline so a legitimately
        // slow finish is not failed closed as if the worker had hung.
        clearTimeout(inactivityTimeout);
        inactivityTimeout = setTimeout(failClosed, WORKER_SCAN_FINALIZE_TIMEOUT_MS);
        setScanPhase('analyzing', file, control);
      } else if (m.type === 'report') {
        if (!isCompleteReportEnvelope(m.report, file, 'worker', expectedSets)) {
          // A malformed success message is not permission to replay a
          // potentially hostile archive on the main thread. Treat the worker
          // as unreliable, replace it, and keep this scan failed closed.
          finishReject(new Error(WORKER_SCAN_FAILURE), 'recycle');
        } else {
          finishResolve(m.report);
        }
      } else if (m.type === 'error') {
        // A scan error may be a clean rejection (not an archive) or a WASM
        // trap that left the instance's memory in an undefined state - and
        // the two are indistinguishable from here. Reusing a trapped
        // instance for the next scan could silently corrupt its result, so
        // the worker is discarded and a fresh one spun up. Fail closed.
        finishReject(new Error(m.message), 'recycle');
      }
    };
    const onErr = () => {
      failClosed();
    };
    const onMessageError = () => failClosed();
    const cancel = () => {
      control.cancelled = true;
      finishReject(new ScanCancelledError(), 'recycle');
    };
    control.cancel = cancel;
    w.addEventListener('message', onMsg);
    w.addEventListener('error', onErr);
    w.addEventListener('messageerror', onMessageError);
    workerState = 'scanning';
    try {
      w.postMessage({
        type: 'scan',
        id,
        file,
        sets: expectedSets.map((s) => ({
          name: s.name,
          text: s.text,
          meta: s.meta,
          min_indicators: s.min_indicators,
          min_applicable: s.min_applicable,
        })),
      });
      armInactivityTimeout();
    } catch (err) {
      finishReject(err);
    }
  });
}

async function scanInline(file, expectedSets, control) {
  const scanner = newScanner(expectedSets);
  try {
    const reader = file.stream().getReader();
    control.cancel = () => {
      control.cancelled = true;
      Promise.resolve(reader.cancel()).catch(() => { /* cancellation is best-effort */ });
    };
    let processed = 0;
    let n = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (control.cancelled) throw new ScanCancelledError();
      scanner.push(value);
      processed += value.byteLength;
      updateProgress(processed, file.size, control);
      if (++n % 2 === 0) await new Promise((r) => setTimeout(r, 0));
    }
    if (control.cancelled) throw new ScanCancelledError();
    setScanPhase('analyzing', file, control);
    control.cancel = null;
    // Let the distinct phase paint before the main-thread fallback enters the
    // blocking WASM finish call.
    await new Promise((resolve) => setTimeout(resolve, 0));
    // The report envelope is assembled entirely in Rust; the producer only
    // supplies the file's declared identity. Timing comes from the engine
    // itself (its injected clock runs through parsing and assembly inside
    // finish, which a reading taken here would miss).
    scanner.set_scan_meta(JSON.stringify({
      source_name: file.name,
      source_size: file.size,
      scanned_via: 'inline',
    }));
    const report = JSON.parse(scanner.finish());
    if (!isCompleteReportEnvelope(report, file, 'inline', expectedSets)) {
      throw new Error('The scanner returned an incomplete report. No verdict was shown.');
    }
    return report;
  } finally {
    control.cancel = null;
    try { scanner.free(); } catch { /* already released */ }
  }
}

function cancelCurrentScan() {
  const control = state.activeScan;
  if (!control || control.cancelled) return;
  control.cancelled = true;
  setScanPhase('canceling', control.file, control);
  control.cancel?.();
}

async function handleFile(file, context = {}, intent = null) {
  const resolvedIntent = intent ?? ++state.scanIntent;
  if (resolvedIntent !== state.scanIntent) return;
  // A completed newer release means this page is knowingly stale. Never start
  // another scan under it: all Trace clients must close so the already-cached
  // release can activate as one page/worker/WASM/indicator generation.
  if (state.waitingWorker) {
    refreshUpdateNotice();
    $('#update-notice').focus();
    return;
  }
  // One scan at a time: a second file racing the first (double-clicked
  // demo button, scripted calls) must not interleave results.
  if (state.scanning) return;
  state.scanning = true;
  state.demoLoading = false;
  updateLandingControls();
  const control = {
    file,
    phase: null,
    via: null,
    cancelled: false,
    cancel: null,
    lastAnnouncedProgress: 0,
  };
  state.activeScan = control;
  // A modal preview must never remain visible over a different scan. Its
  // close handler also releases the report snapshot owned by that dialog.
  const readableDialog = $('#readable-dialog');
  if (readableDialog?.open) readableDialog.close();
  // The previous report no longer owns the results screen once a new scan
  // starts. Clearing it prevents an error from leaving stale provenance in
  // state even though no report is being shown.
  state.lastReport = null;
  state.lastReportContext = null;
  // Results may contain sensitive case data and event listeners that close
  // over it. Remove the old tree immediately rather than retaining it, hidden,
  // for the duration of a new scan.
  $('#results').replaceChildren();
  showSection('scanning');
  // The control that had focus lives inside the now-hidden landing section, so
  // move focus to the scanning view instead of letting it fall back to <body>.
  $('#scanning').focus();
  setScanPhase('preparing', file, control);
  let cancelled = false;
  try {
    // A file dropped before the indicator sets finish loading must wait:
    // scanning with an empty set would produce a hollow "clear".
    await state.ready;
    if (control.cancelled) throw new ScanCancelledError();
    if (workerState === 'starting') await workerReady;
    if (control.cancelled) throw new ScanCancelledError();
    const expectedSets = snapshotIndicatorSets();
    let report;
    if (worker && workerState === 'ready') {
      state.lastScanVia = 'worker';
      control.via = 'worker';
      setScanPhase('reading', file, control);
      report = await scanWithWorker(file, expectedSets, control);
    } else if (workerRequiredForRetry) {
      throw new Error(WORKER_RESTART_FAILURE);
    } else {
      state.lastScanVia = 'inline';
      control.via = 'inline';
      setScanPhase('reading', file, control);
      report = await scanInline(file, expectedSets, control);
    }
    // Schema v4: the report arrives complete from Rust - no fields are
    // appended here. What the UI renders is exactly what exports.
    renderReport(report, { example: context.example === true });
  } catch (err) {
    if (err instanceof ScanCancelledError || control.cancelled) cancelled = true;
    else renderError(err);
  } finally {
    state.scanning = false;
    if (state.activeScan === control) state.activeScan = null;
    updateLandingControls();
    if (cancelled) {
      state.lastReport = null;
      state.lastReportContext = null;
      $('#results').replaceChildren();
      showSection('landing');
      setScannerStatus(
        'ready',
        'Scan canceled. No report was created. Scanner ready with bundled, reviewed indicators.'
      );
      (state.waitingWorker ? $('#update-notice') : $('#dropzone')).focus();
    }
  }
}

/* ---------- rendering results ---------- */

// The Rust engine owns the verdict: every safety consideration (parser
// health, scan limits, artifact presence) already funnels into it there.
// Rendering must never re-derive safety semantics from other report fields.
// A report without a verdict we recognize is from an unknown or newer
// source; treat it as inconclusive, never clear. Only 'clear' earns the
// reassuring banner, and only when the report carries that exact verdict value.
const KNOWN_VERDICTS = new Set([
  'match',
  'suspicious',
  'inconclusive',
  'invalid',
  'clear',
]);
function verdictOf(report) {
  const v = report.verdict;
  return KNOWN_VERDICTS.has(v) ? v : 'inconclusive';
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
    ? `<p><strong>Note: processing or reporting was incomplete.</strong> Read each item under "Scan limits reached" below: some evidence may not have been analyzed, or some findings may not have been retained.</p>`
    : '';
  if (v === 'match') {
    return `<div class="verdict match">
      <h2>Traces matching known spyware were found</h2>
      <p>This file contains process-bearing entries that matched published indicators of mercenary spyware. Trace compares exact process names and file paths after treating Apple's <code>/var</code>, <code>/tmp</code>, and <code>/etc</code> aliases as equivalent to <code>/private/...</code>; a file-name indicator may also match an observed process basename, and a directory path ending in <code>/</code> may match a descendant under the same comparison. This is a serious signal that deserves expert review, but it is not final proof on its own.</p>
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
      <p>This scan did not complete without processing or reporting limits, so <strong>no conclusive negative result can be given</strong>. Nothing matched in the retained result, but a limited scan must not be presented as "no traces found".</p>
      <ul>${limits.map((l) => `<li>${esc(l)}</li>`).join('')}</ul>
      <p>This is unusual: a real sysdiagnose never comes close to these limits. Try capturing and scanning a fresh sysdiagnose. If this happens again, contact <a href="https://www.accessnow.org/help/" target="_blank" rel="noopener noreferrer">Access Now's helpline</a> (free, confidential) and mention the file could not be scanned.</p>
    </div>`;
  }
  if (v === 'invalid') {
    return `<div class="verdict invalid">
      <h2>This doesn't look like a sysdiagnose archive</h2>
      <p>None of the expected artifacts (shutdown.log, crash or diagnostic .ips reports, ps.txt, unified system logs) were found inside. Make sure you're scanning a file named like <code>sysdiagnose_….tar.gz</code>, captured following the guide on the start page.</p>
    </div>`;
  }
  const missing = report.missing_artifacts || [];
  const primarySurfacesExamined = report.assurance.surfaces_examined;
  const pairedOnly = primarySurfacesExamined === 0
    && report.artifacts.some((artifact) => (
      artifact.kind === 'crash_log'
      && artifact.details?.paired_device === true
      && isPairedDeviceArtifactPath(artifact.path)
    ));
  // A one- or two-surface scan is a much narrower look than a full
  // sysdiagnose; the banner must not read identically to a four-surface
  // scan.
  const narrow = missing.length >= 2
    ? `<p><strong>This was a narrow scan.</strong> Most of this tool's detection surfaces were not present in the archive, so ${pairedOnly
      ? 'none of the four primary artifact types were examined; this result rests only on paired-device crash reports'
      : `this result rests on ${primarySurfacesExamined === 1 ? 'a single primary artifact type' : `only ${primarySurfacesExamined} primary artifact types`}`}. A complete, freshly captured sysdiagnose gives a much stronger result.</p>`
    : '';
  const coverageNote = missing.length
    ? `${narrow}<p><strong>Coverage note:</strong> ${missing.length} of the 4 artifact types this tool reads ${missing.length > 1 ? 'were' : 'was'} not present in this archive (${missing.map((m) => esc(m.kind.replace(/_/g, ' '))).join(', ')}), so ${missing.length > 1 ? 'those surfaces' : 'that surface'} could not be checked. Details are in the table below.</p>`
    : '';
  return `<div class="verdict clear">
    <h2>No known spyware traces found</h2>
    <p>No loaded public indicator matched in the artifacts this tool reads. ${applicable} reviewed process-observable indicators established the limited negative coverage for this process scan${noteCount ? `; ${noteCount} informational note${noteCount > 1 ? 's are' : ' is'} listed below` : ''}.</p>
    ${coverageNote}
    <p><strong>This is not the same as "your phone is clean."</strong> It means: no publicly documented implant left its known traces in these artifacts. Spyware that is new, undocumented, or leaves traces elsewhere would not appear here. If you face real risk, treat this as one data point and consider expert help - <a href="https://www.accessnow.org/help/" target="_blank" rel="noopener noreferrer">Access Now's helpline</a> is free.</p>
  </div>`;
}

// DOM cards for findings are capped: a hostile archive can produce
// thousands, and rendering them all would hang the tab. The exported JSON
// always carries the full list.
const MAX_RENDERED_FINDINGS = 200;
const MAX_RENDERED_ARTIFACTS = 200;

function findingsHtml(report) {
  if (!report.findings.length) return '';
  const cards = report.findings.slice(0, MAX_RENDERED_FINDINGS).map((f, index) => {
    const number = index + 1;
    const headingId = `finding-${number}-heading`;
    const ind = f.indicator
      ? `<div><span class="ind-chip">indicator: <code>${esc(f.indicator.value)}</code></span>
         <span class="ind-chip">campaign: ${esc(f.indicator.campaign)}</span>
         <span class="ind-chip">source: ${esc(f.indicator.set)}</span></div>`
      : '';
    return `<section class="finding" aria-labelledby="${headingId}">
      <h3 class="finding-title" id="${headingId}">Finding ${number}: <span class="sev ${esc(f.severity)}">${esc(f.severity)}</span></h3>
      <p class="artifact">${esc(f.artifact)}</p>
      <p class="summary">${esc(f.summary)}</p>
      ${ind}
      <details><summary>Technical evidence for finding ${number}</summary><pre>${esc(JSON.stringify(f.evidence, null, 2))}</pre></details>
    </section>`;
  }).join('');
  const omitted = report.findings.length - Math.min(report.findings.length, MAX_RENDERED_FINDINGS);
  const more = omitted > 0
    ? `<p class="fine">Showing the first ${MAX_RENDERED_FINDINGS} findings (sorted most severe first); ${omitted} more are in the exported report.</p>`
    : '';
  return `<h2>Findings (${report.findings.length})</h2>${cards}${more}`;
}

function artifactsHtml(report) {
  const artifacts = report.artifacts || [];
  const missing = report.missing_artifacts || [];
  if (!artifacts.length && !missing.length) return '';
  const rows = artifacts.slice(0, MAX_RENDERED_ARTIFACTS).map((a) => {
    const kind = a.kind === 'crash_log'
      && a.details?.paired_device === true
      && isPairedDeviceArtifactPath(a.path)
      ? 'paired-device crash log'
      : a.kind;
    return `
    <tr>
      <td>${esc(kind)}</td>
      <td class="path">${esc(a.path)}</td>
      <td>${esc(a.status)}</td>
      <td>${esc(Object.entries(a.details || {})
        .filter(([, v]) => v !== null)
        .map(([k, v]) => `${k}: ${v}`).join(', '))}</td>
    </tr>`;
  }).join('');
  const missingRows = missing.map((m) => `
    <tr>
      <td>${esc(m.kind)}</td>
      <td class="path">not applicable</td>
      <td>not found</td>
      <td>${esc(m.note)}</td>
    </tr>`).join('');
  const omitted = Math.max(0, artifacts.length - MAX_RENDERED_ARTIFACTS);
  const omissionNote = omitted
    ? `<p class="fine">Showing the first ${MAX_RENDERED_ARTIFACTS} processed artifacts; ${omitted} more remain in the full technical JSON report.</p>`
    : '';
  return `<div class="panel"><h2>What was examined (${artifacts.length} artifacts, ${report.stats.archive_entries} files in archive)</h2>
    <div class="table-scroll" role="region" aria-label="Examined artifacts" tabindex="0"><table class="artifacts"><thead><tr><th>Kind</th><th>Path</th><th>Status</th><th>Details</th></tr></thead>
    <tbody>${rows}${missingRows}</tbody></table></div>${omissionNote}</div>`;
}

function limitsHtml(report) {
  const limits = report.scan_limits || [];
  // The inconclusive verdict already lists the reasons in the banner itself.
  if (!limits.length || verdictOf(report) === 'inconclusive') return '';
  return `<div class="panel"><h2>Scan limits reached</h2>
    <ul>${limits.map((l) => `<li>${esc(l)}</li>`).join('')}</ul>
    <p class="fine">Processing or reporting was limited. Depending on the item, some archive evidence may not have been analyzed or some findings may not have been retained. Do not infer absence from material that was not processed or retained.</p>
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
  const rows = (report.indicator_provenance || []).map((p) => {
    const sourceHref = httpsHref(p.url);
    const source = sourceHref
      ? `<a href="${esc(sourceHref)}" target="_blank" rel="noopener noreferrer" aria-label="Indicator source for ${esc(p.campaign)}">source</a>`
      : '<span>source unavailable</span>';
    return `
    <div class="ioc-row">
      <span><span class="campaign">${esc(p.campaign)}</span>
        <span class="badge bundled">reviewed snapshot · ${esc(p.date)}</span></span>
      <span class="meta">${p.sha256 ? `<code title="SHA-256 of the indicator file used: ${esc(p.sha256)}">sha256:${esc(p.sha256.slice(0, 12))}…</code> · ` : ''}${source}</span>
    </div>`;
  }).join('');
  return `<div class="panel"><h2>Indicators used</h2>${rows}
    <p class="fine">Scans use only reviewed snapshot indicators; the hash identifies the exact revision this scan used and is recorded in the exported report. Public indicators inherit a time lag: new campaigns appear here only after researchers publish them and the snapshots are reviewed. A scan can only be as current as the open ecosystem.</p></div>`;
}

// Add safe line-break opportunities without changing the text a user copies.
// The report schema constrains this to 64 lowercase hex characters, but each
// chunk is still escaped because renderReport is also a browser-test seam.
function breakableHashHtml(hash) {
  const chunks = [];
  for (let i = 0; i < hash.length; i += 8) {
    chunks.push(esc(hash.slice(i, i + 8)));
  }
  return chunks.join('<wbr>');
}

function sourceHashHtml(source) {
  if (typeof source.sha256 !== 'string' || !source.sha256) return '';
  return `<p class="fine" id="source-sha256-row">
    <strong>Archive SHA-256:</strong>
    <code id="source-sha256">${breakableHashHtml(source.sha256)}</code>
    <button type="button" class="linklike" id="copy-source-sha256">Copy hash</button>
    <span id="copy-source-sha256-status" role="status" aria-live="polite"></span><br>
    This identifies the exact archive bytes Trace analyzed.
  </p>`;
}

function exampleNoticeHtml(context) {
  if (context.example !== true) return '';
  return `<aside class="example-note" role="note" aria-label="Example result">
    <p><strong>Example result - no device was scanned.</strong></p>
    <p>This report comes from a synthetic demonstration archive. Use “Scan another file” to analyze your own sysdiagnose.</p>
  </aside>`;
}

function reportActionsHtml() {
  return `<div class="actions report-actions">
    <button class="btn" id="readable-btn">Prepare readable report</button>
    <button class="btn secondary" id="export-btn">Export technical report (JSON - includes identifying metadata)</button>
    <button class="btn secondary" id="rescan-btn">Scan another file</button>
  </div>
  <p class="fine report-export-note"><strong>Readable HTML:</strong> previews privacy redactions before download. <strong>Technical JSON:</strong> includes the source filename, device metadata when present, artifact paths, and raw evidence. Neither export contains the archive itself. Results exist only in this tab until you export them.</p>`;
}

function renderReport(report, context = {}) {
  // The report displayed on screen is the report the export controls own.
  // Keep this binding here so no caller can render A while exporting B.
  state.lastReport = report;
  state.lastReportContext = { example: context.example === true };
  const source = report.source_file || {};
  const sourceName = source.name == null || source.name === ''
    ? 'Unknown source file'
    : source.name;
  const sourceLabel = `${esc(sourceName)} (${fmtBytes(source.size)})`;
  const device = report.device
    ? `<p class="fine source-meta">Device: ${esc(report.device.os_version)} (from ${esc(report.device.source)}) · file: ${sourceLabel}</p>`
    : `<p class="fine source-meta">File: ${sourceLabel}</p>`;
  const sourceHash = sourceHashHtml(source);
  $('#results').innerHTML =
    exampleNoticeHtml(state.lastReportContext) +
    verdictHtml(report) +
    device +
    sourceHash +
    reportActionsHtml() +
    findingsHtml(report) +
    limitsHtml(report) +
    artifactsHtml(report) +
    coverageHtml(report) +
    provenanceHtml(report);
  const copyHash = $('#copy-source-sha256');
  if (copyHash) {
    copyHash.addEventListener('click', async () => {
      const status = $('#copy-source-sha256-status');
      try {
        await navigator.clipboard.writeText(source.sha256);
        status.textContent = ' Hash copied.';
      } catch {
        status.textContent = ' Could not copy; select the hash above.';
      }
    });
  }
  $('#readable-btn').addEventListener('click', openReadableDialog);
  $('#export-btn').addEventListener('click', exportReport);
  $('#rescan-btn').addEventListener('click', backToLanding);
  showSection('results');
  // Announce the outcome by focusing the verdict heading itself. Focusing the
  // unnamed results container does not reliably read its contents in NVDA/JAWS,
  // so the tool's most important output could go unspoken; a focused heading is
  // read out. Every known verdict renders exactly one .verdict > h2.
  const verdictHeading = $('#results .verdict h2');
  if (verdictHeading) {
    verdictHeading.setAttribute('tabindex', '-1');
    verdictHeading.focus();
  } else {
    $('#results').focus();
  }
}

function renderError(err) {
  state.lastReport = null;
  state.lastReportContext = null;
  $('#results').innerHTML = `<div class="error-box" role="alert">
    <h2 id="scan-error-heading" tabindex="-1">Couldn't scan that file</h2>
    <p>${esc(err?.message || err)}</p>
    <p>Make sure you're choosing the original <code>sysdiagnose_….tar.gz</code> file, not an unpacked folder or a renamed copy. Nothing was uploaded; you can simply try again.</p>
  </div>
  <div class="actions"><button class="btn secondary" id="rescan-btn">Back</button></div>`;
  $('#rescan-btn').addEventListener('click', backToLanding);
  showSection('results');
  // Same focus treatment as a successful scan, so screen readers announce
  // the failure instead of leaving focus stranded on <body>.
  $('#scan-error-heading').focus();
}

let exportSequence = 0;

function exportToken() {
  const timestamp = new Date().toISOString()
    .replace(/[-:]/g, '')
    .replace(/\.\d{3}Z$/, 'Z');
  let nonce;
  if (typeof globalThis.crypto?.randomUUID === 'function') {
    nonce = globalThis.crypto.randomUUID().slice(0, 8);
  } else if (typeof globalThis.crypto?.getRandomValues === 'function') {
    const value = new Uint32Array(1);
    globalThis.crypto.getRandomValues(value);
    nonce = value[0].toString(16).padStart(8, '0');
  } else {
    nonce = (++exportSequence).toString(36).padStart(4, '0');
  }
  return `${timestamp}-${nonce}`;
}

function reportFilename(kind, extension, context) {
  const example = context?.example === true ? 'example-' : '';
  return `trace-${example}${kind}-${exportToken()}.${extension}`;
}

function exportReport() {
  if (!state.lastReport) return;
  const blob = new Blob([JSON.stringify(state.lastReport, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = reportFilename('technical-report', 'json', state.lastReportContext);
  a.click();
  // Revoking synchronously can cancel the download in some browsers.
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

function readableOptions() {
  return {
    includeSourceName: $('#readable-source-name').checked,
    includeDevice: $('#readable-device').checked,
    includeTechnical: $('#readable-technical').checked,
    example: state.readableContext?.example === true,
  };
}

function updateReadablePreview() {
  if (!state.readableReport) return;
  const options = readableOptions();
  $('#readable-preview').innerHTML = readableReportFragment(
    state.readableReport,
    options
  );
  const included = [];
  if (options.includeSourceName) included.push('source filename');
  if (options.includeDevice) included.push('device metadata');
  if (options.includeTechnical) included.push('technical evidence and artifact fields');
  $('#readable-options-status').textContent = included.length
    ? `Preview updated. Included: ${included.join(', ')}.`
    : 'Preview updated. Identifying metadata and technical evidence remain redacted.';
}

function openReadableDialog() {
  if (!state.lastReport) return;
  // Bind the preview and every later download action to this exact report.
  // A new scan replaces state.lastReport; it must never change what an open
  // handoff dialog exports underneath the person reviewing it.
  state.readableReport = state.lastReport;
  state.readableContext = { example: state.lastReportContext?.example === true };
  for (const id of ['readable-source-name', 'readable-device', 'readable-technical']) {
    $('#' + id).checked = false;
  }
  updateReadablePreview();
  const dialog = $('#readable-dialog');
  if (!dialog.open) dialog.showModal();
}

function downloadReadableReport() {
  if (!state.readableReport) return;
  const documentText = readableReportDocument(state.readableReport, readableOptions());
  const blob = new Blob([documentText], { type: 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = reportFilename('readable-report', 'html', state.readableContext);
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/* ---------- wiring ---------- */

function wireUi() {
  const dz = $('#dropzone');
  const input = $('#file-input');

  dz.addEventListener('click', (e) => {
    if (dz.getAttribute('aria-disabled') !== 'true' && e.target.tagName !== 'LABEL') {
      input.click();
    }
  });
  dz.addEventListener('keydown', (e) => {
    if ((e.key === 'Enter' || e.key === ' ')
        && dz.getAttribute('aria-disabled') !== 'true') {
      e.preventDefault();
      input.click();
    }
  });
  // The dropzone only handles its highlight; the actual drop (anywhere on
  // the page) is handled once, at the document level below.
  dz.addEventListener('dragover', () => dz.classList.add('dragover'));
  dz.addEventListener('dragleave', () => dz.classList.remove('dragover'));
  dz.addEventListener('drop', () => dz.classList.remove('dragover'));
  input.addEventListener('change', () => {
    if (input.files?.[0] && state.indicatorsReady && !state.scanning) {
      handleFile(input.files[0]);
    }
    input.value = '';
  });

  // A file dropped outside the dropzone must never navigate the tab away
  // (the browser default), which would silently destroy the session. Any
  // drop on the page is treated as intent to scan.
  document.addEventListener('dragover', (e) => e.preventDefault());
  document.addEventListener('drop', (e) => {
    e.preventDefault();
    const file = e.dataTransfer?.files?.[0];
    // Native dialogs make the page inert, but a bubbled drop still reaches
    // this document listener. Ignore it: starting a hidden background scan
    // beneath a report preview can bind the person's handoff to the wrong file.
    if (file && state.indicatorsReady && !state.scanning && !state.waitingWorker
        && $('#scanning').hidden && !$('dialog[open]')) {
      handleFile(file);
    }
  });

  const dialog = $('#prove-dialog');
  $('#prove-it').addEventListener('click', () => dialog.showModal());
  dialog.addEventListener('click', (e) => {
    if (e.target === dialog) dialog.close();
  });

  const readableDialog = $('#readable-dialog');
  $('#readable-options').addEventListener('change', updateReadablePreview);
  $('#download-readable').addEventListener('click', downloadReadableReport);
  $('#close-readable').addEventListener('click', () => readableDialog.close());
  $('#cancel-scan').addEventListener('click', cancelCurrentScan);
  // Close only through Cancel or Escape. Treating any click on dialog padding
  // as a backdrop click loses redaction choices and preview position.
  readableDialog.addEventListener('close', () => {
    state.readableReport = null;
    state.readableContext = null;
    $('#readable-options-status').textContent = '';
    $('#readable-preview').replaceChildren();
  });

  // Loading a demonstration and scanning a real file are separate intents.
  // A delayed demo response must never replace a later real-file result.
  const demo = (path, name) => async () => {
    if (!state.indicatorsReady || state.scanning || state.demoLoading || state.waitingWorker) return;
    const intent = ++state.scanIntent;
    state.demoLoading = true;
    setScannerStatus('preparing', 'Loading the synthetic example archive…');
    try {
      const r = await fetch(path);
      if (!r.ok) throw new Error(`the demo file could not be loaded (HTTP ${r.status})`);
      const blob = await r.blob();
      if (intent !== state.scanIntent) return;
      await handleFile(new File([blob], name), { example: true }, intent);
    } catch (err) {
      if (intent === state.scanIntent) {
        state.demoLoading = false;
        updateLandingControls();
        renderError(err);
      }
    } finally {
      if (intent === state.scanIntent && state.demoLoading) {
        state.demoLoading = false;
        updateLandingControls();
        if (!$('#landing').hidden) {
          setScannerStatus(
            'ready',
            'Scanner ready. Bundled, reviewed indicators passed their integrity checks.'
          );
        }
      }
    }
  };
  $('#demo-clean').addEventListener('click',
    demo('./fixtures/sysdiagnose_demo_clean.tar.gz', 'sysdiagnose_demo_clean.tar.gz'));
  $('#demo-infected').addEventListener('click',
    demo('./fixtures/sysdiagnose_demo_infected.tar.gz', 'sysdiagnose_demo_infected.tar.gz'));

  window.addEventListener('online', () => {
    setOnlineState();
    requestServiceWorkerUpdate();
  });
  window.addEventListener('offline', setOnlineState);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') requestServiceWorkerUpdate();
  });
  setOnlineState();
}

async function boot() {
  wireUi();
  initWorker();
  setScannerStatus('preparing', 'Preparing scanner… Loading and validating the bundled, reviewed indicators.');
  // Register cache support independently of scan readiness. navigator.onLine
  // and successful scanner initialization do not prove that a reload can work
  // offline; only a ready service worker establishes that separate state.
  if ('serviceWorker' in navigator) {
    // ready resolves immediately for an existing active registration, even if
    // register() is still performing a network update check. Inspect that
    // registration first so an already-waiting release can never leave a brief
    // window in which stale scan controls become enabled.
    navigator.serviceWorker.ready
      .then((registration) => {
        observeServiceWorkerRegistration(registration);
        state.cacheReady = true;
        setOnlineState();
      })
      .catch(() => { /* cache readiness is useful but non-fatal */ });
    navigator.serviceWorker.register('./sw.js', { updateViaCache: 'none' })
      .then((registration) => {
        observeServiceWorkerRegistration(registration);
      })
      .catch(() => { /* cache readiness is useful but non-fatal */ });
  }
  state.ready = (async () => {
    await init();
    await loadBundledIndicators();
    // Validate every reviewed floor in a short-lived scanner. Actual scans
    // get their own instance, avoiding a duplicate pre-warmed WASM scanner.
    const validationScanner = newScanner();
    validationScanner.free();
    state.indicatorsReady = true;
    renderIocPanel();
    setScannerStatus(
      'ready',
      'Scanner ready. Bundled, reviewed indicators passed their integrity checks.'
    );
    // Optional public-feed freshness is advisory and may time out. It never
    // delays or disables scanning with the reviewed snapshots.
    state.freshnessReady = refreshIndicatorFreshness().catch(() => {
      renderIocPanel();
    });
  })();
  try {
    await state.ready;
  } catch (err) {
    state.indicatorsReady = false;
    const message = err?.message || String(err);
    setScannerStatus(
      'error',
      `Scanner unavailable. ${message} Reload the page to try again.`
    );
    $('#ioc-list').replaceChildren();
    $('#ioc-note').textContent =
      `The scanner failed to start (${message}). Reload the page to try again; scanning is unavailable until this succeeds.`;
    $('#ioc-panel').hidden = false;
  }
}

// Exposed for end-to-end tests; handleFile is the same path the UI uses.
window.__trace = {
  handleFile,
  get lastReport() { return state.lastReport; },
  get lastScanVia() { return state.lastScanVia; },
  get ready() { return state.indicatorsReady; },
  get freshnessReady() { return state.freshnessReady; },
  get cacheReady() { return state.cacheReady; },
  get updateReady() { return Boolean(state.waitingWorker); },
  renderReport,
  // For producer-parity tests: forces the inline path, exactly what a
  // browser without worker support gets.
  disableWorker() {
    worker?.terminate();
    worker = null;
    workerState = 'unavailable';
    workerReady = Promise.resolve(false);
    workerRequiredForRetry = false;
  },
};

boot();
