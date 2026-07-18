import init, { Scanner } from './pkg/trace_core.js';
import { readableReportDocument, readableReportFragment } from './readable-report.js';

const $ = (sel) => document.querySelector(sel);

const state = {
  stix: [],          // { name, source, url, text, loaded_from, date, stats }
  scanner: null,     // pre-warmed Scanner with indicators loaded
  ready: null,       // resolves once WASM + indicators are loaded
  lastReport: null,
  readableReport: null, // report snapshot currently owned by the readable-export dialog
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
  // Results can contain sensitive case metadata. Once the person leaves the
  // result view, do not retain an exportable report behind the landing page.
  state.lastReport = null;
  $('#results').replaceChildren();
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
      return meetsReviewedFloor(set, stats);
    } finally {
      probe.free();
    }
  } catch {
    return false;
  }
}

function meetsReviewedFloor(set, stats) {
  return Number.isSafeInteger(set.min_indicators)
    && set.min_indicators >= 0
    && Number.isSafeInteger(set.min_applicable)
    && set.min_applicable >= 0
    && Number.isSafeInteger(stats?.extracted)
    && stats.extracted >= set.min_indicators
    && Number.isSafeInteger(stats?.applicable)
    && stats.applicable >= set.min_applicable;
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
  try {
    for (const set of state.stix) {
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
const WORKER_SCAN_INACTIVITY_TIMEOUT_MS = Number.isSafeInteger(
  globalThis.__TRACE_TEST_WORKER_TIMEOUT_MS
) && globalThis.__TRACE_TEST_WORKER_TIMEOUT_MS > 0
  ? globalThis.__TRACE_TEST_WORKER_TIMEOUT_MS
  : 45_000;
const WORKER_SCAN_FAILURE =
  'The background scanner stopped while reading this file. Trace did not retry it on the main page because doing so could freeze or crash the tab. Keep the original file, reload this page, and contact a digital security helpline if the problem repeats.';

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isNonnegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function hasExactKeys(value, required, optional = []) {
  if (!isRecord(value)) return false;
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(value, key))
    && Object.keys(value).every((key) => allowed.has(key));
}

function isNullableString(value) {
  return value === null || typeof value === 'string';
}

function sameIntegerMap(actual, expected) {
  if (!isRecord(actual) || !isRecord(expected)) return false;
  const actualKeys = Object.keys(actual);
  const expectedKeys = Object.keys(expected);
  return actualKeys.length === expectedKeys.length
    && actualKeys.every((key) => (
      Object.hasOwn(expected, key)
      && isNonnegativeInteger(actual[key])
      && actual[key] === expected[key]
    ));
}

function isPairedDeviceArtifactPath(path) {
  if (typeof path !== 'string') return false;
  const normalized = path.startsWith('./') ? path.slice(2) : path;
  if (!normalized || normalized.startsWith('/')) return false;
  const components = normalized.split('/');
  if (components.some((component) => (
    !component || component === '.' || component === '..'
  ))) return false;
  return components.some((component, index) => {
    if (index === 0 || components[index - 1] !== 'logs') return false;
    return component === 'ProxiedDevice'
      || (component.startsWith('ProxiedDevice-')
        && component.length > 'ProxiedDevice-'.length);
  });
}

// A worker success message crosses a separate JS/WASM execution boundary.
// Validate the report envelope and its loaded-set provenance before allowing
// any verdict (especially `clear`) onto the page. This checks transport and
// producer integrity; verdict semantics remain owned by Rust.
function isCompleteReportEnvelope(report, file, expectedVia) {
  const topLevelKeys = [
    'schema_version', 'tool', 'verdict', 'generated_at', 'duration_ms',
    'scanned_via', 'source_file', 'indicator_sets', 'indicator_provenance',
    'artifacts', 'missing_artifacts', 'findings', 'stats', 'scan_limits',
    'assurance', 'coverage',
  ];
  if (!hasExactKeys(report, topLevelKeys, ['device'])
      || report.schema_version !== 3
      || !hasExactKeys(report.tool, ['name', 'version', 'build_commit'])
      || report.tool.name !== 'Trace'
      || typeof report.tool.version !== 'string'
      || !(report.tool.build_commit === null
        || (typeof report.tool.build_commit === 'string'
          && /^[0-9a-f]{40}$/.test(report.tool.build_commit)))
      || typeof report.verdict !== 'string'
      || !isNullableString(report.generated_at)
      || !(report.duration_ms === null || isNonnegativeInteger(report.duration_ms))
      || report.scanned_via !== expectedVia
      || !hasExactKeys(report.source_file, ['name', 'size', 'sha256'])
      || report.source_file.name !== file.name
      || report.source_file.size !== file.size
      || typeof report.source_file.sha256 !== 'string'
      || !/^[0-9a-f]{64}$/.test(report.source_file.sha256)
      || !Array.isArray(report.indicator_sets)
      || !Array.isArray(report.indicator_provenance)
      || !Array.isArray(report.artifacts)
      || !Array.isArray(report.missing_artifacts)
      || !Array.isArray(report.findings)
      || !Array.isArray(report.scan_limits)
      || !hasExactKeys(report.stats, [
        'bytes_read', 'archive_entries', 'artifacts_found',
        'total_indicators', 'applicable_indicators',
      ])
      || !hasExactKeys(report.assurance, [
        'complete', 'surfaces', 'surfaces_examined', 'surfaces_total',
      ])
      || !hasExactKeys(report.coverage, ['examined', 'not_examined', 'note'])
      || !Array.isArray(report.assurance.surfaces)
      || !Array.isArray(report.coverage.examined)
      || !Array.isArray(report.coverage.not_examined)
      || !report.coverage.examined.every((item) => typeof item === 'string')
      || !report.coverage.not_examined.every((item) => typeof item === 'string')
      || typeof report.coverage.note !== 'string'
      || (Object.hasOwn(report, 'device')
        && (!hasExactKeys(report.device, ['os_version', 'source'], ['timestamp'])
          || typeof report.device.os_version !== 'string'
          || typeof report.device.source !== 'string'
          || (Object.hasOwn(report.device, 'timestamp')
            && typeof report.device.timestamp !== 'string')))) {
    return false;
  }
  if (!report.scan_limits.every((limit) => typeof limit === 'string')) return false;

  const expectedStats = new Map(state.stix.map((set) => [set.name, set.stats]));
  const expectedTotal = state.stix.reduce((total, set) => total + set.stats.extracted, 0);
  const expectedApplicable = state.stix.reduce(
    (total, set) => total + set.stats.applicable,
    0
  );
  if (report.indicator_sets.length !== expectedStats.size
      || report.stats.total_indicators !== expectedTotal
      || report.stats.applicable_indicators !== expectedApplicable
      || report.stats.bytes_read !== file.size
      || !isNonnegativeInteger(report.stats.archive_entries)
      || !isNonnegativeInteger(report.stats.artifacts_found)) {
    return false;
  }
  const reportedSetNames = new Set();
  for (const set of report.indicator_sets) {
    const expected = isRecord(set) ? expectedStats.get(set.name) : null;
    if (!hasExactKeys(set, [
      'name', 'campaign', 'stix_indicators', 'extracted', 'by_kind', 'applicable',
    ])
        || !expected
        || reportedSetNames.has(set.name)
        || set.campaign !== expected.campaign
        || set.stix_indicators !== expected.stix_indicators
        || set.extracted !== expected.extracted
        || set.applicable !== expected.applicable
        || !sameIntegerMap(set.by_kind, expected.by_kind)) {
      return false;
    }
    reportedSetNames.add(set.name);
  }

  if (report.indicator_provenance.length !== state.stix.length) return false;
  const provenanceNames = new Set();
  for (const provenance of report.indicator_provenance) {
    const bundled = isRecord(provenance)
      ? state.stix.find((set) => set.name === provenance.name)
      : null;
    if (!hasExactKeys(provenance, [
      'name', 'campaign', 'sha256', 'loaded_from', 'date', 'url', 'source', 'upstream',
    ])
        || !bundled
        || provenanceNames.has(provenance.name)
        || provenance.loaded_from !== 'bundled'
        || !isNullableString(provenance.date)
        || !isNullableString(provenance.url)
        || !isNullableString(provenance.source)
        || !['current', 'update-available', 'unknown', null].includes(provenance.upstream)
        || typeof provenance.sha256 !== 'string'
        || !/^[0-9a-f]{64}$/.test(provenance.sha256)
        || (bundled.sha256 !== null && provenance.sha256 !== bundled.sha256)
        || provenance.campaign !== bundled.stats.campaign
        || provenance.date !== bundled.meta.date
        || provenance.url !== bundled.meta.url
        || provenance.source !== bundled.meta.source
        || provenance.upstream !== bundled.meta.upstream) {
      return false;
    }
    provenanceNames.add(provenance.name);
  }

  const primaryArtifactKinds = new Set();
  for (const artifact of report.artifacts) {
    if (!hasExactKeys(artifact, ['path', 'kind', 'status', 'details'])
        || typeof artifact.path !== 'string'
        || artifact.path.length === 0
        || !['shutdown_log', 'crash_log', 'ps_listing', 'unified_log'].includes(artifact.kind)
        || !['parsed', 'parsed_partial', 'unparsed', 'truncated'].includes(artifact.status)
        || !isRecord(artifact.details)) {
      return false;
    }
    const paired = artifact.kind === 'crash_log'
      && isPairedDeviceArtifactPath(artifact.path);
    if (artifact.kind === 'crash_log'
        && (typeof artifact.details.paired_device !== 'boolean'
          || artifact.details.paired_device !== paired)) {
      return false;
    }
    if (!paired) primaryArtifactKinds.add(artifact.kind);
  }
  const retainedArtifactCount = report.artifacts.filter(
    (artifact) => artifact.kind !== 'unified_log'
  ).length;
  if (report.stats.artifacts_found !== retainedArtifactCount) return false;
  const artifactPaths = new Set(report.artifacts.map((artifact) => artifact.path));

  const phoneMetadataArtifacts = report.artifacts.filter((artifact) => (
    artifact.kind === 'crash_log'
    && artifact.details.paired_device === false
    && typeof artifact.details.os_version === 'string'
  ));
  if (Object.hasOwn(report, 'device')) {
    const source = phoneMetadataArtifacts.find(
      (artifact) => artifact.path === report.device.source
    );
    const timestampMatches = source && (Object.hasOwn(report.device, 'timestamp')
      ? source.details.timestamp === report.device.timestamp
      : source.details.timestamp === null);
    if (!source
        || source.details.os_version !== report.device.os_version
        || !timestampMatches) {
      return false;
    }
  } else if (phoneMetadataArtifacts.length > 0) {
    return false;
  }

  for (const finding of report.findings) {
    const hasIndicator = isRecord(finding) && Object.hasOwn(finding, 'indicator');
    if (!hasExactKeys(
      finding,
      ['severity', 'kind', 'artifact', 'summary', 'evidence'],
      ['indicator']
    )
        || !['note', 'suspicious', 'match'].includes(finding.severity)
        || typeof finding.kind !== 'string'
        || typeof finding.artifact !== 'string'
        || !artifactPaths.has(finding.artifact)
        || typeof finding.summary !== 'string'
        || hasIndicator !== (finding.severity === 'match')
        || finding.kind !== (hasIndicator ? 'ioc_match' : 'heuristic')
        || (hasIndicator
          && (!hasExactKeys(finding.indicator, ['value', 'kind', 'set', 'campaign'])
            || !Object.values(finding.indicator).every(
              (value) => typeof value === 'string'
            )
            || finding.indicator.value.length === 0
            || !['process_name', 'file_name', 'file_path'].includes(
              finding.indicator.kind
            )
            || !expectedStats.has(finding.indicator.set)
            || finding.indicator.campaign
              !== expectedStats.get(finding.indicator.set)?.campaign))) {
      return false;
    }
  }

  const surfaceKinds = new Set();
  for (const surface of report.assurance.surfaces) {
    if (!hasExactKeys(surface, ['kind', 'state'])
        || !['shutdown_log', 'crash_log', 'ps_listing', 'unified_log'].includes(surface.kind)
        || !['complete', 'partial', 'absent'].includes(surface.state)
        || surfaceKinds.has(surface.kind)) {
      return false;
    }
    surfaceKinds.add(surface.kind);
  }
  if (report.assurance.surfaces_total !== 4
      || surfaceKinds.size !== 4
      || !isNonnegativeInteger(report.assurance.surfaces_examined)
      || report.assurance.surfaces_examined > 4
      || typeof report.assurance.complete !== 'boolean') {
    return false;
  }

  const absentSurfaceKinds = new Set(
    report.assurance.surfaces
      .filter((surface) => surface.state === 'absent')
      .map((surface) => surface.kind)
  );
  if ([...primaryArtifactKinds].some((kind) => absentSurfaceKinds.has(kind))) {
    return false;
  }
  const surfaceStates = new Map(
    report.assurance.surfaces.map((surface) => [surface.kind, surface.state])
  );
  const completeSurfaceKinds = new Set(
    report.assurance.surfaces
      .filter((surface) => surface.state === 'complete')
      .map((surface) => surface.kind)
  );
  if ([...completeSurfaceKinds].some((kind) => !primaryArtifactKinds.has(kind))
      || report.assurance.surfaces_examined < completeSurfaceKinds.size
      || report.assurance.surfaces_examined > 4 - absentSurfaceKinds.size) {
    return false;
  }
  if (report.artifacts.some((artifact) => {
    const paired = artifact.kind === 'crash_log'
      && artifact.details.paired_device === true;
    return !paired
      && artifact.status !== 'parsed'
      && surfaceStates.get(artifact.kind) === 'complete';
  })) {
    return false;
  }
  const missingKinds = new Set();
  for (const missing of report.missing_artifacts) {
    if (!hasExactKeys(missing, ['kind', 'note'])
        || !absentSurfaceKinds.has(missing.kind)
        || missingKinds.has(missing.kind)
        || typeof missing.note !== 'string') {
      return false;
    }
    missingKinds.add(missing.kind);
  }
  if (missingKinds.size !== absentSurfaceKinds.size) return false;

  const hasPartialProcessing = report.artifacts.some(
    (artifact) => artifact.status !== 'parsed'
  ) || report.assurance.surfaces.some((surface) => surface.state === 'partial');
  if (hasPartialProcessing && report.scan_limits.length === 0) return false;

  const expectedVerdict = report.findings.some((finding) => finding.severity === 'match')
    ? 'match'
    : report.findings.some((finding) => finding.severity === 'suspicious')
      ? 'suspicious'
      : report.scan_limits.length > 0
        ? 'inconclusive'
        : report.artifacts.length === 0
          ? 'invalid'
          : 'clear';
  const expectedComplete = report.scan_limits.length === 0 && expectedVerdict !== 'invalid';
  if (report.verdict !== expectedVerdict
      || report.assurance.complete !== expectedComplete) {
    return false;
  }

  if (report.verdict === 'clear'
      && (!report.assurance.complete
        || report.scan_limits.length !== 0
        || report.assurance.surfaces.some((surface) => surface.state === 'partial')
        || report.assurance.surfaces_examined !== 4 - absentSurfaceKinds.size
        || report.artifacts.length === 0
        || report.artifacts.some((artifact) => artifact.status !== 'parsed')
        || report.findings.some((finding) => finding.severity !== 'note')
        || primaryArtifactKinds.size !== 4 - absentSurfaceKinds.size
        || [...primaryArtifactKinds].some((kind) => absentSurfaceKinds.has(kind)))) {
    return false;
  }
  return true;
}

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
  worker = null;
  try {
    expected.terminate();
  } catch {
    /* already gone */
  }
  initWorker();
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
    let inactivityTimeout;
    const restoreReady = () => {
      if (worker === w && workerState === 'scanning') workerState = 'ready';
    };
    const failClosed = () => {
      cleanup();
      recycleWorker(w);
      reject(new Error(WORKER_SCAN_FAILURE));
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
        updateProgress(m.processed, file.size);
      } else if (m.type === 'report') {
        cleanup();
        if (!isCompleteReportEnvelope(m.report, file, 'worker')) {
          // A malformed success message is not permission to replay a
          // potentially hostile archive on the main thread. Treat the worker
          // as unreliable, replace it, and keep this scan failed closed.
          recycleWorker(w);
          reject(new Error(WORKER_SCAN_FAILURE));
          return;
        }
        restoreReady();
        resolve(m.report);
      } else if (m.type === 'error') {
        cleanup();
        // A scan error may be a clean rejection (not an archive) or a WASM
        // trap that left the instance's memory in an undefined state - and
        // the two are indistinguishable from here. Reusing a trapped
        // instance for the next scan could silently corrupt its result, so
        // the worker is discarded and a fresh one spun up. Fail closed.
        recycleWorker(w);
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
    const onMessageError = () => failClosed();
    const cleanup = () => {
      w.removeEventListener('message', onMsg);
      w.removeEventListener('error', onErr);
      w.removeEventListener('messageerror', onMessageError);
      clearTimeout(inactivityTimeout);
    };
    w.addEventListener('message', onMsg);
    w.addEventListener('error', onErr);
    w.addEventListener('messageerror', onMessageError);
    workerState = 'scanning';
    try {
      w.postMessage({
        type: 'scan',
        id,
        file,
        sets: state.stix.map((s) => ({
          name: s.name,
          text: s.text,
          meta: s.meta,
          min_indicators: s.min_indicators,
          min_applicable: s.min_applicable,
        })),
      });
      armInactivityTimeout();
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
    const report = JSON.parse(scanner.finish());
    if (!isCompleteReportEnvelope(report, file, 'inline')) {
      throw new Error('The scanner returned an incomplete report. No verdict was shown.');
    }
    return report;
  } finally {
    try { scanner.free(); } catch { /* already released */ }
    try { state.scanner = newScanner(); } catch { /* keep last error visible */ }
  }
}

async function handleFile(file) {
  // One scan at a time: a second file racing the first (double-clicked
  // demo button, scripted calls) must not interleave results.
  if (state.scanning) return;
  state.scanning = true;
  // A modal preview must never remain visible over a different scan. Its
  // close handler also releases the report snapshot owned by that dialog.
  const readableDialog = $('#readable-dialog');
  if (readableDialog?.open) readableDialog.close();
  // The previous report no longer owns the results screen once a new scan
  // starts. Clearing it prevents an error from leaving stale provenance in
  // state even though no report is being shown.
  state.lastReport = null;
  // Results may contain sensitive case data and event listeners that close
  // over it. Remove the old tree immediately rather than retaining it, hidden,
  // for the duration of a new scan.
  $('#results').replaceChildren();
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
    } else {
      state.lastScanVia = 'inline';
      report = await scanInline(file);
    }
    // Schema v3: the report arrives complete from Rust - no fields are
    // appended here. What the UI renders is exactly what exports.
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
// A report without a verdict we recognize is from an unknown or newer
// source; treat it as inconclusive, never clear. Only 'clear' earns the
// reassuring banner, and only by exact match.
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
  const rows = report.artifacts.map((a) => {
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
  const missingRows = (report.missing_artifacts || []).map((m) => `
    <tr>
      <td>${esc(m.kind)}</td>
      <td class="path">–</td>
      <td>not found</td>
      <td>${esc(m.note)}</td>
    </tr>`).join('');
  return `<div class="panel"><h2>What was examined (${report.artifacts.length} artifacts, ${report.stats.archive_entries} files in archive)</h2>
    <div class="table-scroll" role="region" aria-label="Examined artifacts" tabindex="0"><table class="artifacts"><thead><tr><th>Kind</th><th>Path</th><th>Status</th><th>Details</th></tr></thead>
    <tbody>${rows}${missingRows}</tbody></table></div></div>`;
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
  const rows = (report.indicator_provenance || []).map((p) => `
    <div class="ioc-row">
      <span><span class="campaign">${esc(p.campaign)}</span>
        <span class="badge bundled">reviewed snapshot · ${esc(p.date)}</span></span>
      <span class="meta">${p.sha256 ? `<code title="SHA-256 of the indicator file used: ${esc(p.sha256)}">sha256:${esc(p.sha256.slice(0, 12))}…</code> · ` : ''}<a href="${esc(p.url)}" target="_blank" rel="noopener noreferrer">source</a></span>
    </div>`).join('');
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

function renderReport(report) {
  // The report displayed on screen is the report the export controls own.
  // Keep this binding here so no caller can render A while exporting B.
  state.lastReport = report;
  const source = report.source_file || {};
  const sourceName = source.name == null || source.name === ''
    ? 'Unknown source file'
    : source.name;
  const sourceLabel = `${esc(sourceName)} (${fmtBytes(source.size)})`;
  const device = report.device
    ? `<p class="fine">Device: ${esc(report.device.os_version)} (from ${esc(report.device.source)}) · file: ${sourceLabel}</p>`
    : `<p class="fine">File: ${sourceLabel}</p>`;
  const sourceHash = sourceHashHtml(source);
  $('#results').innerHTML =
    verdictHtml(report) +
    device +
    sourceHash +
    findingsHtml(report) +
    limitsHtml(report) +
    artifactsHtml(report) +
    coverageHtml(report) +
    provenanceHtml(report) +
    `<div class="actions">
      <button class="btn" id="readable-btn">Prepare readable report</button>
      <button class="btn secondary" id="export-btn">Export technical report (JSON)</button>
      <button class="btn secondary" id="rescan-btn">Scan another file</button>
    </div>
    <p class="fine">The readable HTML export previews privacy redactions before download. The JSON report preserves the complete technical record. Neither contains the archive itself.</p>`;
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
  // Move focus to the verdict so screen readers announce the outcome.
  $('#results').focus();
}

function renderError(err) {
  state.lastReport = null;
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

function readableOptions() {
  return {
    includeSourceName: $('#readable-source-name').checked,
    includeDevice: $('#readable-device').checked,
    includeTechnical: $('#readable-technical').checked,
  };
}

function updateReadablePreview() {
  if (!state.readableReport) return;
  $('#readable-preview').innerHTML = readableReportFragment(
    state.readableReport,
    readableOptions()
  );
}

function openReadableDialog() {
  if (!state.lastReport) return;
  // Bind the preview and every later download action to this exact report.
  // A new scan replaces state.lastReport; it must never change what an open
  // handoff dialog exports underneath the person reviewing it.
  state.readableReport = state.lastReport;
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
  a.download = `trace-readable-report-${new Date().toISOString().slice(0, 10)}.html`;
  a.click();
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
    // Native dialogs make the page inert, but a bubbled drop still reaches
    // this document listener. Ignore it: starting a hidden background scan
    // beneath a report preview can bind the person's handoff to the wrong file.
    if (file && $('#scanning').hidden && !$('dialog[open]')) handleFile(file);
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
  // Close only through Cancel or Escape. Treating any click on dialog padding
  // as a backdrop click loses redaction choices and preview position.
  readableDialog.addEventListener('close', () => {
    state.readableReport = null;
    $('#readable-preview').replaceChildren();
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
      ? 'You are offline, and scanning still works. This demonstrates that the loaded app has no scan-time server dependency; it does not authenticate code already loaded.'
      : 'Analysis is designed to run entirely in this browser tab. Trace has no upload endpoint, and its intended code sends no archive bytes.';
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
