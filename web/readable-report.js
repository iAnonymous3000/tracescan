const MAX_READABLE_FINDINGS = 200;
const MAX_READABLE_ARTIFACTS = 200;

const VERDICTS = {
  match: {
    label: 'Traces matching known spyware were found',
    meaning: 'One or more process-bearing entries matched a published indicator. Trace compares exact process names and full paths; a file-name indicator may also match an observed process basename, and a directory path ending in / may match a canonical descendant. This is a serious signal that needs expert review, but it is not final proof on its own.',
  },
  suspicious: {
    label: 'Anomalies worth expert review',
    meaning: 'No published indicator matched in the parts Trace examined, but Trace found patterns associated with published spyware research. These patterns can have benign causes.',
  },
  clear: {
    label: 'No known spyware traces found',
    meaning: 'No applicable public indicator appeared in the artifacts Trace examined. This is not a clean bill of health and does not rule out new, private, or uncovered spyware traces.',
  },
  inconclusive: {
    label: 'Scan incomplete - result inconclusive',
    meaning: 'Trace could not fully analyze the archive, so absence of a match is not meaningful for the parts it could not examine.',
  },
  invalid: {
    label: 'Input was not recognized as a sysdiagnose',
    meaning: 'Trace did not find the expected sysdiagnose artifacts. This report does not support a device-security conclusion.',
  },
};

// Single-sourced HTML escaper, imported by main.js too: an escaping helper on
// the XSS surface is worth exactly one definition.
export function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[char]));
}

function fmtBytes(value) {
  if (!Number.isFinite(value) || value < 0) return 'unavailable';
  if (value >= 2 ** 30) return `${(value / 2 ** 30).toFixed(2)} GB`;
  if (value >= 2 ** 20) return `${(value / 2 ** 20).toFixed(1)} MB`;
  if (value >= 2 ** 10) return `${(value / 2 ** 10).toFixed(0)} KB`;
  return `${value} B`;
}

function normalizedOptions(options) {
  return {
    includeSourceName: options?.includeSourceName === true,
    includeDevice: options?.includeDevice === true,
    includeTechnical: options?.includeTechnical === true,
    example: options?.example === true,
  };
}

function list(items, emptyText) {
  if (!Array.isArray(items) || items.length === 0) {
    return `<p class="empty">${esc(emptyText)}</p>`;
  }
  return `<ul>${items.map((item) => `<li>${esc(item)}</li>`).join('')}</ul>`;
}

// The exact OS build and capture timestamp identify the device, and they also
// travel inside crash artifact `details` and finding `evidence`. When the
// reader withholds device metadata, strip those keys wherever they surface -
// otherwise enabling the separate technical toggle would silently re-expose
// what the "Device metadata redacted" notice promised to hide.
const DEVICE_KEYS = ['os_version', 'timestamp'];
function withoutDeviceKeys(value, includeDevice) {
  if (includeDevice || value === null || typeof value !== 'object') return value;
  const clone = Array.isArray(value) ? [...value] : { ...value };
  for (const key of DEVICE_KEYS) delete clone[key];
  return clone;
}

function findingHtml(finding, includeTechnical, index, includeDevice) {
  const number = index + 1;
  const headingId = `readable-finding-${number}`;
  const severity = ['match', 'suspicious', 'note'].includes(finding?.severity)
    ? finding.severity
    : 'note';
  const indicator = finding?.indicator
    ? `<p><strong>Published indicator:</strong> <code>${esc(finding.indicator.value)}</code><br>
       <strong>Campaign:</strong> ${esc(finding.indicator.campaign || 'unavailable')}<br>
       <strong>Indicator set:</strong> ${esc(finding.indicator.set || 'unavailable')}</p>`
    : '';
  const evidence = includeTechnical
    ? `<details open><summary>Technical evidence for finding ${number}</summary><pre>${esc(JSON.stringify(withoutDeviceKeys(finding?.evidence ?? null, includeDevice), null, 2))}</pre></details>`
    : '';
  const artifact = includeTechnical
    ? (finding?.artifact || 'artifact unavailable')
    : 'source artifact path redacted';
  return `<section class="finding" aria-labelledby="${headingId}">
    <h3 id="${headingId}">Finding ${number}: ${esc(severity)}</h3>
    <p><span class="severity ${severity}">${esc(severity)}</span> <span class="artifact">${esc(artifact)}</span></p>
    <p>${esc(finding?.summary || 'No summary supplied.')}</p>
    ${indicator}${evidence}
  </section>`;
}

function findingsHtml(report, includeTechnical, includeDevice) {
  const findings = Array.isArray(report?.findings) ? report.findings : [];
  if (findings.length === 0) return '<p class="empty">No findings were recorded.</p>';
  const shown = findings.slice(0, MAX_READABLE_FINDINGS);
  const omitted = findings.length - shown.length;
  return `${shown.map((finding, index) => findingHtml(finding, includeTechnical, index, includeDevice)).join('')}
    ${omitted > 0 ? `<p class="notice">This readable copy shows the first ${MAX_READABLE_FINDINGS} severity-ordered findings. ${omitted} additional findings remain in the JSON report.</p>` : ''}`;
}

function artifactLabel(artifact) {
  return artifact?.kind === 'crash_log' && artifact?.details?.paired_device === true
    ? 'paired-device crash log'
    : artifact?.kind;
}

function artifactsHtml(report, includeTechnical, includeDevice) {
  const artifacts = Array.isArray(report?.artifacts) ? report.artifacts : [];
  const missing = Array.isArray(report?.missing_artifacts) ? report.missing_artifacts : [];
  const shown = artifacts.slice(0, MAX_READABLE_ARTIFACTS);
  const rows = shown.map((artifact) => `<tr>
    <td>${esc(artifactLabel(artifact))}</td>
    <td>${esc(artifact.status)}</td>
    ${includeTechnical ? `<td><code>${esc(artifact.path)}</code></td><td><code>${esc(JSON.stringify(withoutDeviceKeys(artifact.details ?? {}, includeDevice)))}</code></td>` : ''}
  </tr>`).join('');
  const missingRows = missing.map((artifact) => `<tr>
    <td>${esc(artifact.kind)}</td>
    <td>not found</td>
    ${includeTechnical ? `<td>-</td><td>${esc(artifact.note)}</td>` : ''}
  </tr>`).join('');
  if (!rows && !missingRows) return '<p class="empty">No artifact inventory was recorded.</p>';
  return `<div class="table-scroll" role="region" aria-label="Artifact processing details" tabindex="0"><table>
    <thead><tr><th>Artifact family</th><th>Status</th>${includeTechnical ? '<th>Path</th><th>Details</th>' : ''}</tr></thead>
    <tbody>${rows}${missingRows}</tbody>
  </table></div>
  ${artifacts.length > shown.length
    ? `<p class="notice">This readable copy shows the first ${MAX_READABLE_ARTIFACTS} processed artifacts. ${artifacts.length - shown.length} additional artifacts remain in the JSON technical report.</p>`
    : ''}`;
}

function provenanceHtml(report) {
  const sets = Array.isArray(report?.indicator_provenance)
    ? report.indicator_provenance
    : [];
  if (sets.length === 0) return '<p class="empty">No indicator provenance was recorded.</p>';
  return `<div class="table-scroll" role="region" aria-label="Indicator provenance" tabindex="0"><table>
    <thead><tr><th>Campaign</th><th>Snapshot date</th><th>Indicator SHA-256</th></tr></thead>
    <tbody>${sets.map((set) => `<tr>
      <td>${esc(set.campaign || set.name)}</td>
      <td>${esc(set.date || 'unavailable')}</td>
      <td><code class="hash">${esc(set.sha256 || 'unavailable')}</code></td>
    </tr>`).join('')}</tbody>
  </table></div>`;
}

export function readableReportFragment(report, options = {}) {
  const opts = normalizedOptions(options);
  const source = report?.source_file || {};
  const verdict = Object.hasOwn(VERDICTS, report?.verdict) ? report.verdict : 'inconclusive';
  const verdictCopy = VERDICTS[verdict];
  const sourceName = opts.includeSourceName
    ? (source.name || 'unavailable')
    : 'redacted from this readable copy';
  const device = !opts.includeDevice
    ? '<p class="empty">Device metadata redacted from this readable copy.</p>'
    : report?.device
      ? `<dl>
          <div><dt>OS version</dt><dd>${esc(report.device.os_version || 'unavailable')}</dd></div>
          <div><dt>Metadata source</dt><dd>${esc(report.device.source || 'unavailable')}</dd></div>
          <div><dt>Device timestamp</dt><dd>${esc(report.device.timestamp || 'unavailable')}</dd></div>
        </dl>`
      : '<p class="empty">No device metadata was recorded.</p>';
  const rawBuildCommit = report?.tool?.build_commit;
  const hasBuildCommit = typeof rawBuildCommit === 'string'
    && /^[0-9a-f]{40}$/.test(rawBuildCommit);
  const buildCommit = hasBuildCommit
    ? rawBuildCommit
    : 'exact build revision not recorded or invalid';
  const rawVersion = report?.tool?.version;
  const hasSafeVersion = typeof rawVersion === 'string'
    && /^\d+\.\d+\.\d+$/.test(rawVersion);
  const schemaRef = hasBuildCommit
    ? rawBuildCommit
    : hasSafeVersion ? `v${rawVersion}` : 'main';
  const schemaRoot = `https://github.com/iAnonymous3000/tracescan/blob/${schemaRef}`;
  const guideRef = hasBuildCommit ? rawBuildCommit : 'main';
  const guideRoot = `https://github.com/iAnonymous3000/tracescan/blob/${guideRef}`;
  const guideLabel = hasBuildCommit
    ? 'Revision-pinned responder guide'
    : 'Current responder guide (not revision-pinned)';
  const schemaLabel = hasBuildCommit
    ? 'Revision-pinned machine-readable contract'
    : hasSafeVersion
      ? `Version-tag machine-readable contract (v${rawVersion})`
      : 'Current machine-readable contract (not revision-pinned)';
  const reproductionStep = hasBuildCommit
    ? '<li>For consequential use, review and build that exact revision only inside a disposable, no-credentials environment. Build before introducing case data, disconnect the environment, re-scan a copy of the archive, then compare the two JSON technical reports\' source hash and size, indicator hashes, verdict, findings, artifacts, missing artifacts, scan limits, assurance, and coverage.</li>'
    : '<li>No exact build commit is available, so an exact reproduction is impossible. A comparison with a separately trusted release can still be informative, but record the weaker provenance and seek technical review for consequential use.</li>';
  const limits = Array.isArray(report?.scan_limits) ? report.scan_limits : [];
  const missingArtifacts = Array.isArray(report?.missing_artifacts)
    ? report.missing_artifacts
    : [];
  const coverage = report?.coverage || {};
  const limitWarning = limits.length > 0
    ? `<p class="warning"><strong>Processing or reporting was incomplete.</strong> Trace recorded ${limits.length} scan ${limits.length === 1 ? 'limit' : 'limits'}. Read each limit together with the verdict: some evidence may not have been analyzed, or some findings may not have been retained.</p>`
    : '';
  const coverageWarning = verdict === 'clear' && missingArtifacts.length > 0
    ? `<p class="warning"><strong>This was not a full four-surface scan.</strong> ${missingArtifacts.length} of Trace's 4 supported artifact ${missingArtifacts.length === 1 ? 'families was' : 'families were'} absent. This clear result applies only to the supported evidence that was present.</p>`
    : '';
  const referenceWarning = !hasBuildCommit
    ? `<p class="notice"><strong>The links below do not identify the original build exactly.</strong> ${hasSafeVersion ? `The schema link uses the reported version tag v${esc(rawVersion)}, which is an unsigned repository name and must be independently verified.` : 'No strictly valid build commit or version was recorded, so both links use the current branch.'}</p>`
    : '';
  const exampleNotice = opts.example
    ? `<aside class="example-notice" role="note" aria-label="Example report">
        <p><strong>Example report - no device was scanned.</strong></p>
        <p>This report comes from a synthetic demonstration archive. It is for learning the handoff format, not for making a device-security decision.</p>
      </aside>`
    : '';

  return `<article class="readable-report" data-verdict="${verdict}">
    ${exampleNotice}
    <header>
      <p class="eyebrow">Trace responder report</p>
      <h1>${esc(verdictCopy.label)}</h1>
      <p class="meaning">${esc(verdictCopy.meaning)}</p>
      ${limitWarning}${coverageWarning}
    </header>

    <section class="report-section identity">
      <h2>Report identity</h2>
      <dl>
        <div><dt>Verdict</dt><dd>${esc(verdict)}</dd></div>
        <div><dt>Generated</dt><dd>${esc(report?.generated_at || 'unavailable')}</dd></div>
        <div><dt>Trace version</dt><dd>${esc(report?.tool?.version || 'unavailable')}</dd></div>
        <div><dt>Build commit</dt><dd><code class="hash">${esc(buildCommit)}</code></dd></div>
        <div><dt>Source filename</dt><dd>${esc(sourceName)}</dd></div>
        <div><dt>Source size</dt><dd>${esc(fmtBytes(source.size))}</dd></div>
        <div><dt>Archive SHA-256</dt><dd><code class="hash">${esc(source.sha256 || 'unavailable')}</code></dd></div>
        <div><dt>Schema</dt><dd>version ${esc(report?.schema_version ?? 'unavailable')}</dd></div>
      </dl>
      <p class="notice"><strong>The archive hash remains visible even with redaction.</strong> It identifies the archive bytes this copy claims Trace analyzed. Independently compare the hash and re-scan before relying on that claim. The hash does not contain the archive.</p>
    </section>

    <section class="report-section">
      <h2>Device metadata</h2>
      ${device}
    </section>

    <section class="report-section">
      <h2>Findings (${esc(Array.isArray(report?.findings) ? report.findings.length : 0)})</h2>
      ${findingsHtml(report, opts.includeTechnical, opts.includeDevice)}
    </section>

    <section class="report-section">
      <h2>What Trace examined</h2>
      ${artifactsHtml(report, opts.includeTechnical, opts.includeDevice)}
    </section>

    <section class="report-section two-column">
      <div><h2>Examined</h2>${list(coverage.examined, 'No coverage list was recorded.')}</div>
      <div><h2>Not examined</h2>${list(coverage.not_examined, 'No exclusion list was recorded.')}</div>
    </section>
    ${coverage.note ? `<p class="notice">${esc(coverage.note)}</p>` : ''}

    <section class="report-section">
      <h2>Scan limits</h2>
      ${list(limits, 'No scan safety limit was reached.')}
    </section>

    <section class="report-section">
      <h2>Indicator provenance</h2>
      ${provenanceHtml(report)}
    </section>

    <section class="report-section verification">
      <h2>How a responder verifies this report</h2>
      <p>This readable HTML is a reduced convenience copy. Checks involving fields not shown here require the JSON technical report.</p>
      <ol>
        <li>Obtain the original archive through an appropriately safe channel. Compute its SHA-256 and compare all 64 characters with <strong>Archive SHA-256</strong> above.</li>
        <li>Treat build metadata as an untrusted claim. Confirm any recorded 40-hex commit exists in Trace's public history, then use the guide and schema pinned to that revision. This copy declares schema version ${esc(report?.schema_version ?? 'unavailable')}.</li>
        ${reproductionStep}
      </ol>
      <p class="warning"><strong>This HTML file and the JSON report are not digitally signed.</strong> Either can be edited after export. A matching hash only shows that the supplied archive matches the value currently written in the report; it does not prove Trace scanned those bytes. An isolated independent re-scan checks whether the report content is consistent with the claimed revision and archive.</p>
      ${referenceWarning}
      <p><a href="${esc(guideRoot)}/HELPLINE.md">${esc(guideLabel)}</a>. <a href="${esc(schemaRoot)}/web/report.schema.json">${esc(schemaLabel)}</a>.</p>
    </section>
  </article>`;
}

const DOCUMENT_STYLE = `
  :root { color-scheme: light; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #1d2126; background: #f4f5f3; }
  * { box-sizing: border-box; }
  body { margin: 0; line-height: 1.5; }
  main { max-width: 920px; margin: 24px auto; padding: 0 20px; }
  .readable-report { min-width: 0; overflow-wrap: anywhere; background: #fff; border: 1px solid #dfe2e5; border-radius: 12px; padding: 32px; }
  h1, h2, h3 { line-height: 1.25; }
  h1 { margin: 4px 0 10px; font-size: 1.8rem; }
  h2 { font-size: 1.08rem; margin: 0 0 10px; }
  h3 { font-size: .98rem; margin: 0 0 8px; }
  .eyebrow { margin: 0; color: #5b6470; font-size: .78rem; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
  .meaning { font-size: 1.03rem; max-width: 75ch; }
  .report-section { border-top: 1px solid #dfe2e5; padding-top: 20px; margin-top: 24px; }
  dl { margin: 0; }
  dl div { display: grid; grid-template-columns: 150px 1fr; gap: 12px; padding: 5px 0; }
  dt { color: #5b6470; }
  dd { margin: 0; min-width: 0; }
  code, pre { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }
  code.hash, .artifact { overflow-wrap: anywhere; }
  .notice, .warning { background: #eef1f4; border: 1px solid #d3dae1; border-radius: 8px; padding: 10px 12px; }
  .warning { background: #fdf3e0; border-color: #ecd3a2; }
  .example-notice { margin-bottom: 20px; background: #e9f5f2; border: 2px solid #0f6b62; border-radius: 8px; padding: 10px 12px; }
  .example-notice p { margin: 4px 0; }
  .empty { color: #5b6470; font-style: italic; }
  .finding { border: 1px solid #dfe2e5; border-radius: 8px; padding: 12px 14px; margin: 10px 0; break-inside: avoid; }
  .finding p { margin: 5px 0; }
  .severity { display: inline-block; border: 1px solid; border-radius: 99px; padding: 1px 8px; font-size: .72rem; font-weight: 800; text-transform: uppercase; }
  .severity.match { background: #fbeae9; color: #8f1d16; border-color: #e5b3af; }
  .severity.suspicious { background: #fdf3e0; color: #7a4c07; border-color: #ecd3a2; }
  .severity.note { background: #eef1f4; color: #3f4a56; border-color: #d3dae1; }
  pre { white-space: pre-wrap; overflow-wrap: anywhere; background: #f4f5f6; padding: 10px; border-radius: 6px; }
  .table-scroll { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: .9rem; }
  th, td { text-align: left; vertical-align: top; padding: 7px 8px; border-top: 1px solid #dfe2e5; }
  th { border-top: 0; color: #5b6470; }
  .two-column { display: grid; grid-template-columns: 1fr 1fr; gap: 28px; }
  a { color: #0f6b62; }
  @media (max-width: 620px) { .readable-report { padding: 20px; } dl div, .two-column { grid-template-columns: 1fr; gap: 0; } dt { font-weight: 600; } }
  @media print { :root { background: #fff; } main { max-width: none; margin: 0; padding: 0; } .readable-report { border: 0; padding: 0; } a { color: inherit; text-decoration: underline; } .verification a::after { content: " (" attr(href) ")"; overflow-wrap: anywhere; } }
`;

export function readableReportDocument(report, options = {}) {
  const opts = normalizedOptions(options);
  const titleVerdict = Object.hasOwn(VERDICTS, report?.verdict)
    ? VERDICTS[report.verdict].label
    : VERDICTS.inconclusive.label;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>${esc(`${opts.example ? 'Example ' : ''}Trace report - ${titleVerdict}`)}</title>
<style>${DOCUMENT_STYLE}</style>
</head>
<body><main>${readableReportFragment(report, options)}</main></body>
</html>`;
}
