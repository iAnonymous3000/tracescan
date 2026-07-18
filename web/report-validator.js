/*
 * Strictly validate report envelopes received from either scanner producer.
 *
 * This module is deliberately independent of page state and DOM rendering so
 * the worker/main-thread trust boundary can be reviewed and tested in isolation.
 */

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
export function isNonnegativeInteger(value) {
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

export function isPairedDeviceArtifactPath(path) {
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
export function isCompleteReportEnvelope(report, file, expectedVia, expectedSets) {
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

  const expectedStats = new Map(expectedSets.map((set) => [set.name, set.stats]));
  const expectedTotal = expectedSets.reduce((total, set) => total + set.stats.extracted, 0);
  const expectedApplicable = expectedSets.reduce(
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

  if (report.indicator_provenance.length !== expectedSets.length) return false;
  const provenanceNames = new Set();
  for (const provenance of report.indicator_provenance) {
    const bundled = isRecord(provenance)
      ? expectedSets.find((set) => set.name === provenance.name)
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

  // Surface presence and actual examination are distinct for .ips reports.
  // Metadata-only reports remain useful report artifacts, but the engine marks
  // them detection_relevant=false and does not count them as crash coverage.
  const primaryArtifactKinds = new Set();
  const examinedPrimaryArtifactKinds = new Set();
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
    if (artifact.kind === 'crash_log') {
      if (typeof artifact.details.paired_device !== 'boolean'
          || artifact.details.paired_device !== paired
          || typeof artifact.details.detection_relevant !== 'boolean'
          || !isNonnegativeInteger(artifact.details.processes)) {
        return false;
      }
      if (!paired && artifact.details.detection_relevant) {
        primaryArtifactKinds.add(artifact.kind);
        if (artifact.details.processes > 0) {
          examinedPrimaryArtifactKinds.add(artifact.kind);
        }
      }
    } else {
      primaryArtifactKinds.add(artifact.kind);
      if (artifact.kind === 'unified_log') {
        if (!isNonnegativeInteger(artifact.details.tracev3_files)) return false;
        if (artifact.details.tracev3_files > 0) {
          examinedPrimaryArtifactKinds.add(artifact.kind);
        }
      } else {
        examinedPrimaryArtifactKinds.add(artifact.kind);
      }
    }
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
      || report.assurance.surfaces_examined !== examinedPrimaryArtifactKinds.size
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
    // Match the engine's primary_crash_degraded predicate: supplemental
    // paired-device and metadata-only reports can be partially parsed without
    // downgrading an otherwise complete primary crash surface.
    const degradesSurface = artifact.kind === 'crash_log'
      ? artifact.details.paired_device === false
        && artifact.details.detection_relevant === true
        && artifact.status !== 'parsed'
      : artifact.status !== 'parsed';
    return degradesSurface
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

  const hasSupplementalCrashOnly = report.artifacts.some((artifact) => (
    artifact.kind === 'crash_log'
    && (artifact.details.paired_device === true
      || artifact.details.detection_relevant === false)
  )) && examinedPrimaryArtifactKinds.size === 0;
  // The engine always records a no-primary-surface limit for a report made
  // only from paired-device or metadata-only .ips artifacts. Reject a forged
  // worker envelope that removes that limit to manufacture a clear verdict.
  if (hasSupplementalCrashOnly && report.scan_limits.length === 0) return false;

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
