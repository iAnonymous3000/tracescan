//! Plain-Rust engine behind the WASM `Scanner`: accepts streamed archive
//! bytes, auto-detects gzip vs raw tar, and assembles the final report.

use crate::ioc::{IocDb, SetStats};
use crate::report::*;
use crate::tar_stream::{ArtifactKind, Limits, TarCollector};
use crate::{crash_log, ps, shutdown_log};
use flate2::write::MultiGzDecoder;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::Write;

fn crash_timestamp(value: Option<&str>) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    let value = value?;
    chrono::DateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f %z")
        .or_else(|_| chrono::DateTime::parse_from_rfc3339(value))
        .ok()
}

fn device_timestamp_is_newer(candidate: &DeviceInfo, current: &DeviceInfo) -> bool {
    match (
        crash_timestamp(candidate.timestamp.as_deref()),
        crash_timestamp(current.timestamp.as_deref()),
    ) {
        (Some(candidate), Some(current)) => candidate > current,
        // A timestamp that can be placed on a timeline is stronger than
        // missing or malformed metadata. If neither parses, keep the first
        // OS-bearing crash rather than inventing an ordering.
        (Some(_), None) => true,
        _ => false,
    }
}

fn hex(digest: &[u8]) -> String {
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// Catalog metadata for one indicator set, supplied by the producer at
/// load time. The engine records it verbatim as provenance; the set's
/// hash is computed by the engine, never taken from here.
#[derive(Default, Deserialize)]
pub struct SetMeta {
    pub date: Option<String>,
    pub url: Option<String>,
    pub source: Option<String>,
    pub loaded_from: Option<String>,
    pub upstream: Option<String>,
}

/// Scan-level metadata from the producer: what file it fed the engine
/// (the engine has no file handle, only bytes). Descriptive only; nothing
/// here influences the verdict. Timing is not producer-supplied: duration
/// is measured by the engine through an injected clock, because the
/// expensive work (parsing, matching, verdict assembly) happens inside
/// `finish`, after any reading a producer could take.
#[derive(Default, Deserialize)]
pub struct ScanMeta {
    pub source_name: Option<String>,
    /// Accepted for producer compatibility, but never trusted for report
    /// integrity. `source_file.size` is derived from bytes pushed to Engine.
    pub source_size: Option<u64>,
    pub scanned_via: Option<String>,
}

enum Sink {
    Gz(MultiGzDecoder<TarCollector>),
    Plain(TarCollector),
}

fn write_sink(sink: &mut Sink, data: &[u8]) -> Result<(), String> {
    match sink {
        Sink::Gz(g) => g.write_all(data).map_err(|e| {
            format!("decompression failed - is this a .tar.gz sysdiagnose archive? ({e})")
        }),
        Sink::Plain(c) => c.write_all(data).map_err(|e| e.to_string()),
    }
}

pub struct Engine {
    db: IocDb,
    sink: Option<Sink>,
    /// Bytes held back until enough have arrived to sniff the gzip magic;
    /// a stream may legally deliver its first chunk as a single byte.
    prelude: Vec<u8>,
    limits: Limits,
    bytes_in: u64,
    /// Hash of every byte pushed - the archive exactly as received, before
    /// any decoding. Identifies which file a report describes.
    input_hash: Sha256,
    provenance: Vec<SetProvenance>,
    scan_meta: ScanMeta,
    /// Millisecond clock injected by the host (js Date.now in the browser,
    /// a monotonic timer natively). Only differences are taken, so any
    /// epoch works. Without one, duration_ms is null.
    clock: Option<Box<dyn Fn() -> f64>>,
    scan_started: Option<f64>,
    generated_at: Option<String>,
}

impl Default for Engine {
    fn default() -> Self {
        Engine::new()
    }
}

impl Engine {
    pub fn new() -> Self {
        Engine {
            db: IocDb::new(),
            sink: None,
            prelude: Vec::new(),
            limits: Limits::default(),
            bytes_in: 0,
            input_hash: Sha256::new(),
            provenance: Vec::new(),
            scan_meta: ScanMeta::default(),
            clock: None,
            scan_started: None,
            generated_at: None,
        }
    }

    pub fn set_clock(&mut self, clock: Box<dyn Fn() -> f64>) {
        self.clock = Some(clock);
    }

    /// RFC 3339 timestamp for the report, from the host's calendar clock.
    /// Meant to be stamped when finalization begins - the closest a
    /// producer can get to "when the report was generated" from outside.
    pub fn set_generated_at(&mut self, iso: String) {
        self.generated_at = Some(iso);
    }

    pub fn load_stix(&mut self, set_name: &str, json: &str) -> Result<SetStats, String> {
        self.load_stix_with_meta(set_name, json, SetMeta::default())
    }

    pub fn load_stix_with_meta(
        &mut self,
        set_name: &str,
        json: &str,
        meta: SetMeta,
    ) -> Result<SetStats, String> {
        let stats = self.db.load_stix(set_name, json)?;
        self.provenance.push(SetProvenance {
            name: stats.name.clone(),
            campaign: stats.campaign.clone(),
            sha256: sha256_hex(json.as_bytes()),
            // Provenance claims are opt-in. Browser snapshots explicitly set
            // "bundled"; callers without metadata remain honestly unknown.
            loaded_from: meta.loaded_from.unwrap_or_else(|| "unknown".into()),
            date: meta.date,
            url: meta.url,
            source: meta.source,
            upstream: meta.upstream,
        });
        Ok(stats)
    }

    pub fn set_scan_meta(&mut self, meta: ScanMeta) {
        self.scan_meta = meta;
    }

    pub fn push(&mut self, chunk: &[u8]) -> Result<(), String> {
        if chunk.is_empty() {
            return Ok(());
        }
        self.bytes_in += chunk.len() as u64;
        if self.scan_started.is_none() {
            self.scan_started = self.clock.as_ref().map(|c| c());
        }
        self.input_hash.update(chunk);
        if self.sink.is_none() {
            self.prelude.extend_from_slice(chunk);
            if self.prelude.len() < 2 {
                return Ok(());
            }
            let collector = TarCollector::with_limits(self.limits);
            let is_gz = self.prelude[0] == 0x1f && self.prelude[1] == 0x8b;
            let mut sink = if is_gz {
                Sink::Gz(MultiGzDecoder::new(collector))
            } else {
                Sink::Plain(collector)
            };
            let buffered = std::mem::take(&mut self.prelude);
            let res = write_sink(&mut sink, &buffered);
            self.sink = Some(sink);
            return res;
        }
        write_sink(self.sink.as_mut().unwrap(), chunk)
    }

    pub fn finish(mut self) -> Result<Report, String> {
        let mut collector = match self.sink.take() {
            // A sub-2-byte input never got a sink; it cannot be an archive.
            None if !self.prelude.is_empty() => {
                return Err("file is too small to be an archive".into())
            }
            None => return Err("no data received".into()),
            Some(Sink::Gz(g)) => g.finish().map_err(|e| {
                format!("archive ended unexpectedly - the file may be incomplete ({e})")
            })?,
            Some(Sink::Plain(c)) => c,
        };

        let mut findings = Findings::new();
        let mut artifacts: Vec<ArtifactSummary> = Vec::new();
        let mut device: Option<DeviceInfo> = None;
        let mut primary_crash_degraded = false;

        for f in &collector.files {
            let invalid_utf8 = std::str::from_utf8(&f.data).is_err();
            let text = String::from_utf8_lossy(&f.data);
            match f.kind {
                ArtifactKind::ShutdownLog => {
                    artifacts.push(shutdown_log::analyze(
                        &f.path,
                        &text,
                        &self.db,
                        &mut findings,
                    ));
                }
                ArtifactKind::CrashLog | ArtifactKind::PairedCrashLog => {
                    let (a, d) = crash_log::analyze(&f.path, &text, &self.db, &mut findings);
                    artifacts.push(a);
                    // Prefer the newest .ips report: an old report can predate
                    // an OS upgrade and misstate the capture-time OS. Paired
                    // reports are scanned but describe a different device.
                    if matches!(f.kind, ArtifactKind::CrashLog) {
                        if let Some(d) = d {
                            if device
                                .as_ref()
                                .is_none_or(|cur| device_timestamp_is_newer(&d, cur))
                            {
                                device = Some(d);
                            }
                        }
                    }
                }
                ArtifactKind::PsListing => {
                    artifacts.push(ps::analyze(&f.path, &text, &self.db, &mut findings));
                }
            }
            if let Some(last) = artifacts.last_mut() {
                // Lossy decoding is useful for salvaging ASCII evidence, but
                // it changes bytes and therefore cannot count as a complete
                // parse or a clean IOC comparison.
                if invalid_utf8 {
                    last.details["invalid_utf8"] = serde_json::Value::Bool(true);
                    if last.status == "parsed" {
                        last.status = "parsed_partial".into();
                    }
                }
                if f.truncated {
                    last.status = "truncated".into();
                }
                if matches!(f.kind, ArtifactKind::CrashLog)
                    && last.details["detection_relevant"].as_bool() == Some(true)
                    && last.status != "parsed"
                {
                    primary_crash_degraded = true;
                }
            }
        }

        // Unified logs were consumed during streaming; reduce them to
        // findings and a summary now that the whole archive has been seen.
        // Health counters are captured first: parse failures must reach the
        // verdict, not just the artifact details.
        let unified = std::mem::take(&mut collector.unified);
        let truncated_tracev3_files = unified.truncated_tracev3_files;
        let truncated_uuidtext_files = unified.truncated_uuidtext_files;
        let unified_seen = unified.saw_content();
        let tracev3_files = unified.tracev3_files;
        let unified_examined = tracev3_files > 0;
        let tracev3_failures = unified.tracev3_failures;
        let tracev3_incomplete = unified.tracev3_incomplete;
        let uuidtext_files = unified.uuidtext_files;
        let uuidtext_failures = unified.uuidtext_failures;
        let unified_cap_hit = unified.cap_hit;
        let mut unified_unresolved: Option<(u64, u64)> = None;
        let mut unified_empty_inventory = false;
        if let Some(summary) = unified.finalize(&self.db, &mut findings) {
            let seen = summary.details["processes_seen"].as_u64().unwrap_or(0);
            let unresolved = summary.details["processes_unresolved"]
                .as_u64()
                .unwrap_or(0);
            if unresolved > 0 {
                unified_unresolved = Some((unresolved, seen));
            }
            // tracev3 that parsed to an empty inventory: real tracev3
            // always carries catalog processes, so nothing was checked.
            // (Wholesale parse failure has its own limit below.)
            if seen == 0 && tracev3_failures < tracev3_files {
                unified_empty_inventory = true;
            }
            artifacts.push(summary);
        }

        let findings_capped = findings.capped;
        let mut findings = findings.into_vec();
        findings.sort_by_key(|f| std::cmp::Reverse(f.severity));

        let found: std::collections::HashSet<ArtifactKind> =
            collector.files.iter().map(|f| f.kind).collect();
        // Not every primary-device .ips file is a detection surface. Reports
        // such as Siri feedback and reset counters are useful metadata, but
        // deliberately expose no process identity or inventory to compare
        // with process/file indicators. Keep those artifacts in the report
        // without letting their mere presence stand in for phone coverage.
        let primary_crash_relevant_seen = artifacts.iter().any(|artifact| {
            artifact.kind == "crash_log"
                && artifact.details["paired_device"].as_bool() == Some(false)
                && artifact.details["detection_relevant"].as_bool() == Some(true)
        });
        let primary_crash_process_bearing = artifacts.iter().any(|artifact| {
            artifact.kind == "crash_log"
                && artifact.details["paired_device"].as_bool() == Some(false)
                && artifact.details["detection_relevant"].as_bool() == Some(true)
                && artifact.details["processes"].as_u64().unwrap_or(0) > 0
        });
        let primary_metadata_only_seen = artifacts.iter().any(|artifact| {
            artifact.kind == "crash_log"
                && artifact.details["paired_device"].as_bool() == Some(false)
                && artifact.details["detection_relevant"].as_bool() == Some(false)
        });
        // A kind whose files were all dropped after a retention cap was
        // present in the archive - it is not "missing". Reporting it as
        // not-found (with reassuring "this can be normal" wording) would
        // contradict the dropped-artifacts scan limit. Treat it as present
        // for the missing/absent determination; its own scan limit and the
        // partial surface state carry the truth.
        let present = |k: ArtifactKind| found.contains(&k) || collector.dropped_kinds.contains(&k);
        let mut missing_artifacts = Vec::new();
        if !present(ArtifactKind::ShutdownLog) {
            missing_artifacts.push(MissingArtifact {
                kind: "shutdown_log".into(),
                note: "No shutdown.log was found in this archive. It normally exists once the device has been restarted at least once; without it, one of the four detection surfaces is unavailable for this scan.".into(),
            });
        }
        let primary_crash_surface_present = primary_crash_relevant_seen
            || collector.dropped_kinds.contains(&ArtifactKind::CrashLog);
        if !primary_crash_surface_present {
            missing_artifacts.push(MissingArtifact {
                kind: "crash_log".into(),
                note: if primary_metadata_only_seen {
                    "iPhone crash or diagnostic .ips reports were present, but none contained a process identity or process inventory. Metadata-only reports do not provide the phone crash-report detection surface.".into()
                } else {
                    "No crash or diagnostic .ips reports were found in crashes_and_spins. This can be normal, especially on a new or recently erased device.".into()
                },
            });
        }
        if !present(ArtifactKind::PsListing) {
            missing_artifacts.push(MissingArtifact {
                kind: "ps_listing".into(),
                note: "No process listing (ps.txt) was found in this archive, so running processes could not be checked.".into(),
            });
        }
        if !unified_seen {
            missing_artifacts.push(MissingArtifact {
                kind: "unified_log".into(),
                note: "No unified log data (system_logs.logarchive tracev3 files) was found in this archive, so process identities represented in unified-log catalogs could not be checked.".into(),
            });
        }

        // Any verdict-relevant safety limit means part of the archive went
        // unanalyzed. Evidence-only sampling is bounded and reported by its
        // artifact without creating a scan limit.
        let mut scan_limits: Vec<String> = Vec::new();
        if collector.entry_cap_hit {
            scan_limits.push(
                "The archive contained more files than this scanner will walk; scanning stopped early and later files were not examined.".into(),
            );
        }
        let truncated_count = collector.files.iter().filter(|f| f.truncated).count();
        if truncated_count > 0 {
            scan_limits.push(format!(
                "{truncated_count} artifact file(s) exceeded size limits and only their beginning was analyzed."
            ));
        }
        if collector.dropped_artifacts > 0 {
            scan_limits.push(format!(
                "{} artifact file(s) were skipped entirely after the scan reached its memory safety limit.",
                collector.dropped_artifacts
            ));
        }
        if truncated_tracev3_files > 0 {
            scan_limits.push(format!(
                "{truncated_tracev3_files} unified log (tracev3) file(s) exceeded size limits and were skipped; the process history is incomplete."
            ));
        }
        if truncated_uuidtext_files > 0 {
            scan_limits.push(format!(
                "{truncated_uuidtext_files} unified log support (uuidtext) file(s) exceeded size limits and were skipped; some processes may not resolve to binary paths."
            ));
        }
        // Parser health. A surface that failed to parse - fully or in part -
        // was not fully analyzed, and the verdict must not read as clear.
        // Findings already produced from what did parse are unaffected.
        let unparsed_ps = artifacts
            .iter()
            .filter(|a| a.kind == "ps_listing" && a.status == "unparsed")
            .count();
        if unparsed_ps > 0 {
            scan_limits.push(format!(
                "{unparsed_ps} process listing file(s) could not be parsed; the processes they list were not checked."
            ));
        }
        let partial_ps = artifacts
            .iter()
            .filter(|a| a.kind == "ps_listing" && a.status == "parsed_partial")
            .count();
        if partial_ps > 0 {
            scan_limits.push(format!(
                "{partial_ps} process listing file(s) contained rows that could not be parsed; those processes were not checked."
            ));
        }
        // A truncated ps file was parsed from its retained prefix (its rows
        // were checked) but its status is overwritten to "truncated"; the
        // size-limit scan message already covers it. Excluding that case
        // here avoids a contradictory "contained no process rows" claim.
        let truncated_ps = artifacts
            .iter()
            .filter(|a| a.kind == "ps_listing" && a.status == "truncated")
            .count();
        if found.contains(&ArtifactKind::PsListing)
            && unparsed_ps == 0
            && partial_ps == 0
            && truncated_ps == 0
            && artifacts
                .iter()
                .filter(|a| a.kind == "ps_listing")
                .map(|a| a.details["processes"].as_u64().unwrap_or(0))
                .sum::<u64>()
                == 0
        {
            scan_limits.push(
                "The process listings parsed but contained no process rows, so running processes could not be checked."
                    .into(),
            );
        }
        let unparsed_shutdown = artifacts
            .iter()
            .filter(|a| a.kind == "shutdown_log" && a.status == "unparsed")
            .count();
        if unparsed_shutdown > 0 {
            scan_limits.push(format!(
                "{unparsed_shutdown} shutdown log file(s) contained no recognizable content; processes that delayed shutdown were not checked."
            ));
        }
        let partial_shutdown = artifacts
            .iter()
            .filter(|a| a.kind == "shutdown_log" && a.status == "parsed_partial")
            .count();
        if partial_shutdown > 0 {
            scan_limits.push(format!(
                "{partial_shutdown} shutdown log file(s) had client entries in an unrecognized format; the processes those entries name were not checked."
            ));
        }
        let partial_crashes = artifacts
            .iter()
            .filter(|a| a.kind == "crash_log" && a.status == "parsed_partial")
            .count();
        let capped_crash_inventories = artifacts
            .iter()
            .filter(|artifact| artifact.details["candidate_cap_hit"] == true)
            .count();
        if capped_crash_inventories > 0 {
            scan_limits.push(format!(
                "{capped_crash_inventories} crash or diagnostic .ips process inventory file(s) exceeded the {}-candidate safety cap; later process candidates were not checked.",
                crash_log::MAX_CRASH_CANDIDATES
            ));
        }
        if partial_crashes > 0 {
            scan_limits.push(format!(
                "{partial_crashes} crash or diagnostic .ips file(s) could not be fully parsed; parts of their contents were not checked against indicators."
            ));
        }
        if let Some((unresolved, seen)) = unified_unresolved {
            scan_limits.push(format!(
                "{unresolved} of {seen} processes in the unified log inventory could not be resolved to a binary path, so those processes could not be checked against indicators."
            ));
        }
        if unified_empty_inventory {
            scan_limits.push(
                "The unified log (tracev3) files parsed but contained no process inventory, so that surface could not be checked; a real sysdiagnose's logs always list processes.".into(),
            );
        }
        if tracev3_failures > 0 {
            scan_limits.push(format!(
                "{tracev3_failures} of {tracev3_files} unified log (tracev3) file(s) could not be parsed; the process history is incomplete."
            ));
        }
        if tracev3_incomplete > 0 {
            scan_limits.push(format!(
                "{tracev3_incomplete} unified log (tracev3) file(s) had catalog sections that could not be read; some processes in the log history were not checked."
            ));
        }
        if uuidtext_failures > 0 {
            scan_limits.push(format!(
                "{uuidtext_failures} of {uuidtext_files} unified log support (uuidtext) file(s) could not be parsed; some processes could not be resolved to binary paths."
            ));
        }
        if unified_cap_hit {
            scan_limits.push(
                "The unified log identity inventory reached its memory safety cap; some process identities or binary paths were not retained.".into(),
            );
        }
        // A checksum failure after valid entries means the archive is
        // corrupt from that point on and nothing after it was seen. On the
        // very first header it just means "not a tar", which the invalid
        // verdict below covers without a scan limit.
        if collector.bad_checksum
            && (collector.entries > 0 || !collector.files.is_empty() || unified_seen)
        {
            scan_limits.push(
                "An archive entry failed its integrity checksum; scanning stopped there and the rest of the archive was not analyzed.".into(),
            );
        }
        if collector.malformed_header
            && (collector.entries > 0 || !collector.files.is_empty() || unified_seen)
        {
            scan_limits.push(
                "An archive header contained an invalid numeric framing field; scanning stopped there and the rest of the archive was not analyzed.".into(),
            );
        }
        if collector.stream_cap_hit {
            scan_limits.push(
                "The archive expanded past the scanner's decompression budget; scanning stopped early and the rest was not analyzed.".into(),
            );
        }
        // A PAX/GNU extended header that could not be fully parsed means the
        // following member could not be framed or classified safely. Parsing
        // stops before it and the scan cannot be presented as complete.
        if collector.meta_malformed > 0 {
            scan_limits.push(format!(
                "{} archive metadata header(s) could not be read safely; scanning stopped before the affected files.",
                collector.meta_malformed
            ));
        }
        if collector.malformed_paths > 0 {
            scan_limits.push(format!(
                "{} archive member path(s) were absolute, contained ambiguous components, or were not valid UTF-8; scanning stopped before classifying the affected files.",
                collector.malformed_paths
            ));
        }
        if findings_capped {
            scan_limits.push(format!(
                "The scan produced more than {MAX_FINDINGS} findings; the excess was not recorded."
            ));
        }
        // A raw tar that stops before its end-of-archive marker may have been
        // truncated in transit; whatever followed the cut-off was never seen,
        // so the scan must not read as complete. Only flagged when the stream
        // parsed as a tar at all - for arbitrary non-archive bytes the
        // "doesn't look like a sysdiagnose" verdict is the honest one.
        // (A truncated .tar.gz already fails hard at gzip finish above.)
        if !collector.terminated_cleanly() && (collector.entries > 0 || !collector.files.is_empty())
        {
            scan_limits.push(
                "The archive ended before its end-of-archive marker, so it may be incomplete; anything after the cut-off was not analyzed.".into(),
            );
        }
        // File-system indicators that are not process-observable remain
        // indexed for exact positive matches, but they do not establish
        // negative-result coverage. A positive match remains decisive; only
        // a no-match process scan with no policy-accepted observable indicators must
        // fail closed. Gate on recognizable artifacts so arbitrary input still
        // reads as invalid rather than inconclusive.
        let has_indicator_match = findings.iter().any(|f| f.severity == Severity::Match);
        if self.db.applicable_total() == 0
            && !has_indicator_match
            && (!collector.files.is_empty() || unified_seen)
        {
            scan_limits.push(
                "No process-observable indicators accepted by the negative-coverage policy were loaded, so a no-match process scan cannot provide a conclusive negative result.".into(),
            );
        }
        // Paired-device diagnostics and process-free phone metadata are
        // supplemental inputs. Without at least one primary iPhone surface
        // capable of yielding process evidence, a no-match result would be
        // vacuous and must not be presented as clear.
        let primary_process_surface_seen = found.contains(&ArtifactKind::ShutdownLog)
            || found.contains(&ArtifactKind::PsListing)
            || unified_examined
            || primary_crash_process_bearing;
        if !primary_process_surface_seen
            && (found.contains(&ArtifactKind::PairedCrashLog) || primary_metadata_only_seen)
        {
            scan_limits.push(
                "No primary process-bearing iPhone detection surface was available. Paired-device and metadata-only diagnostic reports are supplemental, so Trace cannot produce a clear phone result from them alone.".into(),
            );
        }

        // The verdict is decided here, in one place, from everything above.
        // Consumers render it; they never re-derive safety semantics.
        let has = |sev: Severity| findings.iter().any(|f| f.severity == sev);
        let verdict = if has_indicator_match {
            Verdict::Match
        } else if has(Severity::Suspicious) {
            Verdict::Suspicious
        } else if !scan_limits.is_empty() {
            Verdict::Inconclusive
        } else if collector.files.is_empty() && !unified_seen {
            Verdict::Invalid
        } else {
            Verdict::Clear
        };

        // Machine-readable completeness, derived from the same facts as the
        // verdict. A surface is partial when any of its artifacts parsed
        // less than fully; global limits are covered by `complete`.
        let missing_kinds: std::collections::HashSet<&str> =
            missing_artifacts.iter().map(|m| m.kind.as_str()).collect();
        // A kind whose files were partly or wholly dropped at a retention
        // cap is not fully examined even if some copies parsed cleanly.
        let dropped_kind_names: std::collections::HashSet<&str> = collector
            .dropped_kinds
            .iter()
            .filter_map(|k| match k {
                ArtifactKind::ShutdownLog => Some("shutdown_log"),
                ArtifactKind::CrashLog => Some("crash_log"),
                ArtifactKind::PsListing => Some("ps_listing"),
                // Paired reports are supplemental. Dropping one degrades the
                // overall scan through the global limit, not the phone's
                // primary crash-report surface.
                ArtifactKind::PairedCrashLog => None,
            })
            .collect();
        let surfaces: Vec<SurfaceState> =
            ["shutdown_log", "crash_log", "ps_listing", "unified_log"]
                .into_iter()
                .map(|kind| SurfaceState {
                    kind,
                    state: if missing_kinds.contains(kind) {
                        "absent"
                    } else if dropped_kind_names.contains(kind)
                        || (kind == "crash_log" && primary_crash_degraded)
                        || (kind != "crash_log"
                            && artifacts
                                .iter()
                                .any(|a| a.kind == kind && a.status != "parsed"))
                    {
                        "partial"
                    } else {
                        "complete"
                    },
                })
                .collect();
        // Presence and examination differ when a surface was seen but every
        // file was dropped or skipped at a safety cap. Count only primary
        // surfaces for which at least one file reached its parser.
        let surfaces_examined = [
            found.contains(&ArtifactKind::ShutdownLog),
            primary_crash_process_bearing,
            found.contains(&ArtifactKind::PsListing),
            unified_examined,
        ]
        .into_iter()
        .filter(|examined| *examined)
        .count();
        let assurance = Assurance {
            // Input that was never recognizably a sysdiagnose was not
            // "completely processed" in any sense a consumer should rely on.
            complete: scan_limits.is_empty() && verdict != Verdict::Invalid,
            surfaces_total: surfaces.len(),
            surfaces,
            surfaces_examined,
        };

        // Coverage is per scan: only surfaces actually present are listed as
        // examined, so the report cannot claim a missing surface was read.
        let mut examined: Vec<&'static str> = Vec::new();
        if found.contains(&ArtifactKind::ShutdownLog) {
            examined.push("shutdown.log (and rotated shutdown.N.log) - processes that delayed device shutdown, across reboots");
        }
        if primary_crash_process_bearing {
            examined.push("iOS crash and diagnostic reports (crashes_and_spins/*.ips) - target process names/paths and process inventories where the format contains them");
        }
        if found.contains(&ArtifactKind::PairedCrashLog) {
            examined.push("Paired-device crash and diagnostic reports (logs/ProxiedDevice*/*.ips) - process identities and inventories where the format contains them; metadata-only reports provide no process evidence, and none count as phone crash-report coverage");
        }
        if found.contains(&ArtifactKind::PsListing) {
            examined.push(
                "Process listings (ps.txt, ps_thread.txt) - processes running at capture time",
            );
        }
        if unified_examined {
            examined.push("Unified system logs (system_logs.logarchive) - process identities represented in parsed catalog data (log message contents are not read, and no precise time window is derived)");
        }

        // Duration closes here, after parsing, matching, and assembly - the
        // expensive part of the scan, which all happens in this function.
        let duration_ms = match (&self.clock, self.scan_started) {
            (Some(clock), Some(started)) => Some((clock() - started).max(0.0) as u64),
            _ => None,
        };

        Ok(Report {
            schema_version: 4,
            tool: ToolInfo {
                name: "Trace",
                version: env!("CARGO_PKG_VERSION"),
                build_commit: option_env!("TRACE_BUILD_COMMIT").filter(|s| !s.is_empty()),
            },
            verdict,
            generated_at: self.generated_at,
            duration_ms,
            scanned_via: self.scan_meta.scanned_via,
            source_file: SourceFile {
                name: self.scan_meta.source_name,
                // The engine counted the bytes it actually hashed and parsed.
                // Producer metadata can supply the display name and route, but
                // cannot override this integrity-relevant measurement.
                size: Some(self.bytes_in),
                sha256: hex(&self.input_hash.finalize()),
            },
            device,
            indicator_sets: self.db.sets.clone(),
            indicator_provenance: self.provenance,
            artifacts,
            missing_artifacts,
            findings,
            stats: ScanStats {
                bytes_read: self.bytes_in,
                archive_entries: collector.entries,
                artifacts_found: collector.files.len(),
                total_indicators: self.db.total(),
                applicable_indicators: self.db.applicable_total(),
            },
            scan_limits,
            assurance,
            coverage: Coverage {
                examined,
                not_examined: vec![
                    "OTA update logs (logs/OTAUpdateLogs/*.ips) - an undocumented restore-time text format, not the crash-report schema, so their contents are not checked",
                    "File-system presence of file indicators - a sysdiagnose has no filesystem listing. Safe file-name and file-path indicators remain available for exact positive matches against observed process identities, but only process-image paths accepted by this build's negative-coverage policy contribute to a conclusive no-match process scan (with Apple's /var, /tmp, and /etc aliases resolved to /private/... for comparison)",
                    "Unified log message contents - domain and URL indicators inside log text are not checked",
                    "Safari browsing history - lives in device backups, where most domain indicators would be checked",
                    "SMS/iMessage link payloads - device backups only",
                    "Per-process network usage (DataUsage) - device backups only",
                    "Installed apps and configuration profiles - device backups only",
                ],
                note: "Domain, URL, email and other network indicators in the loaded sets cannot be checked against sysdiagnose artifacts. Process-name indicators and process-image paths accepted by this build's negative-coverage policy establish limited negative coverage over observed process identities. Other safe file indicators remain indexed for exact positive matches, but their absence from process observations cannot establish file-system absence. Apple's /var, /tmp, and /etc aliases are resolved to /private/... for path comparison, and a directory-valued path indicator matches observed descendants of that directory. A result with no matches means these artifacts contained no known traces - it does not examine everything, and it cannot prove a device is clean.",
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tar_stream::test_util;
    use flate2::write::GzEncoder;
    use flate2::Compression;

    const PEGASUS_MINI: &str = r#"{"objects":[
        {"type":"malware","name":"Pegasus"},
        {"type":"indicator","pattern":"[process:name='bh']"},
        {"type":"indicator","pattern":"[domain-name:value='bad.example.com']"}
    ]}"#;

    fn build_archive(infected: bool) -> Vec<u8> {
        let shutdown = if infected {
            "After 0.1s, remaining client pid: 2143 (/private/var/db/com.apple.xpc.roleaccountd.staging/bh)\n"
        } else {
            "After 0.1s, remaining client pid: 155 (/usr/libexec/nfcd)\n"
        };
        let ps = "USER   PID COMMAND\nroot     1 /sbin/launchd\n";
        let crash = r#"{"name":"MobileSafari","bug_type":"309","os_version":"iPhone OS 17.2.1 (21C66)"}
{"procName":"MobileSafari","procPath":"/Applications/MobileSafari.app/MobileSafari"}"#;

        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry("sysdiagnose_t/ps.txt", ps.as_bytes()));
        a.extend_from_slice(&test_util::pax_entry(
            "sysdiagnose_t/system_logs.logarchive/Extra/shutdown.log",
            shutdown.as_bytes(),
        ));
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/crashes_and_spins/MobileSafari-2026-07-01.ips",
            crash.as_bytes(),
        ));
        test_util::finish(a)
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn unspecified_indicator_provenance_is_unknown() {
        let mut engine = Engine::new();
        engine.load_stix("local-test", PEGASUS_MINI).unwrap();
        assert_eq!(engine.provenance[0].loaded_from, "unknown");
    }

    #[test]
    fn end_to_end_infected_gz() {
        let gz = gzip(&build_archive(true));
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        // stream in uneven chunks
        for chunk in gz.chunks(1000) {
            engine.push(chunk).unwrap();
        }
        let report = engine.finish().unwrap();
        assert_eq!(report.verdict, Verdict::Match);
        assert_eq!(report.stats.artifacts_found, 3);
        assert_eq!(
            report.device.unwrap().os_version,
            "iPhone OS 17.2.1 (21C66)"
        );
        let match_count = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Match)
            .count();
        assert_eq!(match_count, 1, "expected exactly one IOC match");
        // findings sorted most-severe first
        assert_eq!(report.findings[0].severity, Severity::Match);
        // applicable-indicator accounting excludes the domain
        assert_eq!(report.stats.total_indicators, 2);
        assert_eq!(report.stats.applicable_indicators, 1);
    }

    #[test]
    fn aliased_ioc_path_controls_verdict_and_preserves_observed_path() {
        let ps = "USER PID COMMAND\nroot 2143 /var/tmp/trace-alias\n";
        let tar = test_util::finish(test_util::entry("sysdiagnose_t/ps.txt", ps.as_bytes()));
        let mut engine = Engine::new();
        engine
            .load_stix(
                "path-alias",
                r#"{"objects":[{"type":"indicator","pattern":"[file:path='/private/var/tmp/trace-alias']"}]}"#,
            )
            .unwrap();
        engine.push(&tar).unwrap();

        let report = engine.finish().unwrap();
        assert_eq!(report.verdict, Verdict::Match);
        assert_eq!(report.stats.applicable_indicators, 0);
        assert!(report.scan_limits.is_empty());
        let matched = report
            .findings
            .iter()
            .find(|finding| finding.severity == Severity::Match)
            .expect("the aliased path must produce an IOC finding");
        assert_eq!(matched.evidence["command"], "/var/tmp/trace-alias");
        assert_eq!(
            matched.indicator.as_ref().unwrap().value,
            "/private/var/tmp/trace-alias"
        );
    }

    #[test]
    fn unreviewed_file_only_set_cannot_produce_a_clear_no_match() {
        let ps = "USER PID COMMAND\nroot 1 /usr/libexec/safe-process\n";
        let tar = test_util::finish(test_util::entry("sysdiagnose_t/ps.txt", ps.as_bytes()));
        let mut engine = Engine::new();
        engine
            .load_stix(
                "file-only",
                r#"{"objects":[{"type":"indicator","pattern":"[file:path='/private/var/tmp/unobserved-payload']"}]}"#,
            )
            .unwrap();
        engine.push(&tar).unwrap();

        let report = engine.finish().unwrap();
        assert_eq!(report.stats.total_indicators, 1);
        assert_eq!(report.stats.applicable_indicators, 0);
        assert_eq!(report.verdict, Verdict::Inconclusive);
        assert!(report.scan_limits.iter().any(|limit| {
            limit.contains("No process-observable indicators accepted by the negative-coverage policy were loaded")
        }));
    }

    #[test]
    fn unified_pid_evidence_sampling_does_not_degrade_verdict() {
        let tracev3 = crate::unified_log::test_pid_retention_cap_tracev3();
        let uuidtext = crate::unified_log::test_uuidtext("/usr/libexec/safe-process");
        let uuidtext_path = format!("root/system_logs.logarchive/AA/{}", "A".repeat(30));
        let mut tar = Vec::new();
        tar.extend_from_slice(&test_util::entry(
            "root/system_logs.logarchive/Persist/0000000000000001.tracev3",
            &tracev3,
        ));
        tar.extend_from_slice(&test_util::entry(&uuidtext_path, &uuidtext));
        let tar = test_util::finish(tar);

        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();

        assert_eq!(report.verdict, Verdict::Clear);
        assert!(report.scan_limits.is_empty());
        assert!(report.assurance.complete);
        let unified = report
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == "unified_log")
            .unwrap();
        assert_eq!(unified.status, "parsed");
        assert_eq!(unified.details["cap_hit"], false);
        assert_eq!(unified.details["identity_cap_hit"], false);
        assert_eq!(unified.details["pid_retention_cap_hit"], true);
        assert_eq!(unified.details["pid_observations_dropped"], 1);
        assert!(report
            .assurance
            .surfaces
            .iter()
            .any(|surface| { surface.kind == "unified_log" && surface.state == "complete" }));
    }

    #[test]
    fn gzip_detected_even_when_streamed_byte_by_byte() {
        let gz = gzip(&build_archive(true));
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        for byte in &gz {
            engine.push(std::slice::from_ref(byte)).unwrap();
        }
        let report = engine.finish().unwrap();
        assert_eq!(report.stats.artifacts_found, 3);
        assert!(report
            .findings
            .iter()
            .any(|f| f.severity == Severity::Match));
    }

    #[test]
    fn truncated_gzip_before_trailer_fails_finalization() {
        let mut gz = gzip(&build_archive(false));
        // A gzip trailer is eight bytes: CRC32 followed by the uncompressed
        // size. Removing it models an interrupted transfer after all tar and
        // DEFLATE bytes arrived, so only decoder finalization can catch it.
        gz.truncate(gz.len() - 8);

        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&gz).unwrap();

        let error = match engine.finish() {
            Ok(report) => panic!(
                "a gzip stream truncated before its trailer produced a {:?} verdict",
                report.verdict
            ),
            Err(error) => error,
        };
        assert!(error.contains("archive ended unexpectedly"), "{error}");
    }

    #[test]
    fn concatenated_gzip_members_match_single_member_scan() {
        let tar = build_archive(true);
        let split = tar.len() / 2;
        let single_member = gzip(&tar);
        let mut concatenated_members = gzip(&tar[..split]);
        concatenated_members.extend_from_slice(&gzip(&tar[split..]));

        let scan = |input: &[u8]| {
            let mut engine = Engine::new();
            engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
            for chunk in input.chunks(37) {
                engine.push(chunk).unwrap();
            }
            engine.finish().unwrap()
        };
        let single = scan(&single_member);
        let concatenated = scan(&concatenated_members);

        assert_eq!(concatenated.verdict, single.verdict);
        assert_eq!(
            concatenated.stats.archive_entries,
            single.stats.archive_entries
        );
        assert_eq!(
            concatenated.stats.artifacts_found,
            single.stats.artifacts_found
        );
        assert_eq!(
            serde_json::to_value(&concatenated.artifacts).unwrap(),
            serde_json::to_value(&single.artifacts).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&concatenated.findings).unwrap(),
            serde_json::to_value(&single.findings).unwrap()
        );
        assert_eq!(concatenated.scan_limits, single.scan_limits);
    }

    #[test]
    fn source_size_is_measured_from_scanned_bytes() {
        let tar = build_archive(false);
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.set_scan_meta(ScanMeta {
            source_name: Some("capture.tar".into()),
            source_size: Some(1),
            scanned_via: Some("native-test".into()),
        });
        for chunk in tar.chunks(113) {
            engine.push(chunk).unwrap();
        }
        let report = engine.finish().unwrap();

        assert_eq!(report.source_file.name.as_deref(), Some("capture.tar"));
        assert_eq!(report.scanned_via.as_deref(), Some("native-test"));
        assert_eq!(report.source_file.size, Some(tar.len() as u64));
        assert_eq!(report.source_file.size, Some(report.stats.bytes_read));
    }

    #[test]
    fn single_byte_input_errors_cleanly() {
        let mut engine = Engine::new();
        engine.push(&[0x1f]).unwrap();
        assert!(engine.finish().is_err());
    }

    #[test]
    fn hitting_limits_marks_scan_incomplete() {
        let mut a = Vec::new();
        for i in 0..3 {
            a.extend_from_slice(&test_util::entry(
                &format!("sysdiagnose_t/crashes_and_spins/p{i}-2026.ips"),
                b"{}\n{}",
            ));
        }
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine.limits = crate::tar_stream::Limits {
            max_retained_files: 1,
            ..Default::default()
        };
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert!(!report.scan_limits.is_empty());
        assert!(report.scan_limits[0].contains("skipped"));
        assert_eq!(report.verdict, Verdict::Inconclusive);
    }

    #[test]
    fn end_to_end_clean_raw_tar() {
        let tar = build_archive(false);
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.stats.artifacts_found, 3);
        assert!(report.findings.is_empty());
        assert_eq!(report.verdict, Verdict::Clear);
        // coverage lists exactly the surfaces that were present
        assert_eq!(report.coverage.examined.len(), 3);
        assert!(!report
            .coverage
            .examined
            .iter()
            .any(|e| e.contains("Unified system logs")));
    }

    #[test]
    fn unparsed_ps_listing_is_never_clear() {
        // An empty ps.txt parses to "unparsed"; that surface was not
        // checked, so nothing about this scan may read as "no traces found".
        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry("sysdiagnose_t/ps.txt", b""));
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.artifacts[0].status, "unparsed");
        assert_eq!(report.verdict, Verdict::Inconclusive);
        assert!(report
            .scan_limits
            .iter()
            .any(|l| l.contains("process listing")));
    }

    #[test]
    fn unparseable_crash_log_is_never_clear() {
        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/crashes_and_spins/benign-2026-07-01-120000.ips",
            b"not json at all",
        ));
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.verdict, Verdict::Inconclusive);
        assert!(report
            .scan_limits
            .iter()
            .any(|l| l.contains("diagnostic .ips")));
    }

    #[test]
    fn corrupt_tracev3_is_never_clear() {
        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/ps.txt",
            b"USER   PID COMMAND\nroot     1 /sbin/launchd\n",
        ));
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/system_logs.logarchive/Persist/0000000000000001.tracev3",
            &[0xAB; 700],
        ));
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.verdict, Verdict::Inconclusive);
        assert!(report.scan_limits.iter().any(|l| l.contains("tracev3")));
    }

    #[test]
    fn unified_only_archive_is_not_invalid() {
        // No retained artifacts, but unified-log content was seen: this is
        // an archive with data in it, not "not a sysdiagnose".
        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/system_logs.logarchive/Persist/0000000000000001.tracev3",
            &[0xAB; 700],
        ));
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_ne!(report.verdict, Verdict::Invalid);
        assert_eq!(report.verdict, Verdict::Inconclusive);
    }

    #[test]
    fn nested_or_paired_logarchive_lookalikes_do_not_supply_phone_coverage() {
        for path in [
            "sysdiagnose_t/random/system_logs.logarchive/Persist/0000000000000001.tracev3",
            "sysdiagnose_t/logs/ProxiedDevice/system_logs.logarchive/Persist/0000000000000001.tracev3",
        ] {
            let tar = test_util::finish(test_util::entry(path, &[0xAB; 700]));
            let mut engine = Engine::new();
            engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
            engine.push(&tar).unwrap();
            let report = engine.finish().unwrap();

            assert_eq!(report.verdict, Verdict::Invalid, "path: {path}");
            assert!(!report.assurance.complete, "path: {path}");
            assert_eq!(report.assurance.surfaces_examined, 0, "path: {path}");
            assert!(
                report
                    .missing_artifacts
                    .iter()
                    .any(|missing| missing.kind == "unified_log"),
                "path: {path}"
            );
            assert!(!report
                .coverage
                .examined
                .iter()
                .any(|surface| surface.starts_with("Unified system logs")));
        }
    }

    #[test]
    fn match_verdict_survives_scan_limits() {
        // An indicator match stands even when the scan was degraded: the
        // verdict must escalate, not wash out to inconclusive.
        let gz = gzip(&build_archive(true));
        let mut engine = Engine::new();
        engine.limits = crate::tar_stream::Limits {
            max_retained_files: 2, // drops the crash log, keeps the match
            ..Default::default()
        };
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&gz).unwrap();
        let report = engine.finish().unwrap();
        assert!(!report.scan_limits.is_empty());
        assert_eq!(report.verdict, Verdict::Match);
    }

    #[test]
    fn corrupt_header_mid_archive_is_inconclusive() {
        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/ps.txt",
            b"USER   PID COMMAND\nroot     1 /sbin/launchd\n",
        ));
        let mut corrupt = test_util::entry("sysdiagnose_t/other.txt", b"x");
        corrupt[0] ^= 0xFF; // invalidates the header checksum
        a.extend_from_slice(&corrupt);
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.verdict, Verdict::Inconclusive);
        assert!(report.scan_limits.iter().any(|l| l.contains("checksum")));
    }

    #[test]
    fn newest_crash_log_provides_device_os() {
        let old = br#"{"name":"a","timestamp":"2026-01-01 10:00:00.00 -0700","bug_type":"309","os_version":"iPhone OS 17.0 (21A1)"}
{"procName":"a"}"#;
        let new = br#"{"name":"b","timestamp":"2026-06-30 10:00:00.00 -0700","bug_type":"309","os_version":"iPhone OS 18.5 (22F76)"}
{"procName":"b"}"#;
        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/crashes_and_spins/a-2026-01-01-100000.ips",
            old,
        ));
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/crashes_and_spins/b-2026-06-30-100000.ips",
            new,
        ));
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        let device = report.device.unwrap();
        assert_eq!(device.os_version, "iPhone OS 18.5 (22F76)");
        assert!(device.source.contains("b-2026-06-30"));
    }

    #[test]
    fn newest_crash_log_compares_offset_aware_instants() {
        // The first timestamp looks later as a string, but is 09:30 UTC;
        // the second is 10:00 UTC and must provide the capture-nearest OS.
        let older = br#"{"name":"a","timestamp":"2026-07-01 23:30:00.00 +1400","bug_type":"309","os_version":"iPhone OS 17.0 (21A1)"}
{"procName":"a"}"#;
        let newer = br#"{"name":"b","timestamp":"2026-07-01 10:00:00.00 +0000","bug_type":"309","os_version":"iPhone OS 18.5 (22F76)"}
{"procName":"b"}"#;
        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/crashes_and_spins/a-2026-07-01-233000.ips",
            older,
        ));
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/crashes_and_spins/b-2026-07-01-100000.ips",
            newer,
        ));
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine.push(&tar).unwrap();
        let device = engine.finish().unwrap().device.unwrap();
        assert_eq!(device.os_version, "iPhone OS 18.5 (22F76)");
        assert!(device.source.contains("b-2026-07-01"));
    }

    #[test]
    fn invalid_utf8_artifact_is_partial_not_clear() {
        let mut crash = br#"{"name":"safe","bug_type":"309","os_version":"iPhone OS 18.5 (22F76)"}
{"procName":"safe","procPath":"/usr/bin/"#
            .to_vec();
        crash.push(0xff);
        crash.extend_from_slice(br#"safe"}"#);
        let tar = test_util::finish(test_util::entry(
            "sysdiagnose_t/crashes_and_spins/safe-2026.ips",
            &crash,
        ));
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        let artifact = &report.artifacts[0];
        assert_eq!(artifact.status, "parsed_partial");
        assert_eq!(artifact.details["invalid_utf8"], true);
        assert_eq!(report.verdict, Verdict::Inconclusive);
        assert!(!report.assurance.complete);
        assert_eq!(
            report
                .assurance
                .surfaces
                .iter()
                .find(|surface| surface.kind == "crash_log")
                .unwrap()
                .state,
            "partial"
        );
    }

    #[test]
    fn paired_report_is_scanned_without_substituting_for_phone_surface() {
        let watch = br#"{"name":"watchapp","timestamp":"2026-07-01 10:00:00.00 +0000","bug_type":"309","os_version":"Watch OS 11.5 (22T572)"}
{"procName":"watchapp","procPath":"/Applications/watchapp"}"#;
        let tar = test_util::finish(test_util::entry(
            "sysdiagnose_t/logs/ProxiedDevice-ABC/watchapp-2026.ips",
            watch,
        ));
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();

        assert!(report.device.is_none());
        assert_eq!(report.verdict, Verdict::Inconclusive);
        assert!(!report.assurance.complete);
        assert_eq!(report.assurance.surfaces_examined, 0);
        assert!(report
            .scan_limits
            .iter()
            .any(|limit| limit.contains("No primary process-bearing iPhone detection surface")));
        assert!(report
            .missing_artifacts
            .iter()
            .any(|missing| missing.kind == "crash_log"));
        assert_eq!(
            report
                .assurance
                .surfaces
                .iter()
                .find(|surface| surface.kind == "crash_log")
                .unwrap()
                .state,
            "absent"
        );
        assert!(report
            .coverage
            .examined
            .iter()
            .any(|line| line.starts_with("Paired-device")));
        assert!(!report
            .coverage
            .examined
            .iter()
            .any(|line| line.starts_with("iOS crash")));
        // Keep report v4's closed artifact-kind enum stable. The artifact's
        // device scope is explicit in details and coverage.
        assert_eq!(report.artifacts[0].kind, "crash_log");
        assert_eq!(report.artifacts[0].details["paired_device"], true);
    }

    #[test]
    fn metadata_only_phone_report_cannot_produce_clear_or_crash_coverage() {
        let siri = br#"{"bug_type":"313","timestamp":"2026-07-08 13:22:15.00 -0700","os_version":"iPhone OS 26.5.2 (23F84)"}
{"agent":"opaque","country_code":"US","session_start":123,"user_guid":"opaque"}"#;
        let tar = test_util::finish(test_util::entry(
            "sysdiagnose_t/crashes_and_spins/SiriSearchFeedback-2026.ips",
            siri,
        ));
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();

        assert_eq!(report.verdict, Verdict::Inconclusive);
        assert!(!report.assurance.complete);
        assert_eq!(report.assurance.surfaces_examined, 0);
        assert_eq!(report.artifacts[0].status, "parsed");
        assert_eq!(report.artifacts[0].details["processes"], 0);
        assert_eq!(report.artifacts[0].details["detection_relevant"], false);
        assert!(report
            .scan_limits
            .iter()
            .any(|limit| limit.contains("No primary process-bearing iPhone detection surface")));
        let missing = report
            .missing_artifacts
            .iter()
            .find(|missing| missing.kind == "crash_log")
            .unwrap();
        assert!(missing.note.contains("Metadata-only reports"));
        assert_eq!(
            report
                .assurance
                .surfaces
                .iter()
                .find(|surface| surface.kind == "crash_log")
                .unwrap()
                .state,
            "absent"
        );
        assert!(!report
            .coverage
            .examined
            .iter()
            .any(|line| line.starts_with("iOS crash")));
    }

    #[test]
    fn paired_metadata_only_coverage_does_not_claim_process_evidence() {
        let siri = br#"{"bug_type":"313"}
{"agent":"opaque","country_code":"US","session_start":123,"user_guid":"opaque"}"#;
        let tar = test_util::finish(test_util::entry(
            "sysdiagnose_t/logs/ProxiedDevice/SiriSearchFeedback-2026.ips",
            siri,
        ));
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();

        assert_eq!(report.verdict, Verdict::Inconclusive);
        assert_eq!(report.artifacts[0].details["detection_relevant"], false);
        let paired_coverage = report
            .coverage
            .examined
            .iter()
            .find(|line| line.starts_with("Paired-device crash"))
            .unwrap();
        assert!(paired_coverage.contains("where the format contains them"));
        assert!(paired_coverage.contains("metadata-only reports provide no process evidence"));
    }

    #[test]
    fn metadata_only_report_does_not_degrade_process_bearing_phone_crash_surface() {
        let siri = br#"{"bug_type":"313"}
{"agent":"opaque","country_code":"US","session_start":123,"user_guid":"opaque"}"#;
        let crash = br#"{"name":"safe","bug_type":"309"}
{"procName":"safe","procPath":"/usr/libexec/safe"}"#;
        let mut archive = test_util::entry(
            "sysdiagnose_t/crashes_and_spins/SiriSearchFeedback-2026.ips",
            siri,
        );
        archive.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/crashes_and_spins/safe-2026.ips",
            crash,
        ));
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&test_util::finish(archive)).unwrap();
        let report = engine.finish().unwrap();

        assert_eq!(report.verdict, Verdict::Clear);
        assert!(report.assurance.complete);
        assert_eq!(report.assurance.surfaces_examined, 1);
        assert!(!report
            .missing_artifacts
            .iter()
            .any(|missing| missing.kind == "crash_log"));
        assert_eq!(
            report
                .assurance
                .surfaces
                .iter()
                .find(|surface| surface.kind == "crash_log")
                .unwrap()
                .state,
            "complete"
        );
        assert!(report
            .coverage
            .examined
            .iter()
            .any(|line| line.starts_with("iOS crash")));
    }

    #[test]
    fn phone_metadata_and_surface_are_independent_of_newer_paired_report() {
        let phone = br#"{"name":"phoneapp","timestamp":"2026-01-01 10:00:00.00 +0000","bug_type":"309","os_version":"iPhone OS 18.0 (22A1)"}
{"procName":"phoneapp","procPath":"/Applications/phoneapp"}"#;
        let watch = br#"{"name":"watchapp","timestamp":"2026-07-01 10:00:00.00 +0000","bug_type":"309","os_version":"Watch OS 11.5 (22T572)"}
{"procName":"watchapp","procPath":"/Applications/watchapp"}"#;
        let mut archive =
            test_util::entry("sysdiagnose_t/crashes_and_spins/phoneapp-2026.ips", phone);
        archive.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/logs/ProxiedDevice-ABC/watchapp-2026.ips",
            watch,
        ));
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&test_util::finish(archive)).unwrap();
        let report = engine.finish().unwrap();

        assert_eq!(report.device.unwrap().os_version, "iPhone OS 18.0 (22A1)");
        assert_eq!(
            report
                .assurance
                .surfaces
                .iter()
                .find(|surface| surface.kind == "crash_log")
                .unwrap()
                .state,
            "complete"
        );
        assert_eq!(report.coverage.examined.len(), 2);
    }

    #[test]
    fn paired_parse_failure_does_not_degrade_complete_phone_surface() {
        let phone = br#"{"name":"phoneapp","bug_type":"309","os_version":"iPhone OS 18.0 (22A1)"}
{"procName":"phoneapp","procPath":"/Applications/phoneapp"}"#;
        let mut archive =
            test_util::entry("sysdiagnose_t/crashes_and_spins/phoneapp-2026.ips", phone);
        archive.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/logs/ProxiedDevice-ABC/broken-2026.ips",
            b"not json",
        ));
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&test_util::finish(archive)).unwrap();
        let report = engine.finish().unwrap();

        assert_eq!(report.verdict, Verdict::Inconclusive);
        assert_eq!(
            report
                .assurance
                .surfaces
                .iter()
                .find(|surface| surface.kind == "crash_log")
                .unwrap()
                .state,
            "complete"
        );
    }

    #[test]
    fn truncated_tracev3_is_present_but_not_claimed_as_examined() {
        let tar = test_util::finish(test_util::entry(
            "sysdiagnose_t/system_logs.logarchive/Persist/0000000000000001.tracev3",
            b"XX",
        ));
        let mut engine = Engine::new();
        engine.limits = Limits {
            file_cap: 1,
            ..Limits::default()
        };
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();

        assert_eq!(report.verdict, Verdict::Inconclusive);
        assert!(!report
            .missing_artifacts
            .iter()
            .any(|missing| missing.kind == "unified_log"));
        let unified = report
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == "unified_log")
            .unwrap();
        assert_eq!(unified.status, "parsed_partial");
        assert_eq!(unified.details["tracev3_truncated"], 1);
        assert_eq!(
            report
                .assurance
                .surfaces
                .iter()
                .find(|surface| surface.kind == "unified_log")
                .unwrap()
                .state,
            "partial"
        );
        assert_eq!(report.assurance.surfaces_examined, 0);
        assert!(!report
            .coverage
            .examined
            .iter()
            .any(|line| line.starts_with("Unified system logs")));
    }

    #[test]
    fn truncated_retained_artifact_uses_the_disclosed_status() {
        let tar = test_util::finish(test_util::entry(
            "sysdiagnose_t/ps.txt",
            b"USER PID COMMAND\nroot 1 /sbin/launchd\n",
        ));
        let mut engine = Engine::new();
        engine.limits = Limits {
            file_cap: 12,
            ..Limits::default()
        };
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();

        assert_eq!(report.verdict, Verdict::Inconclusive);
        assert_eq!(report.artifacts[0].status, "truncated");
        assert!(!report.assurance.complete);
        assert!(report
            .scan_limits
            .iter()
            .any(|limit| limit.contains("exceeded size limits")));
    }

    #[test]
    fn empty_tracev3_is_not_erased_from_surface_health() {
        let tar = test_util::finish(test_util::entry(
            "sysdiagnose_t/system_logs.logarchive/Persist/0000000000000001.tracev3",
            b"",
        ));
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.verdict, Verdict::Inconclusive);
        assert!(!report
            .missing_artifacts
            .iter()
            .any(|missing| missing.kind == "unified_log"));
        assert!(report
            .scan_limits
            .iter()
            .any(|limit| limit.contains("no process inventory")));
        assert!(report
            .coverage
            .examined
            .iter()
            .any(|line| line.starts_with("Unified system logs")));
    }

    #[test]
    fn partially_parsed_ps_listing_is_never_clear() {
        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/ps.txt",
            b"USER PID COMMAND\nroot   1 /sbin/launchd\nshort\n",
        ));
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.artifacts[0].status, "parsed_partial");
        assert_eq!(report.verdict, Verdict::Inconclusive);
        assert!(!report.assurance.complete);
        assert!(report
            .scan_limits
            .iter()
            .any(|limit| limit.contains("process listing")));
    }

    #[test]
    fn ps_thread_full_path_indicator_controls_verdict() {
        let ps_thread = b"USER             PID   TT   %CPU STAT PRI     STIME     UTIME COMMAND  PPID        F %MEM PRI NI      VSZ    RSS WCHAN  STARTED      TIME COMMAND\nroot               1   ??    0.0 S    31T   0:00.00   0:00.00 /sbin/l     0   104004  0.7 31T  0 407931472  13728 -       1:25PM   0:02.37 /sbin/launchd\n                   1         0.0 S    37T   0:00.00   0:00.08             0   104004  0.7 37T  0 407931472  13728 -       1:25PM   0:02.37 \n";
        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry("sysdiagnose_t/ps_thread.txt", ps_thread));
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine
            .load_stix(
                "path-mini",
                r#"{"objects":[{"type":"indicator","pattern":"[file:path='/sbin/launchd']"}]}"#,
            )
            .unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.verdict, Verdict::Match);
        assert_eq!(report.artifacts[0].status, "parsed");
        assert_eq!(report.artifacts[0].details["processes"], 1);
        assert!(report.scan_limits.is_empty());
    }

    #[test]
    fn ps_thread_without_full_command_column_is_never_clear() {
        let ps_thread = b"USER   PID COMMAND\nroot     1 /sbin/launchd\n";
        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry("sysdiagnose_t/ps_thread.txt", ps_thread));
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.artifacts[0].status, "unparsed");
        assert_eq!(report.verdict, Verdict::Inconclusive);
        assert!(!report.assurance.complete);
        assert!(report
            .scan_limits
            .iter()
            .any(|limit| limit.contains("process listing")));
    }

    #[test]
    fn parsed_ps_txt_covers_header_only_ps_thread() {
        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/ps.txt",
            b"USER PID COMMAND\nroot   1 /sbin/launchd\n",
        ));
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/ps_thread.txt",
            b"USER PID COMMAND PPID TIME COMMAND\n",
        ));
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.verdict, Verdict::Clear);
        assert!(report.scan_limits.is_empty());
        assert_eq!(report.artifacts[0].status, "parsed");
        assert_eq!(report.artifacts[1].status, "parsed");
        assert_eq!(report.artifacts[1].details["processes"], 0);
    }

    #[test]
    fn header_only_ps_thread_cannot_be_the_only_process_inventory() {
        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/ps_thread.txt",
            b"USER PID COMMAND PPID TIME COMMAND\n",
        ));
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.verdict, Verdict::Inconclusive);
        assert!(!report.assurance.complete);
        assert!(report
            .scan_limits
            .iter()
            .any(|limit| limit.contains("no process rows")));
    }

    #[test]
    fn artifacts_with_no_loaded_indicators_are_never_clear() {
        // "No known spyware traces found" with zero indicators loaded would
        // be vacuously true. The browser always loads the bundled sets;
        // this guards the native harness and embedders.
        let tar = build_archive(false);
        let mut engine = Engine::new(); // note: no load_stix
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.stats.applicable_indicators, 0);
        assert_eq!(report.verdict, Verdict::Inconclusive);
        assert!(report.scan_limits.iter().any(|l| l.contains("indicators")));
        // garbage input stays "not a sysdiagnose" even with no indicators
        let mut engine = Engine::new();
        engine.push(&[0x50, 0x4b, 0x03, 0x04]).unwrap();
        engine.push(&[0xABu8; 2048]).unwrap();
        assert_eq!(engine.finish().unwrap().verdict, Verdict::Invalid);
    }

    #[test]
    fn empty_shutdown_log_is_never_clear() {
        // An empty (or unrecognizable) shutdown.log has zero entries just
        // like a garbage file; it must read as an unchecked surface, not
        // as a normally parsed one.
        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/system_logs.logarchive/Extra/shutdown.log",
            b"",
        ));
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.artifacts[0].status, "unparsed");
        assert_eq!(report.verdict, Verdict::Inconclusive);
        assert!(report
            .scan_limits
            .iter()
            .any(|l| l.contains("shutdown log")));
    }

    #[test]
    fn header_only_crash_log_is_never_clear() {
        // A parseable one-line header with a malformed body means the
        // substantive document (procPath, parentProc, panicString) was
        // never checked.
        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/crashes_and_spins/app-2026-07-01-120000.ips",
            br#"{"name":"app","bug_type":"309","os_version":"iPhone OS 17.2.1 (21C66)"}
this body is not json"#,
        ));
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.artifacts[0].status, "parsed_partial");
        assert_eq!(report.verdict, Verdict::Inconclusive);
        assert!(report
            .scan_limits
            .iter()
            .any(|l| l.contains("diagnostic .ips")));
    }

    #[test]
    fn ips_inventory_reaches_the_engine_verdict() {
        let jetsam = br#"{"bug_type":"298"}
{"processes":[{"name":"launchd","pid":1},{"name":"bh","pid":2143}]}"#;
        let siri = br#"{"bug_type":"313"}
{"agent":"opaque","country_code":"US","session_start":123,"user_guid":"opaque"}"#;
        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/crashes_and_spins/JetsamEvent-2026.ips",
            jetsam,
        ));
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/crashes_and_spins/SiriSearchFeedback-2026.ips",
            siri,
        ));
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.verdict, Verdict::Match);
        assert!(report
            .artifacts
            .iter()
            .all(|artifact| artifact.status == "parsed"));
        assert!(report.scan_limits.is_empty());
        assert!(report.findings.iter().any(|finding| {
            finding.severity == Severity::Match && finding.evidence["pid"] == 2143
        }));
    }

    #[test]
    fn malformed_ips_inventory_is_never_clear() {
        let jetsam = br#"{"bug_type":"298"}
{"processes":[{"name":"launchd","pid":1},{"pid":2143}]}"#;
        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/crashes_and_spins/JetsamEvent-2026.ips",
            jetsam,
        ));
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.artifacts[0].status, "parsed_partial");
        assert_eq!(report.verdict, Verdict::Inconclusive);
        assert!(!report.assurance.complete);
        assert!(report
            .scan_limits
            .iter()
            .any(|limit| limit.contains("diagnostic .ips")));
    }

    #[test]
    fn capped_ips_inventory_has_an_explicit_scan_limit() {
        let processes: Vec<serde_json::Value> = (0..=crash_log::MAX_CRASH_CANDIDATES)
            .map(|index| serde_json::json!({"name": format!("process-{index}"), "pid": index}))
            .collect();
        let jetsam = format!(
            "{{\"bug_type\":\"298\"}}\n{}",
            serde_json::json!({"bug_type": "298", "processes": processes})
        );
        let tar = test_util::finish(test_util::entry(
            "sysdiagnose_t/crashes_and_spins/JetsamEvent-2026.ips",
            jetsam.as_bytes(),
        ));
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();

        assert_eq!(report.verdict, Verdict::Inconclusive);
        assert_eq!(report.artifacts[0].status, "parsed_partial");
        assert_eq!(report.artifacts[0].details["candidate_cap_hit"], true);
        assert!(report
            .scan_limits
            .iter()
            .any(|limit| limit.contains("candidate safety cap")));
    }

    #[test]
    fn partial_disk_writes_report_keeps_match_and_scan_limit() {
        let report = br#"{"app_name":"bh","name":"bh","bug_type":"145"}
Report Version: malformed
Command: bh
Path: /private/var/db/com.apple.xpc.roleaccountd.staging/bh
PID: 2143
Event: disk writes
Steps: 20
"#;
        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/crashes_and_spins/bh.diskwrites_resource-2026.ips",
            report,
        ));
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine
            .load_stix(
                "path-ioc",
                r#"{"objects":[{"type":"indicator","pattern":"[file:path='/private/var/db/com.apple.xpc.roleaccountd.staging/bh']"}]}"#,
            )
            .unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.artifacts[0].status, "parsed_partial");
        assert_eq!(report.verdict, Verdict::Match);
        assert!(!report.assurance.complete);
        assert!(report
            .scan_limits
            .iter()
            .any(|limit| limit.contains("diagnostic .ips")));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.severity == Severity::Match));
    }

    #[test]
    fn findings_cap_is_enforced_and_surfaces() {
        // A crafted ps.txt whose every line raises a heuristic must not
        // allocate unbounded findings, and the cap must force the verdict
        // away from clear.
        let mut ps = String::from("USER PID COMMAND\n");
        for i in 0..(MAX_FINDINGS + 10) {
            ps.push_str(&format!("root {:>3} /private/var/tmp/x{i}\n", i % 999));
        }
        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry("sysdiagnose_t/ps.txt", ps.as_bytes()));
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.findings.len(), MAX_FINDINGS);
        assert_eq!(report.verdict, Verdict::Inconclusive);
        assert!(report.scan_limits.iter().any(|l| l.contains("findings")));
    }

    #[test]
    fn match_survives_findings_flood() {
        // Retention is severity-aware: an exact IOC match arriving after
        // thousands of crafted informational findings must evict one of
        // them, survive, and control the verdict - a note flood must never
        // suppress a real detection.
        let mut ps = String::from("USER PID COMMAND\n");
        for i in 0..(MAX_FINDINGS + 10) {
            ps.push_str(&format!("root {:>3} /private/var/tmp/x{i}\n", i % 999));
        }
        // The match candidate comes last, well past the cap.
        ps.push_str("root 2143 /private/var/db/com.apple.xpc.roleaccountd.staging/bh\n");
        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry("sysdiagnose_t/ps.txt", ps.as_bytes()));
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.findings.len(), MAX_FINDINGS);
        assert_eq!(report.verdict, Verdict::Match);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.severity == Severity::Match),
            "the IOC match must survive the informational flood"
        );
        assert!(report.scan_limits.iter().any(|l| l.contains("findings")));
    }

    #[test]
    fn uuidtext_only_input_is_not_a_unified_surface() {
        // uuidtext files are support data (UUID -> path); alone they carry
        // no process activity to check, so they must not count as a seen
        // unified-log surface - and an archive with nothing else must read
        // as "not a sysdiagnose", never clear.
        // Minimal valid uuidtext: magic 0x66778899, version 2.1, one entry.
        let mut ut: Vec<u8> = Vec::new();
        ut.extend_from_slice(&0x66778899u32.to_le_bytes());
        ut.extend_from_slice(&2u32.to_le_bytes());
        ut.extend_from_slice(&1u32.to_le_bytes());
        ut.extend_from_slice(&1u32.to_le_bytes()); // one entry
        ut.extend_from_slice(&0u32.to_le_bytes()); // range offset
        ut.extend_from_slice(&8u32.to_le_bytes()); // range size
        ut.extend_from_slice(b"/bin/x\0\0");
        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/system_logs.logarchive/AB/CDEF01234567890123456789012345",
            &ut,
        ));
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_ne!(report.verdict, Verdict::Clear);
        assert!(
            report
                .missing_artifacts
                .iter()
                .any(|m| m.kind == "unified_log"),
            "uuidtext alone must leave the unified surface missing"
        );
        assert!(!report.assurance.complete);
    }

    #[test]
    fn header_only_ps_is_never_clear() {
        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/ps.txt",
            b"USER   PID COMMAND\n",
        ));
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.artifacts[0].status, "unparsed");
        assert_eq!(report.verdict, Verdict::Inconclusive);
        assert!(!report.assurance.complete);
    }

    #[test]
    fn semantically_empty_crash_is_never_clear() {
        // "{}" header and body are syntactically valid JSON that name no
        // crashing process; nothing was actually checked.
        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/crashes_and_spins/x.ips",
            b"{}\n{}",
        ));
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.artifacts[0].status, "parsed_partial");
        assert_eq!(report.verdict, Verdict::Inconclusive);
    }

    #[test]
    fn duration_covers_finish_work() {
        // The injected clock is read once at the first byte and once after
        // report assembly, so the duration includes everything finish()
        // does. A fake stepping clock makes that deterministic.
        let ticks = std::rc::Rc::new(std::cell::Cell::new(0.0f64));
        let t = ticks.clone();
        let mut engine = Engine::new();
        engine.set_clock(Box::new(move || {
            t.set(t.get() + 100.0);
            t.get()
        }));
        engine.push(&build_archive(false)).unwrap();
        let report = engine.finish().unwrap();
        // first read: 100 (first push); second read: 200 (end of finish)
        assert_eq!(report.duration_ms, Some(100));
        assert!(ticks.get() >= 200.0);
    }

    #[test]
    fn assurance_complete_is_false_for_invalid_input() {
        let mut engine = Engine::new();
        engine.push(&[0x50, 0x4b, 0x03, 0x04]).unwrap(); // zip magic
        engine.push(&[0xABu8; 2048]).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.verdict, Verdict::Invalid);
        assert!(!report.assurance.complete);
        assert!(report.scan_limits.is_empty());
    }

    #[test]
    fn missing_artifacts_are_reported() {
        let mut a = Vec::new();
        a.extend_from_slice(&test_util::entry(
            "sysdiagnose_t/ps.txt",
            b"USER   PID COMMAND\nroot     1 /sbin/launchd\n",
        ));
        let tar = test_util::finish(a);
        let mut engine = Engine::new();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.stats.artifacts_found, 1);
        let missing: Vec<&str> = report
            .missing_artifacts
            .iter()
            .map(|m| m.kind.as_str())
            .collect();
        assert_eq!(missing, vec!["shutdown_log", "crash_log", "unified_log"]);
    }

    #[test]
    fn truncated_raw_tar_is_marked_incomplete() {
        // Clean build minus the end-of-archive marker and half the last
        // entry: what a cut-off transfer of a raw tar looks like.
        let full = build_archive(false);
        let mut engine = Engine::new();
        engine.push(&full[..full.len() - 1600]).unwrap();
        let report = engine.finish().unwrap();
        assert!(
            report
                .scan_limits
                .iter()
                .any(|l| l.contains("end-of-archive")),
            "a truncated raw tar must surface as an incomplete scan"
        );
        assert_eq!(report.verdict, Verdict::Inconclusive);
    }

    #[test]
    fn non_archive_bytes_do_not_read_as_truncated() {
        // Arbitrary non-tar bytes must stay on the "not a sysdiagnose"
        // path (zero artifacts, no scan limits), not become "inconclusive".
        let mut engine = Engine::new();
        engine.push(&[0x50, 0x4b, 0x03, 0x04]).unwrap(); // zip magic
        engine.push(&[0xABu8; 2048]).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.stats.artifacts_found, 0);
        assert!(report.scan_limits.is_empty());
        assert_eq!(report.verdict, Verdict::Invalid);
    }

    #[test]
    fn garbage_input_reports_error_or_empty() {
        let mut engine = Engine::new();
        // gzip magic but corrupt body → error at push or finish
        let mut junk = vec![0x1f, 0x8b];
        junk.extend_from_slice(&[0u8; 100]);
        let pushed = engine.push(&junk);
        if pushed.is_ok() {
            assert!(engine.finish().is_err());
        }
    }
}
