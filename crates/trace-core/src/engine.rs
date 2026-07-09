//! Plain-Rust engine behind the WASM `Scanner`: accepts streamed archive
//! bytes, auto-detects gzip vs raw tar, and assembles the final report.

use crate::ioc::{IocDb, SetStats};
use crate::report::*;
use crate::tar_stream::{ArtifactKind, Limits, TarCollector};
use crate::{crash_log, ps, shutdown_log};
use flate2::write::GzDecoder;
use std::io::Write;

enum Sink {
    Gz(GzDecoder<TarCollector>),
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
        }
    }

    pub fn load_stix(&mut self, set_name: &str, json: &str) -> Result<SetStats, String> {
        self.db.load_stix(set_name, json)
    }

    pub fn push(&mut self, chunk: &[u8]) -> Result<(), String> {
        if chunk.is_empty() {
            return Ok(());
        }
        self.bytes_in += chunk.len() as u64;
        if self.sink.is_none() {
            self.prelude.extend_from_slice(chunk);
            if self.prelude.len() < 2 {
                return Ok(());
            }
            let collector = TarCollector::with_limits(self.limits);
            let is_gz = self.prelude[0] == 0x1f && self.prelude[1] == 0x8b;
            let mut sink = if is_gz {
                Sink::Gz(GzDecoder::new(collector))
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

        for f in &collector.files {
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
                ArtifactKind::CrashLog => {
                    let (a, d) = crash_log::analyze(&f.path, &text, &self.db, &mut findings);
                    artifacts.push(a);
                    // Prefer the newest crash: an old crash log can predate
                    // an OS upgrade and misstate the capture-time OS.
                    if let Some(d) = d {
                        if device
                            .as_ref()
                            .is_none_or(|cur| d.timestamp > cur.timestamp)
                        {
                            device = Some(d);
                        }
                    }
                }
                ArtifactKind::PsListing => {
                    artifacts.push(ps::analyze(&f.path, &text, &self.db, &mut findings));
                }
            }
            if f.truncated {
                if let Some(last) = artifacts.last_mut() {
                    last.status = "truncated".into();
                }
            }
        }

        // Unified logs were consumed during streaming; reduce them to
        // findings and a summary now that the whole archive has been seen.
        // Health counters are captured first: parse failures must reach the
        // verdict, not just the artifact details.
        let unified = std::mem::take(&mut collector.unified);
        let unified_truncated = unified.truncated_files;
        let unified_seen = unified.saw_content();
        let tracev3_files = unified.tracev3_files;
        let tracev3_failures = unified.tracev3_failures;
        let uuidtext_files = unified.uuidtext_files;
        let uuidtext_failures = unified.uuidtext_failures;
        let unified_cap_hit = unified.cap_hit;
        if let Some(summary) = unified.finalize(&self.db, &mut findings) {
            artifacts.push(summary);
        }

        let findings_capped = findings.capped;
        let mut findings = findings.into_vec();
        findings.sort_by_key(|f| std::cmp::Reverse(f.severity));

        let found: std::collections::HashSet<ArtifactKind> =
            collector.files.iter().map(|f| f.kind).collect();
        let mut missing_artifacts = Vec::new();
        if !found.contains(&ArtifactKind::ShutdownLog) {
            missing_artifacts.push(MissingArtifact {
                kind: "shutdown_log".into(),
                note: "No shutdown.log was found in this archive. It normally exists once the device has been restarted at least once; without it, one of the four detection surfaces is unavailable for this scan.".into(),
            });
        }
        if !found.contains(&ArtifactKind::CrashLog) {
            missing_artifacts.push(MissingArtifact {
                kind: "crash_log".into(),
                note: "No crash logs were found in crashes_and_spins. This can be normal, especially on a new or recently erased device.".into(),
            });
        }
        if !found.contains(&ArtifactKind::PsListing) {
            missing_artifacts.push(MissingArtifact {
                kind: "ps_listing".into(),
                note: "No process listing (ps.txt) was found in this archive, so running processes could not be checked.".into(),
            });
        }
        if !unified_seen {
            missing_artifacts.push(MissingArtifact {
                kind: "unified_log".into(),
                note: "No unified log data (system_logs.logarchive tracev3 files) was found in this archive, so the process history across the log window could not be checked.".into(),
            });
        }

        // Any safety limit hit means part of the archive went unanalyzed.
        // A real sysdiagnose never comes close to these caps.
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
        if unified_truncated > 0 {
            scan_limits.push(format!(
                "{unified_truncated} unified log file(s) exceeded size limits and were skipped; the process history is incomplete."
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
        let partial_crashes = artifacts
            .iter()
            .filter(|a| a.kind == "crash_log" && a.status == "parsed_partial")
            .count();
        if partial_crashes > 0 {
            scan_limits.push(format!(
                "{partial_crashes} crash log file(s) could not be parsed; only their file names were checked against indicators."
            ));
        }
        if tracev3_failures > 0 {
            scan_limits.push(format!(
                "{tracev3_failures} of {tracev3_files} unified log (tracev3) file(s) could not be parsed; the process history is incomplete."
            ));
        }
        if uuidtext_failures > 0 {
            scan_limits.push(format!(
                "{uuidtext_failures} of {uuidtext_files} unified log support (uuidtext) file(s) could not be parsed; some processes could not be resolved to binary paths."
            ));
        }
        if unified_cap_hit {
            scan_limits.push(
                "The unified log process inventory reached its tracking cap; processes beyond it were not recorded.".into(),
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
        if collector.stream_cap_hit {
            scan_limits.push(
                "The archive expanded past the scanner's decompression budget; scanning stopped early and the rest was not analyzed.".into(),
            );
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

        // The verdict is decided here, in one place, from everything above.
        // Consumers render it; they never re-derive safety semantics.
        let has = |sev: Severity| findings.iter().any(|f| f.severity == sev);
        let verdict = if has(Severity::Match) {
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

        // Coverage is per scan: only surfaces actually present are listed as
        // examined, so the report cannot claim a missing surface was read.
        let mut examined: Vec<&'static str> = Vec::new();
        if found.contains(&ArtifactKind::ShutdownLog) {
            examined.push("shutdown.log (and rotated shutdown.N.log) - processes that delayed device shutdown, across reboots");
        }
        if found.contains(&ArtifactKind::CrashLog) {
            examined
                .push("Crash logs (crashes_and_spins/*.ips) - crashing process names and paths");
        }
        if found.contains(&ArtifactKind::PsListing) {
            examined.push(
                "Process listings (ps.txt, ps_thread.txt) - processes running at capture time",
            );
        }
        if unified_seen {
            examined.push("Unified system logs (system_logs.logarchive) - every process that wrote a log entry during the archive window, typically days of history (process inventory; log message contents are not read)");
        }

        Ok(Report {
            schema_version: 2,
            tool: ToolInfo {
                name: "Trace",
                version: env!("CARGO_PKG_VERSION"),
            },
            verdict,
            device,
            indicator_sets: self.db.sets.clone(),
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
            coverage: Coverage {
                examined,
                not_examined: vec![
                    "File-system presence of file indicators - a sysdiagnose has no filesystem listing, so file name and path indicators match only when a process was observed running from that file",
                    "Unified log message contents - domain and URL indicators inside log text are not checked",
                    "Safari browsing history - lives in device backups, where most domain indicators would be checked",
                    "SMS/iMessage link payloads - device backups only",
                    "Per-process network usage (DataUsage) - device backups only",
                    "Installed apps and configuration profiles - device backups only",
                ],
                note: "Domain, URL, email and other network indicators in the loaded sets cannot be checked against sysdiagnose artifacts, and file indicators are checked only against observed process paths. A result with no matches means these artifacts contained no known traces - it does not examine everything, and it cannot prove a device is clean.",
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
        assert!(report.scan_limits.iter().any(|l| l.contains("crash log")));
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
    fn findings_cap_is_enforced_and_surfaces() {
        // A crafted ps.txt whose every line raises a heuristic must not
        // allocate unbounded findings, and the cap must force the verdict
        // away from clear (a real match could hide beyond the cap).
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
