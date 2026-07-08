//! Plain-Rust engine behind the WASM `Scanner`: accepts streamed archive
//! bytes, auto-detects gzip vs raw tar, and assembles the final report.

use crate::ioc::{IocDb, SetStats};
use crate::report::*;
use crate::tar_stream::{ArtifactKind, TarCollector};
use crate::{crash_log, ps, shutdown_log};
use flate2::write::GzDecoder;
use std::io::Write;

enum Sink {
    Gz(GzDecoder<TarCollector>),
    Plain(TarCollector),
}

pub struct Engine {
    db: IocDb,
    sink: Option<Sink>,
    bytes_in: u64,
}

impl Engine {
    pub fn new() -> Self {
        Engine {
            db: IocDb::new(),
            sink: None,
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
            let collector = TarCollector::new();
            let is_gz = chunk.len() >= 2 && chunk[0] == 0x1f && chunk[1] == 0x8b;
            self.sink = Some(if is_gz {
                Sink::Gz(GzDecoder::new(collector))
            } else {
                Sink::Plain(collector)
            });
        }
        match self.sink.as_mut().unwrap() {
            Sink::Gz(g) => g.write_all(chunk).map_err(|e| {
                format!("decompression failed - is this a .tar.gz sysdiagnose archive? ({e})")
            }),
            Sink::Plain(c) => c.write_all(chunk).map_err(|e| e.to_string()),
        }
    }

    pub fn finish(mut self) -> Result<Report, String> {
        let collector = match self.sink.take() {
            None => return Err("no data received".into()),
            Some(Sink::Gz(g)) => g.finish().map_err(|e| {
                format!("archive ended unexpectedly - the file may be incomplete ({e})")
            })?,
            Some(Sink::Plain(c)) => c,
        };

        let mut findings: Vec<Finding> = Vec::new();
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
                    if device.is_none() {
                        device = d;
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

        findings.sort_by_key(|f| std::cmp::Reverse(f.severity));

        let found: std::collections::HashSet<ArtifactKind> =
            collector.files.iter().map(|f| f.kind).collect();
        let mut missing_artifacts = Vec::new();
        if !found.contains(&ArtifactKind::ShutdownLog) {
            missing_artifacts.push(MissingArtifact {
                kind: "shutdown_log".into(),
                note: "No shutdown.log was found in this archive. It normally exists once the device has been restarted at least once; without it, one of the three detection surfaces is unavailable for this scan.".into(),
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

        Ok(Report {
            tool: ToolInfo {
                name: "Trace",
                version: env!("CARGO_PKG_VERSION"),
            },
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
            coverage: Coverage {
                examined: vec![
                    "shutdown.log - processes that delayed device shutdown, across reboots",
                    "Crash logs (crashes_and_spins/*.ips) - crashing process names and paths",
                    "Process listings (ps.txt, ps_thread.txt) - processes running at capture time",
                ],
                not_examined: vec![
                    "Unified system logs (system_logs.logarchive) - the richest sysdiagnose artifact; planned for a future version",
                    "Safari browsing history - lives in device backups, where most domain indicators would be checked",
                    "SMS/iMessage link payloads - device backups only",
                    "Per-process network usage (DataUsage) - device backups only",
                    "Installed apps and configuration profiles - device backups only",
                ],
                note: "Domain, URL and email indicators in the loaded sets cannot be checked against sysdiagnose artifacts. A result with no matches means these artifacts contained no known traces - it does not examine everything, and it cannot prove a device is clean.",
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
    fn end_to_end_clean_raw_tar() {
        let tar = build_archive(false);
        let mut engine = Engine::new();
        engine.load_stix("pegasus-mini", PEGASUS_MINI).unwrap();
        engine.push(&tar).unwrap();
        let report = engine.finish().unwrap();
        assert_eq!(report.stats.artifacts_found, 3);
        assert!(report.findings.is_empty());
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
        assert_eq!(missing, vec!["shutdown_log", "crash_log"]);
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
