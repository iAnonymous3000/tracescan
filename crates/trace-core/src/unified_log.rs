//! Unified log (tracev3) analysis: catalog-level process inventory.
//!
//! Every tracev3 chunk carries a catalog listing the processes that emitted
//! the entries in it (pid plus the UUID of the main binary), and each
//! uuidtext file's footer stores that binary's full path. Joining the two
//! yields every process that wrote a log entry during the archive window
//! (typically days of device history) without rendering a single log
//! message - so the 155 MB dsc shared-string cache is never loaded and peak
//! memory stays at one file. Design: docs/design-unified-logs.md.
//!
//! Files are consumed as they stream out of the tar (see `tar_stream`):
//! tracev3 files arrive before the uuidtext tree, so process UUIDs are
//! collected first and paths attach afterwards.

use crate::heuristics::path_flag_finding;
use crate::ioc::{basename, IocDb};
use crate::report::{ArtifactSummary, Finding, Findings};
use macos_unifiedlogs::parser::parse_log;
use macos_unifiedlogs::uuidtext::UUIDText;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

/// A real logarchive holds a few hundred binaries; these caps only matter
/// for hostile input, and hitting one surfaces in the artifact details.
const MAX_TRACKED_UUIDS: usize = 65_536;
const MAX_PIDS_PER_PROCESS: usize = 4_096;
/// Real binary paths are well under 1 KB; a crafted uuidtext footer must not
/// be able to store megabytes per tracked UUID.
const MAX_PATH_BYTES: usize = 4_096;
/// Kernel entries carry an all-zeros main UUID and no binary path.
const ZERO_UUID: &str = "00000000000000000000000000000000";

#[derive(Default)]
struct ProcStat {
    pids: BTreeSet<u32>,
    catalog_appearances: u64,
}

#[derive(Default)]
pub struct Aggregator {
    /// main binary UUID (32 hex chars) -> observations across all tracev3.
    procs: BTreeMap<String, ProcStat>,
    /// binary UUID -> full path, from uuidtext footers.
    paths: BTreeMap<String, String>,
    pub(crate) tracev3_files: u64,
    pub(crate) tracev3_failures: u64,
    pub(crate) uuidtext_files: u64,
    pub(crate) uuidtext_failures: u64,
    catalogs: u64,
    pub(crate) cap_hit: bool,
    /// Files our own size cap cut short; parsing a partial file would
    /// silently under-report, so they are skipped and surfaced instead.
    pub truncated_files: u64,
}

fn image_path(ut: &UUIDText) -> Option<String> {
    // The footer holds the entry strings followed by the binary's path;
    // the path starts after the summed entry sizes (the same layout the
    // upstream parser reads for its LogData.process field).
    let offset: usize = ut
        .entry_descriptors
        .iter()
        .map(|e| e.entry_size as usize)
        .sum();
    let footer = ut.footer_data.get(offset..)?;
    let scan = &footer[..footer.len().min(MAX_PATH_BYTES)];
    let end = scan.iter().position(|&b| b == 0).unwrap_or(scan.len());
    let path = String::from_utf8_lossy(&scan[..end]).trim().to_string();
    (!path.is_empty()).then_some(path)
}

impl Aggregator {
    pub fn consume_tracev3(&mut self, source: &str, data: &[u8]) {
        self.tracev3_files += 1;
        let Ok(log) = parse_log(Cursor::new(data), source) else {
            self.tracev3_failures += 1;
            return;
        };
        for cat in &log.catalog_data {
            self.catalogs += 1;
            for entry in cat.catalog.catalog_process_info_entries.values() {
                if entry.main_uuid == ZERO_UUID {
                    continue;
                }
                if !self.procs.contains_key(&entry.main_uuid)
                    && self.procs.len() >= MAX_TRACKED_UUIDS
                {
                    self.cap_hit = true;
                    continue;
                }
                let stat = self.procs.entry(entry.main_uuid.clone()).or_default();
                stat.catalog_appearances += 1;
                if stat.pids.len() < MAX_PIDS_PER_PROCESS {
                    stat.pids.insert(entry.pid);
                }
            }
        }
    }

    pub fn consume_uuidtext(&mut self, uuid: String, data: &[u8]) {
        self.uuidtext_files += 1;
        let Ok((_, ut)) = UUIDText::parse_uuidtext(data) else {
            self.uuidtext_failures += 1;
            return;
        };
        if self.paths.len() >= MAX_TRACKED_UUIDS {
            self.cap_hit = true;
            return;
        }
        if let Some(path) = image_path(&ut) {
            self.paths.insert(uuid, path);
        }
    }

    /// True if any unified-log content was seen at all.
    pub fn saw_content(&self) -> bool {
        self.tracev3_files > 0 || self.uuidtext_files > 0
    }

    pub fn finalize(self, db: &IocDb, findings: &mut Findings) -> Option<ArtifactSummary> {
        if !self.saw_content() {
            return None;
        }
        let mut resolved = 0usize;
        for (uuid, stat) in &self.procs {
            let Some(path) = self.paths.get(uuid) else {
                // Binary no longer on device (rotated uuidtext); nothing to
                // match against, counted below as unresolved.
                continue;
            };
            resolved += 1;
            let pid_sample: Vec<&u32> = stat.pids.iter().take(16).collect();
            let evidence = json!({
                "process_path": path,
                "binary_uuid": uuid,
                "pid_count": stat.pids.len(),
                "pids_sample": pid_sample,
                "catalog_appearances": stat.catalog_appearances,
            });
            for ind in db.match_process(path) {
                findings.push(Finding::ioc_match(
                    "system_logs.logarchive",
                    format!(
                        "Process \u{2018}{}\u{2019} wrote unified log entries - its name matches a published {} indicator",
                        basename(path),
                        ind.campaign
                    ),
                    evidence.clone(),
                    ind,
                ));
            }
            if let Some(f) = path_flag_finding(
                "system_logs.logarchive",
                path,
                "A process wrote unified log entries from",
                &evidence,
            ) {
                findings.push(f);
            }
        }

        let details = json!({
            "tracev3_files": self.tracev3_files,
            "tracev3_parse_failures": self.tracev3_failures,
            "uuidtext_files": self.uuidtext_files,
            "uuidtext_parse_failures": self.uuidtext_failures,
            "catalogs": self.catalogs,
            "processes_seen": self.procs.len(),
            "processes_resolved_to_path": resolved,
            "cap_hit": self.cap_hit,
        });
        // Wholesale parse failure must not read as a normally analyzed
        // surface: it downgrades the artifact status.
        let all_failed = self.tracev3_files > 0 && self.tracev3_failures == self.tracev3_files;
        Some(if all_failed {
            ArtifactSummary::problem(
                "system_logs.logarchive",
                "unified_log",
                "parsed_partial",
                details,
            )
        } else {
            ArtifactSummary::parsed("system_logs.logarchive", "unified_log", details)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Severity;

    fn seeded_db() -> IocDb {
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"malware","name":"Pegasus"},{"type":"indicator","pattern":"[process:name='bh']"}]}"#,
        )
        .unwrap();
        db
    }

    fn agg_with(procs: &[(&str, u32)], paths: &[(&str, &str)]) -> Aggregator {
        let mut a = Aggregator {
            tracev3_files: 1,
            ..Default::default()
        };
        for (uuid, pid) in procs {
            let stat = a.procs.entry(uuid.to_string()).or_default();
            stat.pids.insert(*pid);
            stat.catalog_appearances += 1;
        }
        for (uuid, path) in paths {
            a.paths.insert(uuid.to_string(), path.to_string());
        }
        a
    }

    #[test]
    fn no_content_yields_no_summary() {
        let mut findings = Findings::new();
        assert!(Aggregator::default()
            .finalize(&seeded_db(), &mut findings)
            .is_none());
        assert!(findings.is_empty());
    }

    #[test]
    fn resolved_process_matches_ioc_and_staging_heuristic() {
        let agg = agg_with(
            &[("AAAA", 2143), ("BBBB", 155)],
            &[
                (
                    "AAAA",
                    "/private/var/db/com.apple.xpc.roleaccountd.staging/bh",
                ),
                ("BBBB", "/usr/libexec/nfcd"),
            ],
        );
        let mut findings = Findings::new();
        let summary = agg.finalize(&seeded_db(), &mut findings).unwrap();
        assert_eq!(summary.kind, "unified_log");
        assert_eq!(summary.status, "parsed");
        assert_eq!(summary.details["processes_resolved_to_path"], 2);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.severity == Severity::Match)
                .count(),
            1
        );
        assert!(findings.iter().any(|f| f.severity == Severity::Suspicious));
        assert!(!findings.iter().any(|f| f.summary.contains("nfcd")));
    }

    #[test]
    fn unresolved_uuid_is_counted_not_matched() {
        let agg = agg_with(&[("CCCC", 42)], &[]);
        let mut findings = Findings::new();
        let summary = agg.finalize(&seeded_db(), &mut findings).unwrap();
        assert_eq!(summary.details["processes_seen"], 1);
        assert_eq!(summary.details["processes_resolved_to_path"], 0);
        assert!(findings.is_empty());
    }

    #[test]
    fn garbage_bytes_count_as_failures_not_panics() {
        let mut agg = Aggregator::default();
        agg.consume_tracev3("Persist/0.tracev3", &[0xAB; 512]);
        agg.consume_uuidtext("DEAD".into(), &[0xCD; 64]);
        assert_eq!(agg.tracev3_failures, 1);
        assert_eq!(agg.uuidtext_failures, 1);
        // wholesale failure downgrades the artifact status
        let mut findings = Findings::new();
        let summary = agg.finalize(&seeded_db(), &mut findings).unwrap();
        assert_eq!(summary.status, "parsed_partial");
    }
}
