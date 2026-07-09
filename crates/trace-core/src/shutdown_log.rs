//! shutdown.log analysis. iOS logs processes that hold up device shutdown as
//! "remaining client pid: N (/path)" lines with increasing "After X.Xs"
//! delays. Kaspersky's iShutdown research (Jan 2024) showed Pegasus processes
//! appear here, typically running out of
//! /private/var/db/com.apple.xpc.roleaccountd.staging/.
//!
//! Two generations of the format are handled (both verified against real
//! captures): the classic one-line form
//! "After 0.1s, remaining client pid: 155 (/usr/libexec/nfcd)" and the
//! iOS 26 form, where an "After 1.26s, these clients are still here:" header
//! precedes indented client lines whose paths carry a trailing binary-UUID
//! component that must be stripped before indicator matching.
//!
//! Reboot blocks are delimited by the delay timer resetting (a new shutdown
//! starts again low), which is more stable across iOS versions than any
//! particular phase-marker line.

use crate::heuristics::path_flag_finding;
use crate::ioc::{basename, IocDb};
use crate::report::{ArtifactSummary, Finding, Findings};
use regex_lite::Regex;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

fn entry_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"remaining client pid:\s*(\d+)\s*\((.+)\)").unwrap())
}

fn uuid_component_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"/[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
            .unwrap()
    })
}

/// iOS 26 appends the binary's UUID as a trailing path component:
/// "/usr/libexec/coreduetd/FC9C4AD0-D918-393F-B50C-7B4D830F3E2A". Left in
/// place, the basename is a UUID and no process-name indicator can ever
/// match - a silent false negative on every modern device. Strip it.
fn strip_uuid_component(path: &str) -> &str {
    match uuid_component_re().find(path) {
        Some(m) if m.start() > 0 => &path[..m.start()],
        _ => path,
    }
}

fn delay_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"After\s+([0-9]+(?:\.[0-9]+)?)s").unwrap())
}

pub fn analyze(path: &str, content: &str, db: &IocDb, findings: &mut Findings) -> ArtifactSummary {
    let mut blocks: Vec<BTreeSet<String>> = Vec::new();
    let mut current: BTreeSet<String> = BTreeSet::new();
    let mut client_pids: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    let mut prev_delay: Option<f64> = None;
    let mut entries = 0usize;

    for line in content.lines() {
        if let Some(c) = delay_re().captures(line) {
            let d: f64 = c[1].parse().unwrap_or(0.0);
            if let Some(p) = prev_delay {
                if d < p && !current.is_empty() {
                    blocks.push(std::mem::take(&mut current));
                }
            }
            prev_delay = Some(d);
        }
        if let Some(c) = entry_re().captures(line) {
            entries += 1;
            let pid: u32 = c[1].parse().unwrap_or(0);
            let proc_path = strip_uuid_component(c[2].trim()).to_string();
            client_pids
                .entry(proc_path.clone())
                .or_default()
                .insert(pid);
            current.insert(proc_path);
        }
    }
    if !current.is_empty() {
        blocks.push(current);
    }

    for (proc_path, pids) in &client_pids {
        let blocks_seen = blocks.iter().filter(|b| b.contains(proc_path)).count();
        let evidence = json!({
            "process_path": proc_path,
            "pids": pids,
            "reboot_blocks_seen": blocks_seen,
            "total_reboot_blocks": blocks.len(),
        });

        for ind in db.match_process(proc_path) {
            findings.push(Finding::ioc_match(
                path,
                format!(
                    "Process \u{2018}{}\u{2019} held up device shutdown - its name matches a published {} indicator",
                    basename(proc_path),
                    ind.campaign
                ),
                evidence.clone(),
                ind,
            ));
        }

        if let Some(f) = path_flag_finding(path, proc_path, "A process ran from", &evidence) {
            findings.push(f);
        }
    }

    ArtifactSummary::parsed(
        path,
        "shutdown_log",
        json!({
            "reboot_blocks": blocks.len(),
            "unique_clients": client_pids.len(),
            "entries": entries,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Severity;

    const SAMPLE: &str = "\
%%%%% Entering phase: Waiting for apps to exit

After 0.1s, remaining client pid: 155 (/usr/libexec/nfcd)
After 0.2s, remaining client pid: 155 (/usr/libexec/nfcd)
After 0.3s, remaining client pid: 155 (/usr/libexec/nfcd)
SIGTERM: [0x100304080] Sent SIGTERM to remaining client pid: 155 (/usr/libexec/nfcd)

%%%%% Entering phase: Waiting for apps to exit

After 0.1s, remaining client pid: 2143 (/private/var/db/com.apple.xpc.roleaccountd.staging/bh)
After 0.2s, remaining client pid: 2143 (/private/var/db/com.apple.xpc.roleaccountd.staging/bh)
";

    fn db_with_bh() -> IocDb {
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"malware","name":"Pegasus"},{"type":"indicator","pattern":"[process:name='bh']"}]}"#,
        )
        .unwrap();
        db
    }

    #[test]
    fn splits_reboot_blocks_on_delay_reset() {
        let mut findings = Findings::new();
        let summary = analyze("shutdown.log", SAMPLE, &IocDb::new(), &mut findings);
        assert_eq!(summary.details["reboot_blocks"], 2);
        assert_eq!(summary.details["unique_clients"], 2);
    }

    // iOS 26 form: delay header line, tab-indented clients, binary-UUID
    // suffix on every path. Mirrors a real iOS 26.5.2 capture.
    const SAMPLE_IOS26: &str = "\
After 1.26s, these clients are still here:
\t\tremaining client pid: 153 (/usr/sbin/filecoordinationd/EBFB3E7F-4CA4-3656-8E9C-8CCF5995C34A)
\t\tremaining client pid: 0 (/kernel/D504008E-47BE-3030-836A-E692031BB4AE)
After 1.77s, these clients are still here:
\t\tremaining client pid: 153 (/usr/sbin/filecoordinationd/EBFB3E7F-4CA4-3656-8E9C-8CCF5995C34A)
After 1.26s, these clients are still here:
\t\tremaining client pid: 2143 (/private/var/db/com.apple.xpc.roleaccountd.staging/bh/AAAA1111-B896-3E7F-A6CC-577F0A547BB1)
";

    #[test]
    fn ios26_format_strips_uuid_and_matches() {
        let mut findings = Findings::new();
        let summary = analyze("shutdown.0.log", SAMPLE_IOS26, &db_with_bh(), &mut findings);
        // the delay reset (1.77 -> 1.26) delimits the second reboot block
        assert_eq!(summary.details["reboot_blocks"], 2);
        let matches: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Match)
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "name IOC must match once the UUID component is stripped"
        );
        assert_eq!(
            matches[0].evidence["process_path"],
            "/private/var/db/com.apple.xpc.roleaccountd.staging/bh"
        );
        assert!(findings.iter().any(|f| f.severity == Severity::Suspicious));
        // benign daemons: no findings, and their paths lost the UUID too
        assert!(!findings
            .iter()
            .any(|f| f.summary.contains("filecoordinationd")));
    }

    #[test]
    fn uuid_stripping_is_conservative() {
        // only a full trailing UUID component comes off
        assert_eq!(
            strip_uuid_component("/usr/libexec/coreduetd/FC9C4AD0-D918-393F-B50C-7B4D830F3E2A"),
            "/usr/libexec/coreduetd"
        );
        assert_eq!(
            strip_uuid_component("/usr/libexec/nfcd"),
            "/usr/libexec/nfcd"
        );
        assert_eq!(
            strip_uuid_component("/usr/libexec/AAAA-BB/binary"),
            "/usr/libexec/AAAA-BB/binary"
        );
    }

    #[test]
    fn flags_ioc_match_and_staging_heuristic() {
        let mut findings = Findings::new();
        analyze("shutdown.log", SAMPLE, &db_with_bh(), &mut findings);
        let matches: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Match)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].indicator.as_ref().unwrap().campaign, "Pegasus");
        assert!(findings.iter().any(|f| f.severity == Severity::Suspicious));
        // benign daemon produced no findings
        assert!(!findings.iter().any(|f| f.summary.contains("nfcd")));
    }
}
