//! shutdown.log analysis. iOS logs processes that hold up device shutdown as
//! "remaining client pid: N (/path)" lines with increasing "After X.Xs"
//! delays. Kaspersky's iShutdown research (Jan 2024) showed Pegasus processes
//! appear here, typically running out of
//! /private/var/db/com.apple.xpc.roleaccountd.staging/.
//!
//! Reboot blocks are delimited by the delay timer resetting (a new shutdown
//! starts again at ~0.1s), which is more stable across iOS versions than any
//! particular phase-marker line.

use crate::ioc::{basename, IocDb};
use crate::report::{ArtifactSummary, Finding, Severity};
use regex_lite::Regex;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

fn entry_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"remaining client pid:\s*(\d+)\s*\((.+)\)").unwrap())
}

fn delay_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"After\s+([0-9]+(?:\.[0-9]+)?)s").unwrap())
}

pub fn analyze(
    path: &str,
    content: &str,
    db: &IocDb,
    findings: &mut Vec<Finding>,
) -> ArtifactSummary {
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
            let proc_path = c[2].trim().to_string();
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

        if proc_path.contains("/com.apple.xpc.roleaccountd.staging/") {
            findings.push(Finding::heuristic(
                Severity::Suspicious,
                path,
                format!(
                    "A process ran from {} - this staging directory is strongly associated with Pegasus infections in published research (Kaspersky iShutdown, 2024)",
                    proc_path
                ),
                evidence.clone(),
            ));
        } else if proc_path.starts_with("/private/var/db/")
            || proc_path.starts_with("/private/var/tmp/")
            || proc_path.starts_with("/private/var/root/")
        {
            findings.push(Finding::heuristic(
                Severity::Note,
                path,
                format!(
                    "A process ran from an unusual location ({}) - often benign, but worth review alongside other findings",
                    proc_path
                ),
                evidence.clone(),
            ));
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
        let mut findings = Vec::new();
        let summary = analyze("shutdown.log", SAMPLE, &IocDb::new(), &mut findings);
        assert_eq!(summary.details["reboot_blocks"], 2);
        assert_eq!(summary.details["unique_clients"], 2);
    }

    #[test]
    fn flags_ioc_match_and_staging_heuristic() {
        let mut findings = Vec::new();
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
