//! .ips crash log analysis. Modern crash logs are two JSON documents: a
//! one-line summary header, then the full payload. Process names from both
//! are checked against indicators; historically, crashes of implant processes
//! (and of media/message daemons they exploit) have been detection signals.

use crate::ioc::{basename, IocDb};
use crate::report::{ArtifactSummary, DeviceInfo, Finding, Severity};
use serde_json::{json, Value};
use std::collections::BTreeSet;

fn str_field<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|k| v.get(k).and_then(|x| x.as_str()))
}

pub fn analyze(
    path: &str,
    content: &str,
    db: &IocDb,
    findings: &mut Vec<Finding>,
) -> (ArtifactSummary, Option<DeviceInfo>) {
    let (first_line, rest) = match content.split_once('\n') {
        Some((a, b)) => (a, b),
        None => (content, ""),
    };
    let header: Option<Value> = serde_json::from_str(first_line.trim()).ok();
    let body: Option<Value> = serde_json::from_str(rest.trim()).ok();

    let mut candidates: BTreeSet<String> = BTreeSet::new();
    let mut proc_path: Option<String> = None;
    let mut proc_name: Option<String> = None;
    let mut bug_type: Option<String> = None;
    let mut timestamp: Option<String> = None;
    let mut os_version: Option<String> = None;

    if let Some(h) = &header {
        for key in ["name", "app_name"] {
            if let Some(n) = h.get(key).and_then(|x| x.as_str()) {
                candidates.insert(n.to_string());
                proc_name.get_or_insert_with(|| n.to_string());
            }
        }
        bug_type = str_field(h, &["bug_type"]).map(String::from);
        timestamp = str_field(h, &["timestamp"]).map(String::from);
        os_version = str_field(h, &["os_version"]).map(String::from);
    }
    if let Some(b) = &body {
        if let Some(n) = str_field(b, &["procName", "process_name", "processName"]) {
            candidates.insert(n.to_string());
            proc_name.get_or_insert_with(|| n.to_string());
        }
        if let Some(p) = str_field(b, &["procPath", "process_path", "procesPath"]) {
            candidates.insert(basename(p).to_string());
            proc_path = Some(p.to_string());
        }
        if let Some(pp) = str_field(b, &["parentProc", "parent_process"]) {
            candidates.insert(pp.to_string());
        }
        if os_version.is_none() {
            if let Some(ov) = b.get("osVersion") {
                let train = str_field(ov, &["train"]).unwrap_or("");
                let build = str_field(ov, &["build"]).unwrap_or("");
                if !train.is_empty() {
                    os_version = Some(format!("{train} ({build})"));
                }
            }
        }
    }

    // The filename itself encodes the crashing process ("bh-2026-07-01-….ips"),
    // which survives even when the JSON fails to parse.
    let fname = basename(path);
    if let Some(prefix) = fname.split('-').next() {
        if !prefix.is_empty() && prefix.len() > 1 {
            candidates.insert(prefix.to_string());
        }
    }

    let status = if header.is_some() || body.is_some() {
        "parsed"
    } else {
        "parsed_partial"
    };

    let evidence_base = json!({
        "crash_file": fname,
        "process": proc_name,
        "process_path": proc_path,
        "bug_type": bug_type,
        "timestamp": timestamp,
    });

    let mut seen: BTreeSet<String> = BTreeSet::new();
    for cand in &candidates {
        for ind in db.match_process(cand) {
            if !seen.insert(format!("{}|{}", ind.set, ind.value)) {
                continue;
            }
            findings.push(Finding::ioc_match(
                path,
                format!(
                    "Crash log involves process \u{2018}{}\u{2019} - matches a published {} indicator",
                    cand, ind.campaign
                ),
                evidence_base.clone(),
                ind,
            ));
        }
    }

    if let Some(pp) = &proc_path {
        if pp.contains("/com.apple.xpc.roleaccountd.staging/") {
            findings.push(Finding::heuristic(
                Severity::Suspicious,
                path,
                format!(
                    "Crashing process ran from {} - this staging directory is strongly associated with Pegasus infections in published research",
                    pp
                ),
                evidence_base.clone(),
            ));
        }
    }

    let device = os_version.as_ref().map(|ov| DeviceInfo {
        os_version: ov.clone(),
        source: path.to_string(),
    });

    (
        ArtifactSummary::problem(
            path,
            "crash_log",
            status,
            json!({
                "process": proc_name,
                "bug_type": bug_type,
                "timestamp": timestamp,
                "os_version": os_version,
            }),
        ),
        device,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{"app_name":"bh","timestamp":"2026-07-01 12:03:11.00 -0700","name":"bh","bug_type":"309","os_version":"iPhone OS 17.2.1 (21C66)","incident_id":"AAAA-BBBB"}
{"procName":"bh","procPath":"/private/var/db/com.apple.xpc.roleaccountd.staging/bh","parentProc":"launchd","pid":2143,"exception":{"codes":"0x0","type":"EXC_CRASH"}}"#;

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
    fn extracts_device_info_and_matches_ioc() {
        let mut findings = Vec::new();
        let (summary, device) = analyze(
            "root/crashes_and_spins/bh-2026-07-01-120311.ips",
            SAMPLE,
            &db_with_bh(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed");
        assert_eq!(device.unwrap().os_version, "iPhone OS 17.2.1 (21C66)");
        // one deduped IOC match plus the staging-directory heuristic
        assert_eq!(
            findings.iter().filter(|f| f.severity == Severity::Match).count(),
            1
        );
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.severity == Severity::Suspicious)
                .count(),
            1
        );
    }

    #[test]
    fn benign_crash_produces_no_findings() {
        let benign = r#"{"app_name":"MobileSafari","name":"MobileSafari","bug_type":"309","os_version":"iPhone OS 17.2.1 (21C66)"}
{"procName":"MobileSafari","procPath":"/Applications/MobileSafari.app/MobileSafari","parentProc":"launchd"}"#;
        let mut findings = Vec::new();
        analyze(
            "root/crashes_and_spins/MobileSafari-2026.ips",
            benign,
            &db_with_bh(),
            &mut findings,
        );
        assert!(findings.is_empty());
    }
}
