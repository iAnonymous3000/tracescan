//! .ips crash log analysis. Modern crash logs are two JSON documents: a
//! one-line summary header, then the full payload. Process names from both
//! are checked against indicators; historically, crashes of implant processes
//! (and of media/message daemons they exploit) have been detection signals.

use crate::heuristics::{path_flag, path_flag_finding, PathFlag};
use crate::ioc::{basename, IocDb, IocKind};
use crate::report::{ArtifactSummary, DeviceInfo, Finding, Severity};
use regex_lite::Regex;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::OnceLock;

fn str_field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(|x| x.as_str())
}

fn panic_pid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"pid (\d+)[:\s]+\(?([A-Za-z0-9_.-]+)\)?").unwrap())
}

fn date_suffix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"-\d{4}-\d{2}-\d{2}").unwrap())
}

/// Crash file names encode the crashing process ("bh-2026-07-01-120311.ips").
/// Process names can themselves contain hyphens (Pegasus's published
/// indicators include 'Diagnostics-2543'), so the name is recovered by
/// stripping the trailing date-time stamp, not by cutting at the first
/// hyphen - the latter would silently miss such indicators.
fn filename_process(fname: &str) -> Option<&str> {
    let stem = fname.strip_suffix(".ips").unwrap_or(fname);
    let name = match date_suffix_re().find(stem) {
        Some(m) => &stem[..m.start()],
        None => stem,
    };
    (name.len() > 1).then_some(name)
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
        bug_type = str_field(h, "bug_type").map(String::from);
        timestamp = str_field(h, "timestamp").map(String::from);
        os_version = str_field(h, "os_version").map(String::from);
    }
    if let Some(b) = &body {
        if let Some(n) = str_field(b, "procName") {
            candidates.insert(n.to_string());
            proc_name.get_or_insert_with(|| n.to_string());
        }
        if let Some(p) = str_field(b, "procPath") {
            // The full path must be a candidate too: file:path indicators
            // (e.g. '/private/var/tmp/UserEventAgent') only match on it.
            candidates.insert(p.to_string());
            candidates.insert(basename(p).to_string());
            proc_path = Some(p.to_string());
        }
        if let Some(pp) = str_field(b, "parentProc") {
            candidates.insert(pp.to_string());
        }
        if os_version.is_none() {
            if let Some(ov) = b.get("osVersion") {
                let train = str_field(ov, "train").unwrap_or("");
                let build = str_field(ov, "build").unwrap_or("");
                if !train.is_empty() {
                    os_version = Some(format!("{train} ({build})"));
                }
            }
        }
    }

    // Kernel panics (bug_type 210) carry their signal inside panicString
    // rather than procName. Process names in it look like "pid 282: bh" or
    // "pid 282 (bh)"; extract them as match candidates. Candidates are only
    // ever compared by exact equality against the indicator set, so noisy
    // extraction cannot create false positives.
    let mut panic_staging = false;
    if let Some(ps) = body.as_ref().and_then(|b| str_field(b, "panicString")) {
        if ps.contains("/com.apple.xpc.roleaccountd.staging/") {
            panic_staging = true;
        }
        for cap in panic_pid_re().captures_iter(ps) {
            candidates.insert(cap[2].to_string());
        }
    }

    // The filename itself encodes the crashing process, which survives even
    // when the JSON fails to parse.
    let fname = basename(path);
    if let Some(name) = filename_process(fname) {
        candidates.insert(name.to_string());
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
            // Name indicators read best as a bare process name; a file:path
            // indicator only makes sense shown as the full path it matched.
            let shown = match ind.kind {
                IocKind::FilePath => cand.as_str(),
                _ => basename(cand),
            };
            findings.push(Finding::ioc_match(
                path,
                format!(
                    "Crash log involves process \u{2018}{}\u{2019} - matches a published {} indicator",
                    shown, ind.campaign
                ),
                evidence_base.clone(),
                ind,
            ));
        }
    }

    // Same yardstick as the ps and shutdown.log surfaces.
    if let Some(f) = proc_path
        .as_deref()
        .and_then(|p| path_flag_finding(path, p, "The crashing process ran from", &evidence_base))
    {
        findings.push(f);
    }
    // A staging path seen only inside a kernel panic string has no process
    // path to cite; suppressed when the path-based flag already raised it.
    if panic_staging && proc_path.as_deref().and_then(path_flag) != Some(PathFlag::Staging) {
        findings.push(Finding::heuristic(
            Severity::Suspicious,
            path,
            "A kernel panic report references the roleaccountd.staging directory - it is strongly associated with Pegasus infections in published research (Kaspersky iShutdown, 2024)".into(),
            evidence_base.clone(),
        ));
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
            findings
                .iter()
                .filter(|f| f.severity == Severity::Match)
                .count(),
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
    fn kernel_panic_string_yields_candidates_and_staging_heuristic() {
        let panic = r#"{"name":"kernel","bug_type":"210","timestamp":"2026-07-06 03:00:00.00 -0700","os_version":"iPhone OS 17.2.1 (21C66)"}
{"panicString":"panic(cpu 4): Panicked task 0xffffff80211a5f80: 306 threads: pid 2143: bh, ran from /private/var/db/com.apple.xpc.roleaccountd.staging/bh","osVersion":{"train":"iPhone OS 17.2.1","build":"21C66"}}"#;
        let mut findings = Vec::new();
        analyze(
            "root/crashes_and_spins/Panics/panic-full-2026-07-06.ips",
            panic,
            &db_with_bh(),
            &mut findings,
        );
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.severity == Severity::Match)
                .count(),
            1,
            "panicString pid extraction should match the seeded IOC"
        );
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.severity == Severity::Suspicious)
                .count(),
            1,
            "staging path inside panicString should raise the heuristic"
        );
    }

    #[test]
    fn file_path_indicator_matches_full_proc_path() {
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"malware","name":"Pegasus"},{"type":"indicator","pattern":"[file:path='/private/var/db/com.apple.xpc.roleaccountd.staging/bh']"}]}"#,
        )
        .unwrap();
        let mut findings = Vec::new();
        analyze(
            "root/crashes_and_spins/bh-2026-07-01-120311.ips",
            SAMPLE,
            &db,
            &mut findings,
        );
        let matches: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Match)
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "file:path indicator must match the crash log's full procPath"
        );
        assert_eq!(matches[0].indicator.as_ref().unwrap().kind, "file_path");
        assert!(matches[0]
            .summary
            .contains("/com.apple.xpc.roleaccountd.staging/bh"));
    }

    #[test]
    fn crash_from_unusual_location_yields_note() {
        let sample = r#"{"app_name":"agent","name":"agent","bug_type":"309"}
{"procName":"agent","procPath":"/private/var/tmp/agent","parentProc":"launchd"}"#;
        let mut findings = Vec::new();
        analyze(
            "root/crashes_and_spins/agent-2026.ips",
            sample,
            &IocDb::new(),
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Note);
        assert!(findings[0].summary.contains("/private/var/tmp/agent"));
    }

    #[test]
    fn filename_process_recovers_hyphenated_names() {
        assert_eq!(
            filename_process("bh-2026-07-01-120311.ips"),
            Some("bh"),
            "plain name before the date stamp"
        );
        assert_eq!(
            filename_process("Diagnostics-2543-2026-07-01-120311.ips"),
            Some("Diagnostics-2543"),
            "hyphenated process names must survive"
        );
        assert_eq!(filename_process("no-date-stamp.ips"), Some("no-date-stamp"));
        assert_eq!(filename_process("x.ips"), None, "too short to be a name");
    }

    #[test]
    fn unparseable_crash_still_matches_hyphenated_name_from_filename() {
        // A real Pegasus indicator style name with a hyphen; the JSON body is
        // garbage, so the filename is the only signal left.
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"malware","name":"Pegasus"},{"type":"indicator","pattern":"[process:name='Diagnostics-2543']"}]}"#,
        )
        .unwrap();
        let mut findings = Vec::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/Diagnostics-2543-2026-07-01-120311.ips",
            "not json at all",
            &db,
            &mut findings,
        );
        assert_eq!(summary.status, "parsed_partial");
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.severity == Severity::Match)
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
