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

fn ios26_header_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^After\s+([0-9]+(?:\.[0-9]+)?)s,\s+these clients are still here:\s*$").unwrap()
    })
}

fn ios26_entry_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^[ \t]+remaining client pid:\s*(\d+)\s*\((/[^()]*)\)\s*$").unwrap()
    })
}

fn classic_entry_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^After\s+([0-9]+(?:\.[0-9]+)?)s,\s+remaining client pid:\s*(\d+)\s*\((/[^()]*)\)\s*$",
        )
        .unwrap()
    })
}

fn sigterm_entry_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^SIGTERM:.*Sent SIGTERM to remaining client pid:\s*(\d+)\s*\((/[^()]*)\)\s*$")
            .unwrap()
    })
}

fn phase_marker_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^%+\s+Entering phase:\s+\S.*$").unwrap())
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

#[derive(Default)]
struct ClientListState {
    seen: usize,
    malformed: bool,
}

fn finish_client_list(active: &mut Option<ClientListState>, invalid_lists: &mut usize) {
    if active
        .take()
        .is_some_and(|list| list.seen == 0 || list.malformed)
    {
        *invalid_lists += 1;
    }
}

fn observe_delay(
    delay: f64,
    previous: &mut Option<f64>,
    current: &mut BTreeSet<String>,
    blocks: &mut Vec<BTreeSet<String>>,
) {
    if previous.is_some_and(|prior| delay < prior) && !current.is_empty() {
        blocks.push(std::mem::take(current));
    }
    *previous = Some(delay);
}

fn record_client(
    pid: &str,
    raw_path: &str,
    strip_ios26_uuid: bool,
    client_pids: &mut BTreeMap<String, BTreeSet<u32>>,
    current: &mut BTreeSet<String>,
    entries: &mut usize,
) -> bool {
    let Ok(pid) = pid.parse::<u32>() else {
        return false;
    };
    // Do not normalize captured path text: trimming a classic `(.../bh )`
    // line can manufacture an IOC match. Internal spaces are legitimate path
    // bytes and remain intact; only ambiguous outer whitespace is rejected.
    if raw_path != raw_path.trim() {
        return false;
    }
    let proc_path = if strip_ios26_uuid {
        // This suffix is proven only for the scoped iOS 26 client-list form.
        strip_uuid_component(raw_path)
    } else {
        raw_path
    }
    .to_string();
    if !proc_path.starts_with('/')
        || proc_path.len() <= 1
        || proc_path[1..]
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return false;
    }
    *entries += 1;
    client_pids
        .entry(proc_path.clone())
        .or_default()
        .insert(pid);
    current.insert(proc_path);
    true
}

pub fn analyze(path: &str, content: &str, db: &IocDb, findings: &mut Findings) -> ArtifactSummary {
    let mut blocks: Vec<BTreeSet<String>> = Vec::new();
    let mut current: BTreeSet<String> = BTreeSet::new();
    let mut client_pids: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    let mut prev_delay: Option<f64> = None;
    let mut entries = 0usize;
    // iOS 26 headers open a scoped indented client list. Every non-empty
    // indented row in that scope must parse; a later classic or SIGTERM entry
    // belongs to a different event and cannot retroactively validate it.
    let mut active_list: Option<ClientListState> = None;
    let mut orphan_headers = 0usize;
    let mut malformed_entries = 0usize;

    for line in content.lines() {
        if let Some(captures) = ios26_header_re().captures(line) {
            finish_client_list(&mut active_list, &mut orphan_headers);
            let delay = captures[1].parse::<f64>().unwrap_or(0.0);
            observe_delay(delay, &mut prev_delay, &mut current, &mut blocks);
            active_list = Some(ClientListState::default());
            continue;
        }

        if let Some(list) = active_list.as_mut() {
            if let Some(captures) = ios26_entry_re().captures(line) {
                if record_client(
                    &captures[1],
                    &captures[2],
                    true,
                    &mut client_pids,
                    &mut current,
                    &mut entries,
                ) {
                    list.seen += 1;
                } else {
                    list.malformed = true;
                    malformed_entries += 1;
                }
                continue;
            }
            if line.trim().is_empty() {
                finish_client_list(&mut active_list, &mut orphan_headers);
                continue;
            }
            if line.starts_with([' ', '\t'])
                || line.trim_start().starts_with("remaining client pid:")
            {
                list.malformed = true;
                malformed_entries += 1;
                continue;
            }
            finish_client_list(&mut active_list, &mut orphan_headers);
        }

        if let Some(captures) = classic_entry_re().captures(line) {
            let delay = captures[1].parse::<f64>().unwrap_or(0.0);
            observe_delay(delay, &mut prev_delay, &mut current, &mut blocks);
            if !record_client(
                &captures[2],
                &captures[3],
                false,
                &mut client_pids,
                &mut current,
                &mut entries,
            ) {
                malformed_entries += 1;
            }
            continue;
        }
        if let Some(captures) = sigterm_entry_re().captures(line) {
            if !record_client(
                &captures[1],
                &captures[2],
                false,
                &mut client_pids,
                &mut current,
                &mut entries,
            ) {
                malformed_entries += 1;
            }
            continue;
        }
        if line.contains("remaining client pid:") {
            malformed_entries += 1;
        }
    }
    finish_client_list(&mut active_list, &mut orphan_headers);
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
                    "Process \u{2018}{}\u{2019} held up device shutdown - its observed name or path matches a published {} indicator",
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

    // Structural success requires recognizing the format at all: an empty
    // or garbage file has zero entries too, and treating it as a normally
    // parsed surface would let "nothing found" read as "nothing there".
    // A real shutdown.log with no delayed clients still carries an anchored
    // phase marker. Recognition is limited to complete known line shapes:
    // substring matches such as "garbage After 1.0s garbage" must not turn
    // arbitrary text into a successfully parsed detection surface.
    let recognized = entries > 0
        || content.lines().any(|line| {
            phase_marker_re().is_match(line)
                || ios26_header_re().is_match(line)
                || ios26_entry_re().is_match(line)
                || classic_entry_re().is_match(line)
                || sigterm_entry_re().is_match(line)
        });
    let details = json!({
        "reboot_blocks": blocks.len(),
        "unique_clients": client_pids.len(),
        "entries": entries,
        "orphan_headers": orphan_headers,
        "malformed_entries": malformed_entries,
    });
    if !recognized {
        ArtifactSummary::problem(path, "shutdown_log", "unparsed", details)
    } else if orphan_headers > 0 || malformed_entries > 0 {
        ArtifactSummary::problem(path, "shutdown_log", "parsed_partial", details)
    } else {
        ArtifactSummary::parsed(path, "shutdown_log", details)
    }
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
        assert_eq!(summary.status, "parsed");
        assert_eq!(summary.details["reboot_blocks"], 2);
        assert_eq!(summary.details["unique_clients"], 2);
    }

    #[test]
    fn unrecognizable_content_is_unparsed_not_parsed() {
        let mut findings = Findings::new();
        // empty file: zero entries must not read as a checked surface
        let summary = analyze("shutdown.log", "", &IocDb::new(), &mut findings);
        assert_eq!(summary.status, "unparsed");
        // garbage text: same
        let summary = analyze(
            "shutdown.log",
            "not a shutdown log\nat all\n",
            &IocDb::new(),
            &mut findings,
        );
        assert_eq!(summary.status, "unparsed");
        for garbage in [
            "garbage After 1.0s garbage\n",
            "not-a-log SIGTERM text\n",
            "prefix %%%%% Entering phase: Waiting for apps to exit\n",
        ] {
            let summary = analyze("shutdown.log", garbage, &IocDb::new(), &mut findings);
            assert_eq!(summary.status, "unparsed", "content: {garbage:?}");
        }
        // a real log with phase markers but no delayed clients is a
        // legitimate quick shutdown, and stays parsed
        let summary = analyze(
            "shutdown.log",
            "%%%%% Entering phase: Waiting for apps to exit\n",
            &IocDb::new(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed");
        assert_eq!(summary.details["entries"], 0);
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
        assert_eq!(summary.status, "parsed");
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
    fn directory_path_match_summary_does_not_claim_a_name_match() {
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"malware","name":"Pegasus"},{"type":"indicator","pattern":"[file:path='/private/var/db/com.apple.xpc.roleaccountd.staging/']"}]}"#,
        )
        .unwrap();
        let mut findings = Findings::new();
        analyze("shutdown.log", SAMPLE, &db, &mut findings);

        let matched = findings
            .iter()
            .find(|finding| finding.severity == Severity::Match)
            .unwrap();
        assert!(matched.summary.contains("observed name or path matches"));
        assert!(!matched.summary.contains("its name matches"));
    }

    #[test]
    fn header_without_parsed_clients_is_parsed_partial() {
        // The header announces clients, but the client-line wording drifted:
        // the process paths those lines carry were never read. Treating this
        // as fully parsed would let an infected device read as clear.
        const DRIFTED: &str = "\
After 1.26s, these clients are still here:
\t\tstill held by pid 2143 (/private/var/db/com.apple.xpc.roleaccountd.staging/bh)
";
        let mut findings = Findings::new();
        let summary = analyze("shutdown.0.log", DRIFTED, &db_with_bh(), &mut findings);
        assert_eq!(summary.status, "parsed_partial");
        assert_eq!(summary.details["entries"], 0);
        assert_eq!(summary.details["orphan_headers"], 1);
        // a header list where only SOME headers lost their clients is
        // partial too
        const MIXED: &str = "\
After 1.26s, these clients are still here:
\t\tremaining client pid: 155 (/usr/libexec/nfcd)
After 1.77s, these clients are still here:
\t\tgone missing
";
        let mut findings = Findings::new();
        let summary = analyze("shutdown.0.log", MIXED, &IocDb::new(), &mut findings);
        assert_eq!(summary.status, "parsed_partial");
        assert_eq!(summary.details["orphan_headers"], 1);
    }

    #[test]
    fn mixed_valid_and_drifted_clients_is_partial() {
        const MIXED_CLIENTS: &str = "\
After 1.26s, these clients are still here:
\t\tremaining client pid: 155 (/usr/libexec/nfcd)
\t\tstill held by pid 2143 (/private/var/db/com.apple.xpc.roleaccountd.staging/bh)
";
        let mut findings = Findings::new();
        let summary = analyze(
            "shutdown.0.log",
            MIXED_CLIENTS,
            &db_with_bh(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed_partial");
        assert_eq!(summary.details["entries"], 1);
        assert_eq!(summary.details["orphan_headers"], 1);
        assert_eq!(summary.details["malformed_entries"], 1);
        assert!(!findings
            .iter()
            .any(|finding| finding.severity == Severity::Match));
    }

    #[test]
    fn orphan_ios26_header_is_not_cleared_by_later_classic_entry() {
        const ORPHAN_THEN_CLASSIC: &str = "\
After 1.26s, these clients are still here:
After 1.77s, remaining client pid: 155 (/usr/libexec/nfcd)
";
        let mut findings = Findings::new();
        let summary = analyze(
            "shutdown.0.log",
            ORPHAN_THEN_CLASSIC,
            &IocDb::new(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed_partial");
        assert_eq!(summary.details["entries"], 1);
        assert_eq!(summary.details["orphan_headers"], 1);
    }

    #[test]
    fn malformed_matching_client_line_keeps_listing_partial() {
        for client in [
            "\t\tremaining client pid: 2143 (/private/var/tmp/bh) junk (x)",
            "\t\tremaining client pid: 2143 (relative/path)",
            "\t\tremaining client pid: 2143 (/safe/../bh)",
            "\t\tremaining client pid: 2143 (/safe//bh)",
        ] {
            let sample = format!("After 1.26s, these clients are still here:\n{client}\n");
            let mut findings = Findings::new();
            let summary = analyze("shutdown.0.log", &sample, &db_with_bh(), &mut findings);
            assert_eq!(summary.status, "parsed_partial", "client: {client}");
            assert_eq!(summary.details["entries"], 0);
            assert_eq!(summary.details["malformed_entries"], 1);
            assert!(findings.is_empty());
        }
    }

    #[test]
    fn classic_path_with_outer_whitespace_is_not_normalized() {
        const PADDED: &str = "After 0.1s, remaining client pid: 2143 (/private/var/tmp/bh )\n";
        let mut findings = Findings::new();
        let summary = analyze("shutdown.log", PADDED, &db_with_bh(), &mut findings);
        assert_eq!(summary.status, "parsed_partial");
        assert_eq!(summary.details["entries"], 0);
        assert_eq!(summary.details["malformed_entries"], 1);
        assert!(!findings
            .iter()
            .any(|finding| finding.severity == Severity::Match));
    }

    #[test]
    fn classic_noncanonical_path_is_partial_and_cannot_match() {
        const AMBIGUOUS: &str = "After 0.1s, remaining client pid: 2143 (/safe/../bh)\n";
        let mut findings = Findings::new();
        let summary = analyze("shutdown.log", AMBIGUOUS, &db_with_bh(), &mut findings);
        assert_eq!(summary.status, "parsed_partial");
        assert_eq!(summary.details["entries"], 0);
        assert_eq!(summary.details["malformed_entries"], 1);
        assert!(!findings
            .iter()
            .any(|finding| finding.severity == Severity::Match));
    }

    #[test]
    fn classic_and_sigterm_paths_do_not_strip_uuid_components() {
        const UUID: &str = "AAAA1111-B896-3E7F-A6CC-577F0A547BB1";
        for line in [
            format!(
                "After 0.1s, remaining client pid: 2143 (/private/var/db/com.apple.xpc.roleaccountd.staging/bh/{UUID})\n"
            ),
            format!(
                "SIGTERM: [0x1] Sent SIGTERM to remaining client pid: 2143 (/private/var/db/com.apple.xpc.roleaccountd.staging/bh/{UUID})\n"
            ),
        ] {
            let mut findings = Findings::new();
            let summary = analyze("shutdown.log", &line, &db_with_bh(), &mut findings);
            assert_eq!(summary.status, "parsed", "line: {line}");
            assert_eq!(summary.details["entries"], 1);
            assert!(
                !findings
                    .iter()
                    .any(|finding| finding.severity == Severity::Match),
                "line: {line}"
            );
        }
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
