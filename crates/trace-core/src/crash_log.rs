//! .ips crash and diagnostic analysis. Modern crash logs are two JSON
//! documents: a one-line summary header, then the full payload. Ancillary
//! formats can instead carry a process inventory, a validated text preamble,
//! or metadata with no process identity. Process-bearing fields are checked
//! against indicators; unknown or structurally incomplete formats stay partial.

use crate::heuristics::{path_flag, path_flag_finding, PathFlag};
use crate::ioc::{basename, IocDb, IocKind};
use crate::report::{ArtifactSummary, DeviceInfo, Finding, Findings, Severity};
use regex_lite::Regex;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

fn str_field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(|x| x.as_str())
}

fn labeled_value<'a>(line: &'a str, label: &str) -> Option<&'a str> {
    let value = line.strip_prefix(label)?.strip_prefix(':')?.trim();
    (!value.is_empty()).then_some(value)
}

fn parent_process(value: &str) -> Option<&str> {
    let (name, pid) = value.rsplit_once(" [")?;
    pid.strip_suffix(']')?.parse::<u64>().ok()?;
    let name = name.trim();
    (!name.is_empty() && !name.contains(char::is_whitespace)).then_some(name)
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
    findings: &mut Findings,
) -> (ArtifactSummary, Option<DeviceInfo>) {
    let (first_line, rest) = match content.split_once('\n') {
        Some((a, b)) => (a, b),
        None => (content, ""),
    };
    let header: Option<Value> = serde_json::from_str(first_line.trim()).ok();
    let body: Option<Value> = serde_json::from_str(rest.trim()).ok();

    let mut candidates: BTreeSet<String> = BTreeSet::new();
    let mut candidate_pids: BTreeMap<String, u64> = BTreeMap::new();
    let mut proc_path: Option<String> = None;
    let mut proc_name: Option<String> = None;
    let mut bug_type: Option<String> = None;
    let mut timestamp: Option<String> = None;
    let mut os_version: Option<String> = None;
    let mut format = "crash";
    let mut special_format = false;
    let mut special_complete = false;
    let mut processes_seen = 0usize;
    let mut skipped_processes = 0usize;
    let mut detection_relevant = true;

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

    // Several .ips families are diagnostics rather than single-process crash
    // reports. Dispatch on their documented bug type and validate the whole
    // process-bearing shape before allowing the artifact to count as parsed.
    // Valid rows still produce findings when a sibling row is malformed, but
    // any malformed row keeps the artifact partial and the verdict fail-closed.
    match bug_type.as_deref() {
        Some(kind) if kind == "288" || kind == "151" => {
            special_format = true;
            format = if kind == "288" {
                "stacks"
            } else {
                "force_reset"
            };
            if let Some(inventory) = body
                .as_ref()
                .filter(|b| {
                    b.get("bug_type")
                        .is_none_or(|value| value.as_str() == Some(kind))
                })
                .and_then(|b| b.get("processByPid"))
                .and_then(Value::as_object)
            {
                for (pid_key, entry) in inventory {
                    let Some(key_pid) = pid_key.parse::<u64>().ok() else {
                        skipped_processes += 1;
                        continue;
                    };
                    let Some(pid) = entry.get("pid").and_then(Value::as_u64) else {
                        skipped_processes += 1;
                        continue;
                    };
                    let Some(name) = entry
                        .get("procname")
                        .and_then(Value::as_str)
                        .filter(|name| !name.is_empty())
                    else {
                        skipped_processes += 1;
                        continue;
                    };
                    if pid != key_pid {
                        skipped_processes += 1;
                        continue;
                    }
                    let name = name.to_string();
                    candidates.insert(name.clone());
                    candidate_pids.entry(name).or_insert(pid);
                    processes_seen += 1;
                }
                special_complete = !inventory.is_empty() && skipped_processes == 0;
            }
        }
        Some("298") => {
            special_format = true;
            format = "jetsam";
            if let Some(inventory) = body
                .as_ref()
                .filter(|b| {
                    b.get("bug_type")
                        .is_none_or(|value| value.as_str() == Some("298"))
                })
                .and_then(|b| b.get("processes"))
                .and_then(Value::as_array)
            {
                for entry in inventory {
                    let Some(pid) = entry.get("pid").and_then(Value::as_u64) else {
                        skipped_processes += 1;
                        continue;
                    };
                    let Some(name) = entry
                        .get("name")
                        .and_then(Value::as_str)
                        .filter(|name| !name.is_empty())
                    else {
                        skipped_processes += 1;
                        continue;
                    };
                    let name = name.to_string();
                    candidates.insert(name.clone());
                    candidate_pids.entry(name).or_insert(pid);
                    processes_seen += 1;
                }
                special_complete = !inventory.is_empty() && skipped_processes == 0;
            }
        }
        Some("313") => {
            special_format = true;
            format = "siri_search_feedback";
            detection_relevant = false;
            candidates.clear();
            proc_name = None;
            proc_path = None;
            special_complete = body
                .as_ref()
                .and_then(Value::as_object)
                .is_some_and(|object| {
                    object.len() == 4
                        && object.get("agent").is_some_and(Value::is_string)
                        && object.get("country_code").is_some_and(Value::is_string)
                        && object.get("session_start").is_some_and(Value::is_number)
                        && object.get("user_guid").is_some_and(Value::is_string)
                });
        }
        Some("115") => {
            special_format = true;
            format = "reset_counter";
            detection_relevant = false;
            candidates.clear();
            proc_name = None;
            proc_path = None;

            let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
            let mut malformed = false;
            for line in rest.lines() {
                let Some((label, value)) = line.split_once(':') else {
                    malformed = true;
                    continue;
                };
                if !matches!(
                    label,
                    "Incident Identifier"
                        | "CrashReporter Key"
                        | "Date"
                        | "Reset count"
                        | "Boot failure count"
                        | "Boot faults"
                        | "Boot stage"
                        | "Boot app"
                ) || fields.insert(label, value.trim()).is_some()
                {
                    malformed = true;
                }
            }
            let incident_valid = fields.get("Incident Identifier").is_some_and(|value| {
                value.len() == 36
                    && value.bytes().enumerate().all(|(index, byte)| {
                        if matches!(index, 8 | 13 | 18 | 23) {
                            byte == b'-'
                        } else {
                            byte.is_ascii_hexdigit()
                        }
                    })
            });
            special_complete = !malformed
                && fields.len() == 8
                && header
                    .as_ref()
                    .is_some_and(|h| str_field(h, "name") == Some("Reset count"))
                && incident_valid
                && fields.get("CrashReporter Key").is_some_and(|value| {
                    value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())
                })
                && fields.get("Date").is_some_and(|value| !value.is_empty())
                && fields
                    .get("Reset count")
                    .is_some_and(|value| value.parse::<u64>().is_ok())
                && fields
                    .get("Boot failure count")
                    .is_some_and(|value| value.parse::<u64>().is_ok())
                && fields.contains_key("Boot faults")
                && fields
                    .get("Boot stage")
                    .is_some_and(|value| value.parse::<u64>().is_ok())
                && fields
                    .get("Boot app")
                    .is_some_and(|value| value.parse::<u64>().is_ok());
        }
        Some("145") => {
            special_format = true;
            format = "disk_writes";
            let mut commands = Vec::new();
            let mut paths = Vec::new();
            let mut parents = Vec::new();
            let mut pids = Vec::new();
            let mut report_versions = Vec::new();
            let mut events = Vec::new();
            let mut saw_steps = false;
            for line in rest.lines() {
                if line.strip_prefix("Steps:").is_some() {
                    saw_steps = true;
                    break;
                }
                for (label, output) in [
                    ("Command", &mut commands),
                    ("Path", &mut paths),
                    ("Parent", &mut parents),
                    ("PID", &mut pids),
                    ("Report Version", &mut report_versions),
                    ("Event", &mut events),
                ] {
                    if let Some(value) = labeled_value(line, label) {
                        output.push(value);
                    }
                }
            }
            let parent = match parents.as_slice() {
                [] => Some(None),
                [value] => parent_process(value).map(Some),
                _ => None,
            };
            // Command + absolute Path are independently useful exact evidence.
            // Preserve them even when unrelated metadata makes the report
            // partial; completeness still controls only whether the artifact
            // can contribute to a clear verdict.
            let identity = if commands.len() == 1
                && paths.len() == 1
                && paths[0].starts_with('/')
                && basename(paths[0]) == commands[0]
            {
                Some((commands[0], paths[0]))
            } else {
                None
            };
            if let Some((command, process_path)) = identity {
                candidates.insert(command.to_string());
                candidates.insert(process_path.to_string());
                candidates.insert(basename(process_path).to_string());
                proc_name = Some(command.to_string());
                proc_path = Some(process_path.to_string());
                processes_seen = 1;
            }
            if let Some(Some(parent)) = parent {
                candidates.insert(parent.to_string());
            }

            let valid = identity.is_some()
                && pids.len() == 1
                && report_versions.len() == 1
                && events.len() == 1
                && saw_steps
                && pids[0].parse::<u64>().is_ok()
                && report_versions[0].parse::<u64>().is_ok()
                && events[0]
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .eq_ignore_ascii_case("disk writes")
                && header.as_ref().is_some_and(|h| {
                    str_field(h, "name") == Some(commands[0])
                        && str_field(h, "app_name") == Some(commands[0])
                })
                && parent.is_some();
            special_complete = valid;
        }
        _ => {}
    }

    // Kernel panics (bug_type 210) carry their signal inside panicString
    // rather than procName. Process names in it look like "pid 282: bh" or
    // "pid 282 (bh)"; extract them as match candidates. Candidates are only
    // ever compared by exact equality against the indicator set, so noisy
    // extraction cannot create false positives.
    let mut panic_staging = false;
    let mut panic_signal = false;
    if !special_format {
        if let Some(ps) = body.as_ref().and_then(|b| str_field(b, "panicString")) {
            panic_staging = ps
                .split_ascii_whitespace()
                .map(|token| {
                    token.trim_matches(|c: char| {
                        matches!(c, '(' | ')' | ',' | ';' | ':' | '"' | '\'')
                    })
                })
                .any(|token| path_flag(token) == Some(PathFlag::Staging));
            for cap in panic_pid_re().captures_iter(ps) {
                candidates.insert(cap[2].to_string());
                panic_signal = true;
            }
        }
    }

    // The filename itself encodes the crashing process for ordinary crash
    // logs, which survives even when the JSON fails to parse. Ancillary
    // diagnostics are named after their format, not a process.
    let fname = basename(path);
    if !special_format {
        if let Some(name) = filename_process(fname) {
            candidates.insert(name.to_string());
        }
    }

    // The body is the substantive document (procPath, parentProc,
    // panicString); a crash whose body did not parse had most of its
    // signal unchecked, and must not count as a fully analyzed artifact
    // even when the one-line header parsed. Parsing alone is not enough:
    // syntactically valid JSON that names no crashing process ("{}") was
    // never really checked either - every real crash log identifies its
    // process (procName/procPath) or, for kernel panics, names pids in
    // the panic string.
    let identified = proc_name.is_some() || proc_path.is_some() || panic_signal;
    if !special_format {
        processes_seen = usize::from(identified);
        if panic_signal {
            format = "kernel_panic";
        }
    }
    let status = if if special_format {
        special_complete
    } else {
        body.is_some() && identified
    } {
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
        "format": format,
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
            let evidence = candidate_pids.get(cand).map_or_else(
                || evidence_base.clone(),
                |pid| {
                    json!({
                        "crash_file": fname,
                        "process": cand,
                        "pid": pid,
                        "bug_type": bug_type,
                        "timestamp": timestamp,
                        "format": format,
                    })
                },
            );
            findings.push(Finding::ioc_match(
                path,
                format!(
                    "iOS diagnostic involves process \u{2018}{}\u{2019} - matches a published {} indicator",
                    shown, ind.campaign
                ),
                evidence,
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
        timestamp: timestamp.clone(),
    });

    (
        ArtifactSummary::problem(
            path,
            "crash_log",
            status,
            json!({
                "process": proc_name,
                "process_path": proc_path,
                "bug_type": bug_type,
                "timestamp": timestamp,
                "os_version": os_version,
                "format": format,
                "processes": processes_seen,
                "skipped_processes": skipped_processes,
                "detection_relevant": detection_relevant,
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
        let mut findings = Findings::new();
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
        let mut findings = Findings::new();
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
    fn kernel_panic_nested_roleaccount_workspace_is_not_suspicious() {
        let panic = r#"{"name":"kernel","bug_type":"210"}
{"panicString":"pid 20: UpdateBrainService ran from /private/var/db/com.apple.xpc.roleaccountd.staging/exec/16777224.1.xpc/com.apple.NRD.UpdateBrainService"}"#;
        let mut findings = Findings::new();
        analyze(
            "root/crashes_and_spins/Panics/panic-full-2026-07-06.ips",
            panic,
            &IocDb::new(),
            &mut findings,
        );
        assert!(!findings
            .iter()
            .any(|finding| finding.severity == Severity::Suspicious));
    }

    #[test]
    fn file_path_indicator_matches_full_proc_path() {
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"malware","name":"Pegasus"},{"type":"indicator","pattern":"[file:path='/private/var/db/com.apple.xpc.roleaccountd.staging/bh']"}]}"#,
        )
        .unwrap();
        let mut findings = Findings::new();
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
        let mut findings = Findings::new();
        analyze(
            "root/crashes_and_spins/agent-2026.ips",
            sample,
            &IocDb::new(),
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        let f = findings.iter().next().unwrap();
        assert_eq!(f.severity, Severity::Note);
        assert!(f.summary.contains("/private/var/tmp/agent"));
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
        let mut findings = Findings::new();
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
    fn header_only_crash_is_parsed_partial() {
        // A valid header with a malformed body means procPath, parentProc,
        // and panicString were never checked: not a fully parsed artifact.
        let sample = r#"{"name":"app","bug_type":"309","os_version":"iPhone OS 17.2.1 (21C66)"}
not json"#;
        let mut findings = Findings::new();
        let (summary, device) = analyze(
            "root/crashes_and_spins/app-2026.ips",
            sample,
            &IocDb::new(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed_partial");
        // the header's os_version is still harvested
        assert_eq!(device.unwrap().os_version, "iPhone OS 17.2.1 (21C66)");
    }

    #[test]
    fn benign_crash_produces_no_findings() {
        let benign = r#"{"app_name":"MobileSafari","name":"MobileSafari","bug_type":"309","os_version":"iPhone OS 17.2.1 (21C66)"}
{"procName":"MobileSafari","procPath":"/Applications/MobileSafari.app/MobileSafari","parentProc":"launchd"}"#;
        let mut findings = Findings::new();
        analyze(
            "root/crashes_and_spins/MobileSafari-2026.ips",
            benign,
            &db_with_bh(),
            &mut findings,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn jetsam_inventory_checks_every_process() {
        let sample = r#"{"bug_type":"298","timestamp":"2026-07-08 13:32:34.00 -0700","os_version":"iPhone OS 26.5.2 (23F84)"}
{"bug_type":"298","processes":[{"name":"launchd","pid":1},{"name":"bh","pid":2143}]}"#;
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/JetsamEvent-2026-07-08-133234.ips",
            sample,
            &db_with_bh(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed");
        assert_eq!(summary.details["format"], "jetsam");
        assert_eq!(summary.details["processes"], 2);
        assert_eq!(summary.details["skipped_processes"], 0);
        let hit = findings
            .iter()
            .find(|f| f.severity == Severity::Match)
            .unwrap();
        assert_eq!(hit.evidence["process"], "bh");
        assert_eq!(hit.evidence["pid"], 2143);
    }

    #[test]
    fn malformed_jetsam_record_is_partial_but_valid_matches_survive() {
        let sample = r#"{"bug_type":"298"}
{"bug_type":"298","processes":[{"name":"bh","pid":2143},{"pid":9}]}"#;
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/JetsamEvent-2026.ips",
            sample,
            &db_with_bh(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed_partial");
        assert_eq!(summary.details["processes"], 1);
        assert_eq!(summary.details["skipped_processes"], 1);
        assert!(findings.iter().any(|f| f.severity == Severity::Match));
    }

    #[test]
    fn stacks_inventory_checks_every_process() {
        let sample = r#"{"bug_type":"288","timestamp":"2026-07-08 13:44:37.00 -0700","os_version":"iPhone OS 26.5.2 (23F84)"}
{"processByPid":{"1":{"pid":1,"procname":"launchd"},"2143":{"pid":2143,"procname":"bh"}}}"#;
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/stacks-2026-07-08-134437.ips",
            sample,
            &db_with_bh(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed");
        assert_eq!(summary.details["format"], "stacks");
        assert_eq!(summary.details["processes"], 2);
        let hit = findings
            .iter()
            .find(|f| f.severity == Severity::Match)
            .unwrap();
        assert_eq!(hit.evidence["process"], "bh");
        assert_eq!(hit.evidence["pid"], 2143);
    }

    #[test]
    fn stacks_pid_mismatch_is_partial() {
        let sample = r#"{"bug_type":"288"}
{"bug_type":"288","processByPid":{"1":{"pid":1,"procname":"launchd"},"2143":{"pid":99,"procname":"bh"}}}"#;
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/stacks-2026.ips",
            sample,
            &db_with_bh(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed_partial");
        assert_eq!(summary.details["processes"], 1);
        assert_eq!(summary.details["skipped_processes"], 1);
        assert!(!findings.iter().any(|f| f.severity == Severity::Match));
    }

    #[test]
    fn force_reset_inventory_checks_every_process() {
        let sample = r#"{"bug_type":"151","timestamp":"2023-05-24 13:22:01.00 -0700","os_version":"iPhone OS 15.7.6 (19H349)"}
{"processByPid":{"0":{"pid":0,"procname":"kernel_task"},"2143":{"pid":2143,"procname":"bh"}}}"#;
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/forceReset-full-2023-05-24.ips",
            sample,
            &db_with_bh(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed");
        assert_eq!(summary.details["format"], "force_reset");
        assert_eq!(summary.details["processes"], 2);
        assert!(findings.iter().any(|f| f.severity == Severity::Match));
    }

    #[test]
    fn reset_counter_is_recognized_without_inventing_a_process() {
        let sample = r#"{"bug_type":"115","name":"Reset count","timestamp":"2023-05-24 13:22:07.00 -0700","os_version":"iPhone OS 15.7.6 (19H349)"}
Incident Identifier: AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE
CrashReporter Key: 0123456789abcdef0123456789abcdef01234567
Date: 2023-05-24 13:22:07.00 -0700
Reset count: 1
Boot failure count: 0
Boot faults:
Boot stage: 0
Boot app: 0
"#;
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"indicator","pattern":"[process:name='Reset count']"},{"type":"indicator","pattern":"[process:name='ResetCounter']"}]}"#,
        )
        .unwrap();
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/ResetCounter-2023-05-24.ips",
            sample,
            &db,
            &mut findings,
        );
        assert_eq!(summary.status, "parsed");
        assert_eq!(summary.details["format"], "reset_counter");
        assert_eq!(summary.details["processes"], 0);
        assert_eq!(summary.details["detection_relevant"], false);
        assert!(findings.is_empty());
    }

    #[test]
    fn reset_counter_schema_drift_is_partial() {
        let sample = r#"{"bug_type":"115","name":"Reset count"}
Incident Identifier: AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE
CrashReporter Key: 0123456789abcdef0123456789abcdef01234567
Date: 2023-05-24 13:22:07.00 -0700
Reset count: 1
Boot failure count: 0
Boot faults:
Boot stage: 0
Boot app: 0
New field: 1
"#;
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/ResetCounter-2023-05-24.ips",
            sample,
            &IocDb::new(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed_partial");
    }

    #[test]
    fn disk_writes_report_checks_validated_command_and_first_path() {
        let sample = r#"{"app_name":"bh","name":"bh","bug_type":"145","timestamp":"2026-07-08 10:43:44.00 -0700","os_version":"iPhone OS 26.5.2 (23F84)"}
Date/Time: 2026-07-08
Report Version: 12
Command: bh
Path: /private/var/db/com.apple.xpc.roleaccountd.staging/bh
Parent: launchd [1]
PID: 2143
Event: disk writes
Steps: 20
Path: /System/Library/Frameworks/NotTheExecutable.framework/NotTheExecutable
"#;
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"indicator","pattern":"[file:path='/private/var/db/com.apple.xpc.roleaccountd.staging/bh']"}]}"#,
        )
        .unwrap();
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/bh.diskwrites_resource-2026-07-08.ips",
            sample,
            &db,
            &mut findings,
        );
        assert_eq!(summary.status, "parsed");
        assert_eq!(summary.details["format"], "disk_writes");
        assert_eq!(summary.details["process"], "bh");
        assert_eq!(
            summary.details["process_path"],
            "/private/var/db/com.apple.xpc.roleaccountd.staging/bh"
        );
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
    fn disk_writes_identity_mismatch_is_partial() {
        let sample = r#"{"app_name":"searchd","name":"searchd","bug_type":"145"}
Report Version: 12
Command: otherd
Path: /System/Library/PrivateFrameworks/Search.framework/searchd
PID: 2143
Event: disk writes
Steps: 20
"#;
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/searchd.diskwrites_resource-2026.ips",
            sample,
            &IocDb::new(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed_partial");
    }

    #[test]
    fn partial_disk_writes_report_preserves_exact_path_evidence() {
        let sample = r#"{"app_name":"bh","name":"bh","bug_type":"145"}
Report Version: malformed
Command: bh
Path: /private/var/db/com.apple.xpc.roleaccountd.staging/bh
PID: 2143
Event: disk writes
Steps: 20
"#;
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"indicator","pattern":"[file:path='/private/var/db/com.apple.xpc.roleaccountd.staging/bh']"}]}"#,
        )
        .unwrap();
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/bh.diskwrites_resource-2026.ips",
            sample,
            &db,
            &mut findings,
        );
        assert_eq!(summary.status, "parsed_partial");
        assert_eq!(
            summary.details["process_path"],
            "/private/var/db/com.apple.xpc.roleaccountd.staging/bh"
        );
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.severity == Severity::Match)
                .count(),
            1
        );
    }

    #[test]
    fn siri_feedback_is_recognized_without_inventing_a_process() {
        let sample = r#"{"bug_type":"313","timestamp":"2026-07-08 13:22:15.00 -0700","os_version":"iPhone OS 26.5.2 (23F84)"}
{"agent":"opaque-session-agent","country_code":"US","session_start":12345,"user_guid":"opaque-guid"}"#;
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"indicator","pattern":"[process:name='SiriSearchFeedback']"}]}"#,
        )
        .unwrap();
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/SiriSearchFeedback-2026-07-08.ips",
            sample,
            &db,
            &mut findings,
        );
        assert_eq!(summary.status, "parsed");
        assert_eq!(summary.details["format"], "siri_search_feedback");
        assert_eq!(summary.details["processes"], 0);
        assert_eq!(summary.details["detection_relevant"], false);
        assert!(findings.is_empty());
    }

    #[test]
    fn siri_feedback_schema_drift_is_partial() {
        let sample = r#"{"bug_type":"313"}
{"agent":"opaque-session-agent","country_code":"US","session_start":12345,"user_guid":"opaque-guid","new_field":true}"#;
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/SiriSearchFeedback-2026.ips",
            sample,
            &IocDb::new(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed_partial");
    }
}
