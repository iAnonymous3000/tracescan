//! ps.txt / ps_thread.txt analysis. Sysdiagnose captures a full `ps` process
//! listing; implant process names occasionally appear here directly. The
//! COMMAND value in ps.txt is recovered by skipping the header's count of
//! preceding fields, so commands containing spaces survive and rows whose
//! numeric fields outgrow their printf column widths (shifting the row
//! right) cannot silently mis-slice the command. ps_thread has an
//! abbreviated COMMAND column (which may itself contain spaces, ruling out
//! simple field counting) and a final full-path COMMAND column. The boundary
//! is recovered from the typed ten-field suffix between those columns, so
//! numeric width overflow cannot turn TIME or another field into a command;
//! only process rows from the final COMMAND are analyzed (thread rows are
//! skipped).

use crate::heuristics::path_flag_finding;
use crate::ioc::{basename, IocDb};
use crate::report::{ArtifactSummary, Finding, Findings};
use serde_json::json;
use std::collections::BTreeSet;

/// The remainder of `line` after `skip` whitespace-separated fields. Every
/// pre-COMMAND ps field is space-free, so field counting stays correct even
/// when a value overflows its padded column width.
fn field_rest(line: &str, skip: usize) -> Option<&str> {
    let mut rest = line.trim_start_matches([' ', '\t']);
    for _ in 0..skip {
        let cut = rest.find([' ', '\t'])?;
        rest = rest[cut..].trim_start_matches([' ', '\t']);
    }
    let rest = rest.trim_end_matches([' ', '\t']);
    (!rest.is_empty()).then_some(rest)
}

/// Whitespace-delimited fields paired with their byte start in the original
/// line. ps output is ASCII-columnar, but commands may contain non-ASCII; the
/// byte scanner only slices at ASCII whitespace boundaries.
fn field_spans(line: &str) -> Vec<(usize, &str)> {
    let bytes = line.as_bytes();
    let mut fields = Vec::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor == bytes.len() {
            break;
        }
        let start = cursor;
        while cursor < bytes.len() && !bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        fields.push((start, &line[start..cursor]));
    }
    fields
}

fn ps_time(value: &str) -> bool {
    value.contains(':')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b':' | b'.' | b'-'))
}

fn ps_flags(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_argv0(value: &str) -> bool {
    if !value.contains('/') {
        return !value.is_empty();
    }
    value.starts_with('/')
        && value
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}

/// Validate known typed columns before ps.txt's COMMAND field. Field-count
/// recovery alone is unsafe when a numeric value is missing: the executable
/// path can slide into PPID (or another typed column) and a trailing argument
/// can then be misread as COMMAND while the row is still reported as parsed.
fn valid_ps_prefix(columns: &[&str], fields: &[(usize, &str)]) -> bool {
    fields.len() > columns.len()
        && columns.iter().zip(fields).all(|(column, (_, value))| {
            // No metadata column in the supported layouts is a path. This
            // catches missing columns even when the shifted destination is
            // a string field we do not otherwise type.
            if value.starts_with('/') {
                return false;
            }
            match *column {
                "UID" | "RUID" | "EUID" | "SVUID" | "GID" | "RGID" | "EGID" | "SVGID" | "PID"
                | "PPID" | "PGID" | "SID" => value.parse::<u32>().is_ok(),
                "TPGID" | "NI" => value.parse::<i32>().is_ok(),
                "%CPU" | "%MEM" => value.parse::<f64>().is_ok_and(|number| number.is_finite()),
                "VSZ" | "RSS" => value.parse::<u64>().is_ok(),
                "F" => ps_flags(value),
                "STAT" | "STATE" => {
                    let mut state = value.chars();
                    // '?' is the primary state iOS reports for essentially
                    // every process in a real sysdiagnose ps.txt ("?s", "?"):
                    // the standard BSD run-state letters do not appear there.
                    // Omitting it rejected every row of a genuine iOS capture.
                    state.next().is_some_and(|first| {
                        matches!(first, 'D' | 'I' | 'R' | 'S' | 'T' | 'U' | 'Z' | '?')
                    }) && state.all(|modifier| {
                        matches!(
                            modifier,
                            '+' | '<'
                                | '>'
                                | 'A'
                                | 'E'
                                | 'L'
                                | 'N'
                                | 'S'
                                | 'V'
                                | 'W'
                                | 'X'
                                | 's'
                                | 'l'
                        )
                    })
                }
                // STIME is ambiguous across BSD ps layouts (start instant
                // in some, CPU duration in others), so only unambiguous
                // duration columns are checked here.
                "UTIME" | "TIME" => ps_time(value),
                _ => true,
            }
        })
}

/// Validate the fields between ps_thread's abbreviated and full COMMAND:
/// PPID F %MEM PRI NI VSZ RSS WCHAN STARTED TIME.
fn valid_thread_tail(fields: &[(usize, &str)], start: usize) -> bool {
    let Some(tail) = fields.get(start..start.saturating_add(10)) else {
        return false;
    };
    tail.len() == 10
        && tail[0].1.parse::<u32>().is_ok()
        && ps_flags(tail[1].1)
        && tail[2].1.parse::<f64>().is_ok()
        && !tail[3].1.is_empty()
        && tail[4].1.parse::<i32>().is_ok()
        && tail[5].1.parse::<u64>().is_ok()
        && tail[6].1.parse::<u64>().is_ok()
        && !tail[7].1.is_empty()
        && !tail[8].1.is_empty()
        && ps_time(tail[9].1)
}

fn thread_command<'a>(
    line: &'a str,
    fields: &[(usize, &'a str)],
    pre_command_fields: usize,
) -> Option<&'a str> {
    let mut command_starts = Vec::new();
    // At least one token belongs to the abbreviated COMMAND, ten to the
    // typed suffix, and one to the full COMMAND.
    let first_tail = pre_command_fields.saturating_add(1);
    for tail_start in first_tail..fields.len().saturating_sub(10) {
        if valid_thread_tail(fields, tail_start) {
            if let Some((command_start, _)) = fields.get(tail_start + 10) {
                command_starts.push(*command_start);
            }
        }
    }
    match command_starts.as_slice() {
        [start] => Some(line[*start..].trim()),
        _ => None,
    }
}

fn valid_thread_continuation(fields: &[(usize, &str)], previous_pid: Option<&str>) -> bool {
    let Some((_, pid)) = fields.first() else {
        return false;
    };
    if pid.parse::<u32>().is_err() || previous_pid != Some(*pid) || fields.len() < 12 {
        return false;
    }
    let tail_start = fields.len() - 10;
    tail_start >= 2
        && ps_time(fields[tail_start - 2].1)
        && ps_time(fields[tail_start - 1].1)
        && valid_thread_tail(fields, tail_start)
}

pub fn analyze(path: &str, content: &str, db: &IocDb, findings: &mut Findings) -> ArtifactSummary {
    let Some((header, header_fields)) = content.lines().find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        (fields.contains(&"PID") && fields.contains(&"COMMAND")).then_some((line, fields))
    }) else {
        return ArtifactSummary::problem(
            path,
            "ps_listing",
            "unparsed",
            json!({"reason": "no header row found"}),
        );
    };
    let is_thread = basename(path) == "ps_thread.txt";
    // Exact-token selection above makes these positions infallible. Do not
    // select by substring and unwrap: a malformed `XPID COMMAND` header used
    // to panic the entire scan here.
    let pre_cmd_fields = header_fields.iter().position(|t| *t == "COMMAND").unwrap();
    let last_cmd_field = header_fields.iter().rposition(|t| t == &"COMMAND").unwrap();
    let pid_idx = header_fields.iter().position(|t| t == &"PID").unwrap();
    const THREAD_SUFFIX: [&str; 11] = [
        "PPID", "F", "%MEM", "PRI", "NI", "VSZ", "RSS", "WCHAN", "STARTED", "TIME", "COMMAND",
    ];
    let thread_header_valid = pre_cmd_fields != last_cmd_field
        && pid_idx < pre_cmd_fields
        && header_fields.get(pre_cmd_fields + 1..) == Some(THREAD_SUFFIX.as_slice());
    let header_only = !content
        .lines()
        .skip_while(|line| *line != header)
        .skip(1)
        .any(|line| !line.trim().is_empty());
    if !is_thread
        && (pre_cmd_fields != last_cmd_field
            || last_cmd_field + 1 != header_fields.len()
            || pid_idx >= pre_cmd_fields)
    {
        return ArtifactSummary::problem(
            path,
            "ps_listing",
            "unparsed",
            json!({"reason": "ps header columns were not recognized"}),
        );
    }
    if is_thread && !thread_header_valid {
        // Some captures retain only a shortened ps_thread header. With no
        // rows there is no process data to mis-slice, so preserve it as an
        // explicitly empty inventory. If it is the only ps surface, the
        // engine still makes the scan inconclusive; a parsed ps.txt can cover
        // it. The same shortened header with rows remains unparsed.
        if header_only && pre_cmd_fields != last_cmd_field && pid_idx < pre_cmd_fields {
            return ArtifactSummary::parsed(
                path,
                "ps_listing",
                json!({
                    "processes": 0,
                    "empty": true,
                    "note": "ps_thread contained a header but no rows",
                }),
            );
        }
        return ArtifactSummary::problem(
            path,
            "ps_listing",
            "unparsed",
            json!({"reason": "ps_thread header columns were not recognized"}),
        );
    }

    let mut count = 0usize;
    let mut skipped_rows = 0usize;
    let mut last_thread_pid: Option<String> = None;
    let mut past_header = false;
    for line in content.lines() {
        if !past_header {
            past_header = line == header;
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        let (cmd, pid) = if is_thread {
            // Numeric columns right-align and outgrow their headers (PID is
            // 3 chars; real pids reach 5), so byte offsets cannot locate the
            // pid. Row shape is positional instead: USER is left-aligned at
            // column 0, so a process row starts flush and its pid is the
            // second token; a thread-continuation row is indented (no USER)
            // and leads with the repeated pid of its process.
            let indented = line.starts_with([' ', '\t']);
            let fields = field_spans(line);
            if indented {
                if valid_thread_continuation(&fields, last_thread_pid.as_deref()) {
                    continue;
                }
                skipped_rows += 1;
                continue;
            }
            let Some(pid) = fields.get(pid_idx).map(|field| field.1) else {
                skipped_rows += 1;
                continue;
            };
            let Some(cmd) = thread_command(line, &fields, pre_cmd_fields) else {
                skipped_rows += 1;
                continue;
            };
            if pid.parse::<u32>().is_err() || cmd.is_empty() {
                skipped_rows += 1;
                continue;
            }
            last_thread_pid = Some(pid.to_string());
            (cmd, pid)
        } else {
            let fields = field_spans(line);
            if !valid_ps_prefix(&header_fields[..pre_cmd_fields], &fields) {
                skipped_rows += 1;
                continue;
            }
            let Some(cmd) = field_rest(line, pre_cmd_fields) else {
                skipped_rows += 1;
                continue;
            };
            let Some(pid) = fields
                .get(pid_idx)
                .map(|field| field.1)
                .filter(|pid| pid.parse::<u32>().is_ok())
            else {
                skipped_rows += 1;
                continue;
            };
            (cmd, pid)
        };
        let argv0 = cmd.split_whitespace().next().unwrap_or(cmd);
        if !valid_argv0(argv0) {
            skipped_rows += 1;
            continue;
        }
        count += 1;
        let evidence = json!({"pid": pid, "command": cmd});

        // argv0 cannot be told apart from a binary path containing spaces
        // ("/…/My App.app/My App"). Offer the full command only to the
        // path-specific matcher: treating an argument as a basename candidate
        // can turn `legit /tmp/bh` into a false process-name match.
        let mut seen_indicators = BTreeSet::new();
        for (cand, matches) in [(argv0, db.match_process(argv0)), (cmd, db.match_path(cmd))] {
            for ind in matches {
                if !seen_indicators.insert(format!("{:?}|{}|{}", ind.kind, ind.set, ind.value)) {
                    continue;
                }
                findings.push(Finding::ioc_match(
                    path,
                    format!(
                        "Running process \u{2018}{}\u{2019} matches a published {} indicator",
                        basename(cand),
                        ind.campaign
                    ),
                    evidence.clone(),
                    ind,
                ));
            }
        }
        if let Some(f) = path_flag_finding(path, argv0, "A process was running from", &evidence) {
            findings.push(f);
        }
    }

    // Current iOS 26 captures can contain a header-only ps_thread.txt beside
    // a complete ps.txt. The file itself was parsed, but contributes no
    // inventory; the engine requires at least one process row across the
    // combined ps surface before a scan can be clear.
    if count == 0 {
        if is_thread && skipped_rows == 0 {
            return ArtifactSummary::parsed(
                path,
                "ps_listing",
                json!({
                    "processes": 0,
                    "empty": true,
                    "note": "ps_thread contained a header but no rows",
                }),
            );
        }
        // A real ps.txt always lists processes (launchd at minimum).
        // "Parsed, 0 processes" would let an emptied file read as clear.
        return ArtifactSummary::problem(
            path,
            "ps_listing",
            "unparsed",
            json!({
                "reason": "header present but no readable process rows",
                "processes": 0,
                "skipped_rows": skipped_rows,
            }),
        );
    }
    if skipped_rows > 0 {
        return ArtifactSummary::problem(
            path,
            "ps_listing",
            "parsed_partial",
            json!({
                "reason": "one or more process rows could not be parsed",
                "processes": count,
                "skipped_rows": skipped_rows,
            }),
        );
    }
    ArtifactSummary::parsed(path, "ps_listing", json!({"processes": count}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Severity;

    const SAMPLE: &str = "\
USER             UID   PID  PPID  %CPU %MEM STARTED     TIME COMMAND
root               0     1     0   0.0  0.1 Tue07PM  0:12.34 /sbin/launchd
mobile           501   211     1   0.0  0.5 Tue07PM  0:01.02 /usr/sbin/mediaserverd
mobile           501   340     1   0.0  0.3 Tue07PM  0:00.55 /Applications/Music.app/Music --launchedByApp
root               0  2143     1   0.0  0.2 Tue07PM  0:00.11 /private/var/db/com.apple.xpc.roleaccountd.staging/bh
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
    fn counts_processes_and_flags_ioc() {
        let mut findings = Findings::new();
        let summary = analyze("root/ps.txt", SAMPLE, &db_with_bh(), &mut findings);
        assert_eq!(summary.details["processes"], 4);
        let matches: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Match)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].evidence["pid"], "2143");
        assert!(findings.iter().any(|f| f.severity == Severity::Suspicious));
    }

    #[test]
    fn commands_with_arguments_keep_argv0() {
        let mut findings = Findings::new();
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"indicator","pattern":"[process:name='Music']"}]}"#,
        )
        .unwrap();
        analyze("root/ps.txt", SAMPLE, &db, &mut findings);
        // exactly one IOC match: the basename of argv0, with the trailing
        // "--launchedByApp" argument not treated as part of the name (the
        // staging line in SAMPLE also raises its heuristic, which is not
        // under test here and is filtered out by severity)
        let matches: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Match)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].indicator.as_ref().unwrap().value, "Music");
        assert_eq!(
            matches[0].evidence["command"],
            "/Applications/Music.app/Music --launchedByApp"
        );
    }

    #[test]
    fn binary_path_containing_spaces_matches_via_full_command() {
        // argv0 splitting truncates "/…/My App.app/My App" at the first
        // space; the full command must still be offered as a candidate so a
        // file:path indicator with spaces can hit.
        const SPACED: &str = "\
USER             UID   PID  PPID  %CPU %MEM STARTED     TIME COMMAND
mobile           501   777     1   0.0  0.3 Tue07PM  0:00.55 /private/var/app/My App.app/My App
";
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"indicator","pattern":"[file:path='/private/var/app/My App.app/My App']"}]}"#,
        )
        .unwrap();
        let mut findings = Findings::new();
        analyze("root/ps.txt", SPACED, &db, &mut findings);
        let matches: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Match)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].indicator.as_ref().unwrap().kind, "file_path");
    }

    #[test]
    fn command_argument_is_not_treated_as_a_process_name() {
        const WITH_ARGUMENT: &str = "\
USER PID COMMAND
root 1 /usr/bin/legit /tmp/bh
";
        let mut findings = Findings::new();
        analyze("root/ps.txt", WITH_ARGUMENT, &db_with_bh(), &mut findings);
        assert!(!findings
            .iter()
            .any(|finding| finding.severity == Severity::Match));
    }

    #[test]
    fn noncanonical_slash_commands_mark_listing_partial() {
        for command in ["/safe/../bh", "/safe/./bh", "/safe//bh", "safe/bh"] {
            let sample = format!("USER PID COMMAND\nroot 1 /sbin/launchd\nroot 2 {command}\n");
            let mut findings = Findings::new();
            let summary = analyze("root/ps.txt", &sample, &db_with_bh(), &mut findings);
            assert_eq!(summary.status, "parsed_partial", "command: {command}");
            assert_eq!(summary.details["processes"], 1);
            assert_eq!(summary.details["skipped_rows"], 1);
            assert!(
                !findings
                    .iter()
                    .any(|finding| finding.severity == Severity::Match),
                "command: {command}"
            );
        }
    }

    #[test]
    fn directory_indicator_is_deduplicated_across_command_candidates() {
        const WITH_ARGUMENT: &str = "\
USER PID COMMAND
root 1 /private/var/tmp/tool --flag
";
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"indicator","pattern":"[file:path='/private/var/tmp/']"}]}"#,
        )
        .unwrap();
        let mut findings = Findings::new();
        analyze("root/ps.txt", WITH_ARGUMENT, &db, &mut findings);
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.severity == Severity::Match)
                .count(),
            1
        );
    }

    #[test]
    fn skipped_process_rows_mark_listing_partial() {
        // A row with fewer fields than the header cannot name its command;
        // it must be skipped and the artifact must not claim full parsing.
        // (The emoji row exercises a non-ASCII bare process name, which field
        // counting handles fine - byte-offset slicing used to choke on it.)
        const PARTIAL: &str = "\
USER PID COMMAND
root   1 /sbin/launchd
short
root 1 💥example
";
        let mut findings = Findings::new();
        let summary = analyze("root/ps.txt", PARTIAL, &IocDb::new(), &mut findings);
        assert_eq!(summary.status, "parsed_partial");
        assert_eq!(summary.details["processes"], 2);
        assert_eq!(summary.details["skipped_rows"], 1);
    }

    #[test]
    fn ps_txt_invalid_pid_marks_row_partial() {
        const INVALID_PID: &str = "\
USER PID COMMAND
root 1 /sbin/launchd
root not-a-pid /usr/libexec/example
";
        let mut findings = Findings::new();
        let summary = analyze("root/ps.txt", INVALID_PID, &IocDb::new(), &mut findings);
        assert_eq!(summary.status, "parsed_partial");
        assert_eq!(summary.details["processes"], 1);
        assert_eq!(summary.details["skipped_rows"], 1);
    }

    #[test]
    fn malformed_header_tokens_are_unparsed_not_panic() {
        for malformed in [
            "USER XPID COMMAND\nroot 1 /sbin/launchd\n",
            "USER PID COMMANDER\nroot 1 /sbin/launchd\n",
        ] {
            let mut findings = Findings::new();
            let summary = analyze("root/ps.txt", malformed, &IocDb::new(), &mut findings);
            assert_eq!(summary.status, "unparsed", "header: {malformed:?}");
            assert!(findings.is_empty());
        }
    }

    #[test]
    fn ps_txt_rejects_multiple_command_columns() {
        const THREAD_SHAPED: &str = "\
USER PID COMMAND PPID TIME COMMAND
root 1 /privat 0 0:00 /private/var/tmp/bh
";
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"indicator","pattern":"[file:path='/private/var/tmp/bh']"}]}"#,
        )
        .unwrap();
        let mut findings = Findings::new();
        let summary = analyze("root/ps.txt", THREAD_SHAPED, &db, &mut findings);
        assert_eq!(summary.status, "unparsed");
        assert!(findings.is_empty());
    }

    #[test]
    fn ps_txt_shifted_typed_prefix_is_not_parsed_clear() {
        const SHIFTED: &str = "\
USER UID PID PPID COMMAND
root 0 1 /private/var/tmp/bh --flag
";
        let mut findings = Findings::new();
        let summary = analyze("root/ps.txt", SHIFTED, &db_with_bh(), &mut findings);
        assert_eq!(summary.status, "unparsed");
        assert_eq!(summary.details["skipped_rows"], 1);
        assert!(!findings
            .iter()
            .any(|finding| finding.severity == Severity::Match));
    }

    #[test]
    fn ps_txt_shifted_string_prefix_is_not_parsed_clear() {
        const SHIFTED: &str = "\
USER PID STAT COMMAND
root 1 /private/var/tmp/bh --flag
";
        let mut findings = Findings::new();
        let summary = analyze("root/ps.txt", SHIFTED, &db_with_bh(), &mut findings);
        assert_eq!(summary.status, "unparsed");
        assert_eq!(summary.details["skipped_rows"], 1);
        assert!(!findings
            .iter()
            .any(|finding| finding.severity == Severity::Match));
    }

    #[test]
    fn overflowed_numeric_field_does_not_hide_the_command() {
        // BSD ps prints numeric fields printf-style: a value wider than its
        // padded column (here TIME) shifts the rest of the row right. The
        // command is recovered by field count, not byte offset, so the
        // shifted row still matches its indicator.
        const OVERFLOW: &str = "\
USER             UID   PID  PPID  %CPU %MEM STARTED     TIME COMMAND
root               0     1     0   0.0  0.1 Tue07PM  0:12.34 /sbin/launchd
root               0  2143     1   0.0  0.2 Tue07PM 12345:00.11 /private/var/db/com.apple.xpc.roleaccountd.staging/bh
";
        let mut findings = Findings::new();
        let summary = analyze("root/ps.txt", OVERFLOW, &db_with_bh(), &mut findings);
        assert_eq!(summary.status, "parsed");
        assert_eq!(summary.details["processes"], 2);
        let matches: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Match)
            .collect();
        assert_eq!(matches.len(), 1, "shifted row must still be checked");
        assert_eq!(matches[0].evidence["pid"], "2143");
    }

    #[test]
    fn ps_thread_shifted_row_recovers_full_command() {
        // The typed tail recovers full COMMAND even when TIME outgrows its
        // printed width and shifts the final column.
        const PS_THREAD: &str = "\
USER             PID   TT   %CPU STAT PRI     STIME     UTIME COMMAND  PPID        F %MEM PRI NI      VSZ    RSS WCHAN  STARTED      TIME COMMAND
root           10001   ??    0.0 S    31T   0:00.00   0:00.00 /sbin/l     0   104004  0.7 31T  0 407931472  13728 -       1:25PM   0:02.37 /sbin/launchd
root              30   ??    0.0 S    31T   0:00.00   0:00.17 /usr/li     1  4004004  0.9 31T  0 407965120  18224 -       1:25PM 12345:02.38 /usr/libexec/UserEventAgent
";
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"indicator","pattern":"[file:path='/usr/libexec/UserEventAgent']"}]}"#,
        )
        .unwrap();
        let mut findings = Findings::new();
        let summary = analyze("root/ps_thread.txt", PS_THREAD, &db, &mut findings);
        assert_eq!(summary.status, "parsed");
        assert_eq!(summary.details["processes"], 2);
        assert!(findings.iter().any(|finding| {
            finding.severity == Severity::Match
                && finding.evidence["command"] == "/usr/libexec/UserEventAgent"
        }));
    }

    #[test]
    fn ps_thread_shift_to_token_boundary_recovers_full_command() {
        // Seven extra digits shift the row so the old fixed offset landed at
        // the first byte of TIME. It must not read TIME as COMMAND and miss
        // the exact file-path indicator.
        const PS_THREAD: &str = "\
USER             PID   TT   %CPU STAT PRI     STIME     UTIME COMMAND  PPID        F %MEM PRI NI      VSZ    RSS WCHAN  STARTED      TIME COMMAND
root              30   ??    0.0 S    31T   0:00.00   0:00.17 /privat     1  12345678901234  0.9 31T  0 407965120  18224 -       1:25PM   0:02.38 /private/var/tmp/relaunch
";
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"indicator","pattern":"[file:path='/private/var/tmp/relaunch']"}]}"#,
        )
        .unwrap();
        let mut findings = Findings::new();
        let summary = analyze("root/ps_thread.txt", PS_THREAD, &db, &mut findings);
        assert_eq!(summary.status, "parsed");
        assert_eq!(summary.details["processes"], 1);
        let matching: Vec<_> = findings
            .iter()
            .filter(|finding| finding.severity == Severity::Match)
            .collect();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].evidence["command"], "/private/var/tmp/relaunch");
    }

    #[test]
    fn ps_thread_uses_full_command_and_ignores_continuations() {
        // Real ps_thread.txt has an abbreviated COMMAND column followed by
        // a second, full COMMAND column. Indented rows are threads belonging
        // to the preceding process, not separate processes. TTY values can
        // also exceed the header width (`s000`), so PID parsing is token-based.
        const PS_THREAD: &str = "\
USER             PID   TT   %CPU STAT PRI     STIME     UTIME COMMAND  PPID        F %MEM PRI NI      VSZ    RSS WCHAN  STARTED      TIME COMMAND
root           10001   ??    0.0 S    31T   0:00.00   0:00.00 /sbin/l     0   104004  0.7 31T  0 407931472  13728 -       1:25PM   0:02.37 /sbin/launchd
               10001         0.0 S    37T   0:00.00   0:00.08             0   104004  0.7 37T  0 407931472  13728 -       1:25PM   0:02.37
root              30   ??    0.0 S    31T   0:00.00   0:00.17 /usr/li     1  4004004  0.9 31T  0 407965120  18224 -       1:25PM   0:02.38 /usr/libexec/UserEventAgent (System)
root             300 s000    0.0 S    31T   0:00.00   0:00.08 -zsh      298  4004006  0.1 31T  0 407919648   2640 -       1:27PM   0:00.08 -zsh
";
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"indicator","pattern":"[file:path='/sbin/launchd']"}]}"#,
        )
        .unwrap();
        let mut findings = Findings::new();
        let summary = analyze("root/ps_thread.txt", PS_THREAD, &db, &mut findings);
        assert_eq!(summary.status, "parsed");
        assert_eq!(summary.details["processes"], 3);
        let matches: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Match)
            .collect();
        assert_eq!(matches.len(), 1);
        // The PID column right-aligns and outgrows its 3-char header for
        // real pids; evidence must carry the whole number, not a byte-slice
        // suffix of it.
        assert_eq!(matches[0].evidence["pid"], "10001");
        assert_eq!(matches[0].evidence["command"], "/sbin/launchd");
    }

    #[test]
    fn ps_thread_without_full_command_column_is_unparsed() {
        // ps_thread's first COMMAND column is abbreviated. Without the
        // second, full-path COMMAND column, treating the listing as complete
        // could miss an IOC that was truncated out of the abbreviated value.
        const SINGLE_COMMAND: &str = "\
USER   PID COMMAND
root     1 /sbin/launchd
";
        let mut findings = Findings::new();
        let summary = analyze(
            "root/ps_thread.txt",
            SINGLE_COMMAND,
            &IocDb::new(),
            &mut findings,
        );
        assert_eq!(summary.status, "unparsed");
        assert_eq!(
            summary.details["reason"],
            "ps_thread header columns were not recognized"
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ps_thread_header_only_is_a_recognized_empty_listing() {
        // Current iOS 26 sysdiagnoses can carry a valid ps_thread header but
        // no rows while ps.txt still contains the complete process snapshot.
        const HEADER_ONLY: &str = "\
USER               PID   TT   %CPU STAT PRI     STIME     UTIME COMMAND  PPID        F %MEM PRI NI      VSZ    RSS WCHAN  STARTED      TIME COMMAND
";
        let mut findings = Findings::new();
        let summary = analyze(
            "root/ps_thread.txt",
            HEADER_ONLY,
            &IocDb::new(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed");
        assert_eq!(summary.details["processes"], 0);
        assert!(findings.is_empty());

        // Older/minimal captures can preserve only a shortened header. It is
        // safe to recognize only when there are no rows to interpret.
        let mut findings = Findings::new();
        let summary = analyze(
            "root/ps_thread.txt",
            "USER PID COMMAND PPID TIME COMMAND\n",
            &IocDb::new(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed");
        assert_eq!(summary.details["processes"], 0);
        assert!(findings.is_empty());
    }
}
