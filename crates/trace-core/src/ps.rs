//! ps.txt / ps_thread.txt analysis. Sysdiagnose captures a full `ps` process
//! listing; implant process names occasionally appear here directly. The
//! COMMAND column is located by its header offset so commands containing
//! spaces survive, since column counts vary across iOS versions. ps_thread
//! has an abbreviated COMMAND column and a final full-path COMMAND column;
//! only process rows from the latter are analyzed (thread rows are skipped).

use crate::heuristics::path_flag_finding;
use crate::ioc::{basename, IocDb};
use crate::report::{ArtifactSummary, Finding, Findings};
use serde_json::json;

pub fn analyze(path: &str, content: &str, db: &IocDb, findings: &mut Findings) -> ArtifactSummary {
    let Some(header) = content
        .lines()
        .find(|l| l.contains("PID") && l.contains("COMMAND"))
    else {
        return ArtifactSummary::problem(
            path,
            "ps_listing",
            "unparsed",
            json!({"reason": "no header row found"}),
        );
    };
    let is_thread = basename(path) == "ps_thread.txt";
    let first_cmd_col = header.find("COMMAND").unwrap();
    let last_cmd_col = header.rfind("COMMAND").unwrap();
    let cmd_col = if is_thread {
        last_cmd_col
    } else {
        first_cmd_col
    };
    let pid_idx = header.split_whitespace().position(|t| t == "PID");
    if is_thread
        && (first_cmd_col == last_cmd_col
            || header.find("PID").filter(|pid| *pid < cmd_col).is_none())
    {
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
            let mut tokens = line.split_whitespace();
            let Some(pid) = (if indented {
                tokens.next()
            } else {
                tokens.nth(1)
            }) else {
                skipped_rows += 1;
                continue;
            };
            let cmd = line.get(cmd_col..).map(str::trim).unwrap_or("");
            let pid_valid = pid.parse::<u32>().is_ok();
            let continuation =
                indented && pid_valid && cmd.is_empty() && last_thread_pid.as_deref() == Some(pid);
            if continuation {
                continue;
            }
            if indented || !pid_valid || cmd.is_empty() {
                skipped_rows += 1;
                continue;
            }
            last_thread_pid = Some(pid.to_string());
            (cmd, pid)
        } else {
            let Some(cmd) = line.get(cmd_col..).map(str::trim).filter(|c| !c.is_empty()) else {
                skipped_rows += 1;
                continue;
            };
            let pid = pid_idx
                .and_then(|i| line.split_whitespace().nth(i))
                .unwrap_or("?");
            (cmd, pid)
        };
        count += 1;
        let argv0 = cmd.split_whitespace().next().unwrap_or(cmd);
        let evidence = json!({"pid": pid, "command": cmd});

        // argv0 cannot be told apart from a binary path containing spaces
        // ("/…/My App.app/My App --flag"), so the full command is offered as
        // a second candidate. Matching is exact, so a command with real
        // arguments can never accidentally hit an indicator this way.
        let mut candidates = vec![argv0];
        if cmd != argv0 {
            candidates.push(cmd);
        }
        for cand in candidates {
            for ind in db.match_process(cand) {
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
            r#"{"objects":[{"type":"indicator","pattern":"[process:name='music']"}]}"#,
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
        assert_eq!(matches[0].indicator.as_ref().unwrap().value, "music");
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
    fn skipped_process_rows_mark_listing_partial() {
        // Rows that cannot reach the header's COMMAND byte offset, or whose
        // offset lands inside a UTF-8 code point, were previously discarded
        // while the artifact still claimed to be fully parsed.
        const PARTIAL: &str = "\
USER PID COMMAND
root   1 /sbin/launchd
short
root 1 💥/bin/example
";
        let mut findings = Findings::new();
        let summary = analyze("root/ps.txt", PARTIAL, &IocDb::new(), &mut findings);
        assert_eq!(summary.status, "parsed_partial");
        assert_eq!(summary.details["processes"], 1);
        assert_eq!(summary.details["skipped_rows"], 2);
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
    }
}
