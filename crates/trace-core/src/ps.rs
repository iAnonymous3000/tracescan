//! ps.txt / ps_thread.txt analysis. Sysdiagnose captures a full `ps` process
//! listing; implant process names occasionally appear here directly. The
//! COMMAND column is located by its header offset so commands containing
//! spaces survive, since column counts vary across iOS versions.

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
    let cmd_col = header.find("COMMAND").unwrap();
    let pid_idx = header.split_whitespace().position(|t| t == "PID");

    let mut count = 0usize;
    let mut past_header = false;
    for line in content.lines() {
        if !past_header {
            past_header = line == header;
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        let Some(cmd) = line.get(cmd_col..).map(str::trim).filter(|c| !c.is_empty()) else {
            continue;
        };
        count += 1;
        let argv0 = cmd.split_whitespace().next().unwrap_or(cmd);
        let pid = pid_idx
            .and_then(|i| line.split_whitespace().nth(i))
            .unwrap_or("?");
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
}
