//! ps.txt / ps_thread.txt analysis. Sysdiagnose captures a full `ps` process
//! listing; implant process names occasionally appear here directly. The
//! COMMAND column is located by its header offset so commands containing
//! spaces survive, since column counts vary across iOS versions.

use crate::ioc::{basename, IocDb};
use crate::report::{ArtifactSummary, Finding, Severity};
use serde_json::json;

pub fn analyze(
    path: &str,
    content: &str,
    db: &IocDb,
    findings: &mut Vec<Finding>,
) -> ArtifactSummary {
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
            past_header = std::ptr::eq(line, header) || line == header;
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

        for ind in db.match_process(argv0) {
            findings.push(Finding::ioc_match(
                path,
                format!(
                    "Running process \u{2018}{}\u{2019} matches a published {} indicator",
                    basename(argv0),
                    ind.campaign
                ),
                evidence.clone(),
                ind,
            ));
        }
        if argv0.contains("/com.apple.xpc.roleaccountd.staging/") {
            findings.push(Finding::heuristic(
                Severity::Suspicious,
                path,
                format!(
                    "A process was running from {} - this staging directory is strongly associated with Pegasus infections in published research",
                    argv0
                ),
                evidence.clone(),
            ));
        } else if argv0.starts_with("/private/var/db/")
            || argv0.starts_with("/private/var/tmp/")
            || argv0.starts_with("/private/var/root/")
        {
            findings.push(Finding::heuristic(
                Severity::Note,
                path,
                format!(
                    "A process was running from an unusual location ({}) - often benign, but worth review alongside other findings",
                    argv0
                ),
                evidence.clone(),
            ));
        }
    }

    ArtifactSummary::parsed(path, "ps_listing", json!({"processes": count}))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut findings = Vec::new();
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
        let mut findings = Vec::new();
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"indicator","pattern":"[process:name='music']"}]}"#,
        )
        .unwrap();
        analyze("root/ps.txt", SAMPLE, &db, &mut findings);
        // matches basename of argv0, not the trailing "--launchedByApp"
        assert_eq!(findings.len(), 2); // ioc match + staging heuristic note? no: staging is Suspicious, bh not in db here
    }
}
