//! .ips crash and diagnostic analysis. Modern crash logs are two JSON
//! documents: a one-line summary header, then the full payload. Ancillary
//! formats can instead carry a process inventory, a validated text preamble,
//! or metadata with no process identity. Process-bearing fields are checked
//! against indicators; unknown or structurally incomplete formats stay partial.

use crate::heuristics::{path_flag, path_flag_finding, PathFlag};
use crate::ioc::{basename, IocDb, IocKind};
use crate::report::{ArtifactSummary, DeviceInfo, Finding, Findings, Severity};
use crate::tar_stream::is_paired_device_path;
use regex_lite::Regex;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

fn str_field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(|x| x.as_str())
}

fn labeled_value<'a>(line: &'a str, label: &str) -> Option<&'a str> {
    let tail = line.strip_prefix(label)?.strip_prefix(':')?;
    // Reserved labels use exactly one separator. Accepting `Label:: value`
    // turns a malformed opener into a different non-empty value and can make
    // a truncated diagnostic look structurally complete.
    let tail = tail.trim_start();
    if tail.starts_with(':') {
        return None;
    }
    let value = tail.trim_end();
    (!value.is_empty()).then_some(value)
}

fn has_reserved_label(line: &str, label: &str) -> bool {
    line.strip_prefix(label)
        .is_some_and(|tail| tail.starts_with(':'))
}

fn parent_process(value: &str) -> Option<&str> {
    let (name, pid) = value.rsplit_once(" [")?;
    pid.strip_suffix(']')?.parse::<u64>().ok()?;
    let name = name.trim();
    (valid_process_name(name) && !name.contains(char::is_whitespace)).then_some(name)
}

fn valid_process_name(name: &str) -> bool {
    !name.trim().is_empty() && !name.contains('/')
}

fn panic_pid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bpid (\d+)[:\s]+\(?([A-Za-z0-9_.-]+)\)?").unwrap())
}

fn valid_absolute_process_path(path: &str) -> bool {
    path.starts_with('/')
        && path[1..]
            .chars()
            .any(|character| !character.is_whitespace())
        && path
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}

fn date_suffix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"-\d{4}-\d{2}-\d{2}(?:-\d{6})?$").unwrap())
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

fn add_candidate(
    candidates: &mut BTreeSet<String>,
    candidate_sources: &mut BTreeMap<String, BTreeSet<&'static str>>,
    value: &str,
    field: &'static str,
) {
    candidates.insert(value.to_string());
    candidate_sources
        .entry(value.to_string())
        .or_default()
        .insert(field);
}

fn remove_header_candidates(
    candidates: &mut BTreeSet<String>,
    candidate_sources: &mut BTreeMap<String, BTreeSet<&'static str>>,
    header_process_names: &BTreeSet<String>,
) {
    for header_name in header_process_names {
        let remove_candidate = candidate_sources
            .get_mut(header_name)
            .is_some_and(|sources| {
                sources.remove("name");
                sources.remove("app_name");
                sources.is_empty()
            });
        if remove_candidate {
            candidate_sources.remove(header_name);
            candidates.remove(header_name);
        }
    }
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
    let mut candidate_sources: BTreeMap<String, BTreeSet<&'static str>> = BTreeMap::new();
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
    let paired_device = is_paired_device_path(path);
    let mut header_process_names = BTreeSet::new();
    let mut header_identity_malformed = false;

    if let Some(h) = &header {
        for key in ["name", "app_name"] {
            match h.get(key) {
                Some(Value::String(n)) if valid_process_name(n) => {
                    add_candidate(&mut candidates, &mut candidate_sources, n, key);
                    header_process_names.insert(n.to_string());
                    proc_name.get_or_insert_with(|| n.to_string());
                }
                Some(_) => header_identity_malformed = true,
                None => {}
            }
        }
        bug_type = str_field(h, "bug_type").map(String::from);
        timestamp = str_field(h, "timestamp").map(String::from);
        os_version = str_field(h, "os_version").map(String::from);
    }
    let mut body_identified = false;
    let mut body_identity_malformed = false;
    let mut body_identity_mismatch = false;
    let mut body_proc_name: Option<String> = None;
    let mut header_body_identity_mismatch = false;
    if let Some(b) = &body {
        match b.get("procName") {
            Some(Value::String(n)) if valid_process_name(n) => {
                add_candidate(&mut candidates, &mut candidate_sources, n, "procName");
                header_body_identity_mismatch = header_process_names
                    .iter()
                    .any(|header_name| header_name != n);
                // The body is the substantive crash document. Prefer its
                // validated identity in evidence even when the header drifts;
                // the disagreement still keeps the artifact fail-closed.
                proc_name = Some(n.to_string());
                body_proc_name = Some(n.to_string());
                body_identified = true;
            }
            Some(_) => body_identity_malformed = true,
            None => {}
        }
        match b.get("procPath") {
            Some(Value::String(p)) if valid_absolute_process_path(p) => {
                body_identified = true;
                let path_name = basename(p);
                body_identity_mismatch = body_proc_name
                    .as_deref()
                    .is_some_and(|name| path_name != name);
                if body_proc_name.is_none() {
                    header_body_identity_mismatch = header_process_names
                        .iter()
                        .any(|header_name| header_name != path_name);
                    // A validated body path is authoritative when procName is
                    // absent. Do not continue presenting the weaker header as
                    // the crashing process in artifact evidence.
                    proc_name = Some(path_name.to_string());
                }
                // The full path must be a candidate too: file:path indicators
                // (e.g. '/private/var/tmp/UserEventAgent') only match on it.
                add_candidate(&mut candidates, &mut candidate_sources, p, "procPath");
                add_candidate(
                    &mut candidates,
                    &mut candidate_sources,
                    path_name,
                    "procPath",
                );
                proc_path = Some(p.to_string());
            }
            Some(_) => body_identity_malformed = true,
            None => {}
        }
        match b.get("parentProc") {
            Some(Value::String(parent)) if valid_process_name(parent) => {
                add_candidate(
                    &mut candidates,
                    &mut candidate_sources,
                    parent,
                    "parentProc",
                );
            }
            Some(_) => body_identity_malformed = true,
            None => {}
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

    if body_identified || bug_type.as_deref() == Some("210") {
        // Header identity is only a fallback. Once the substantive body names
        // the process (directly or through a validated procPath), remove
        // header-only candidates so contradictory metadata cannot create a
        // false IOC match. A bug_type 210 header is format metadata even when
        // its panicString is malformed, so it is never a process candidate.
        // Candidates also sourced from the body remain.
        remove_header_candidates(
            &mut candidates,
            &mut candidate_sources,
            &header_process_names,
        );
    }
    if bug_type.as_deref() == Some("210") && !body_identified {
        proc_name = None;
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
            // The header labels the diagnostic family, not necessarily a
            // process. Only validated inventory rows are IOC candidates.
            candidates.clear();
            candidate_sources.clear();
            proc_name = None;
            proc_path = None;
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
                        .filter(|name| valid_process_name(name))
                    else {
                        skipped_processes += 1;
                        continue;
                    };
                    if pid != key_pid {
                        skipped_processes += 1;
                        continue;
                    }
                    let name = name.to_string();
                    add_candidate(
                        &mut candidates,
                        &mut candidate_sources,
                        &name,
                        "processByPid.procname",
                    );
                    candidate_pids.entry(name).or_insert(pid);
                    processes_seen += 1;
                }
                special_complete = !inventory.is_empty() && skipped_processes == 0;
            }
        }
        Some("298") => {
            special_format = true;
            format = "jetsam";
            candidates.clear();
            candidate_sources.clear();
            proc_name = None;
            proc_path = None;
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
                        .filter(|name| valid_process_name(name))
                    else {
                        skipped_processes += 1;
                        continue;
                    };
                    let name = name.to_string();
                    add_candidate(
                        &mut candidates,
                        &mut candidate_sources,
                        &name,
                        "processes.name",
                    );
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
            candidate_sources.clear();
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
            candidate_sources.clear();
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
        Some(kind @ ("145" | "202")) => {
            special_format = true;
            candidates.clear();
            candidate_sources.clear();
            proc_name = None;
            proc_path = None;
            let expected_event;
            (format, expected_event) = if kind == "145" {
                ("disk_writes", "disk writes")
            } else {
                ("cpu_resource", "cpu usage")
            };
            let mut commands = Vec::new();
            let mut paths = Vec::new();
            let mut parents = Vec::new();
            let mut pids = Vec::new();
            let mut report_versions = Vec::new();
            let mut events = Vec::new();
            let mut valid_steps = false;
            for line in rest.lines() {
                if line.starts_with("Steps:") {
                    valid_steps = labeled_value(line, "Steps")
                        .and_then(|value| value.split_whitespace().next())
                        .is_some_and(|value| value.parse::<u64>().is_ok());
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
                && valid_absolute_process_path(paths[0])
                && basename(paths[0]) == commands[0]
            {
                Some((commands[0], paths[0]))
            } else {
                None
            };
            if let Some((command, process_path)) = identity {
                add_candidate(&mut candidates, &mut candidate_sources, command, "Command");
                add_candidate(
                    &mut candidates,
                    &mut candidate_sources,
                    process_path,
                    "Path",
                );
                add_candidate(
                    &mut candidates,
                    &mut candidate_sources,
                    basename(process_path),
                    "Path",
                );
                proc_name = Some(command.to_string());
                proc_path = Some(process_path.to_string());
                processes_seen = 1;
            }
            if let Some(Some(parent)) = parent {
                add_candidate(&mut candidates, &mut candidate_sources, parent, "Parent");
            }

            let valid = identity.is_some()
                && pids.len() == 1
                && report_versions.len() == 1
                && events.len() == 1
                && valid_steps
                && pids[0].parse::<u64>().is_ok()
                && report_versions[0].parse::<u64>().is_ok()
                && events[0]
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .eq_ignore_ascii_case(expected_event)
                && header.as_ref().is_some_and(|h| {
                    str_field(h, "name") == Some(commands[0])
                        && str_field(h, "app_name") == Some(commands[0])
                })
                && parent.is_some();
            special_complete = valid;
        }
        Some("226") => {
            special_format = true;
            format = "security_analytics";
            detection_relevant = false;
            candidates.clear();
            candidate_sources.clear();
            proc_name = None;
            proc_path = None;

            // SFA-*.json diagnostics: opaque security-stack health counters.
            // The body is one or more back-to-back JSON documents (no
            // separator), each {postTime, events:[objects]} - which is why
            // a single-document parse of the body can fail on real files.
            let mut docs = 0usize;
            let mut valid = true;
            for doc in serde_json::Deserializer::from_str(rest).into_iter::<Value>() {
                let shape_ok = doc
                    .ok()
                    .as_ref()
                    .and_then(Value::as_object)
                    .is_some_and(|object| {
                        object.len() == 2
                            && object.get("postTime").is_some_and(Value::is_number)
                            && object
                                .get("events")
                                .and_then(Value::as_array)
                                .is_some_and(|events| events.iter().all(Value::is_object))
                    });
                if !shape_ok {
                    valid = false;
                    break;
                }
                docs += 1;
            }
            special_complete = valid && docs > 0;
        }
        Some("303") => {
            special_format = true;
            format = "proactive_events";
            detection_relevant = false;
            candidates.clear();
            candidate_sources.clear();
            proc_name = None;
            proc_path = None;

            // proactive_event_tracker dumps: repeated blocks of four labeled
            // lines followed by a free-form message dump. Every block opener
            // must be well-formed; anything before the first block was never
            // understood, so it keeps the artifact partial.
            let mut blocks = 0usize;
            let mut valid = true;
            let mut payload_seen = false;
            let mut lines = rest.lines();
            while let Some(line) = lines.next() {
                if has_reserved_label(line, "Message Group") {
                    if blocks > 0 && !payload_seen {
                        valid = false;
                        break;
                    }
                    let opener_ok = labeled_value(line, "Message Group").is_some()
                        && lines
                            .next()
                            .and_then(|l| labeled_value(l, "Message Name"))
                            .is_some()
                        && lines
                            .next()
                            .and_then(|l| labeled_value(l, "Message Type"))
                            .is_some()
                        && lines.next().is_some_and(|l| {
                            l.strip_prefix("Message Body:")
                                .is_some_and(|tail| tail.trim().is_empty())
                        });
                    if !opener_ok {
                        valid = false;
                        break;
                    }
                    blocks += 1;
                    payload_seen = false;
                } else if ["Message Name", "Message Type", "Message Body"]
                    .iter()
                    .any(|label| has_reserved_label(line, label))
                {
                    valid = false;
                    break;
                } else if blocks == 0 {
                    if !line.trim().is_empty() {
                        valid = false;
                        break;
                    }
                } else if !line.trim().is_empty() {
                    payload_seen = true;
                }
            }
            special_complete = valid && blocks > 0 && payload_seen;
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
                add_candidate(
                    &mut candidates,
                    &mut candidate_sources,
                    &cap[2],
                    "panicString",
                );
                panic_signal = true;
            }
        }
    }
    if panic_signal {
        // For panics the pid/name pairs in panicString are the authoritative
        // process signal. The generic header label (normally "kernel") is not
        // a crashed-process identity and must never be an IOC candidate.
        remove_header_candidates(
            &mut candidates,
            &mut candidate_sources,
            &header_process_names,
        );
    }

    // The filename itself encodes the crashing process for ordinary crash
    // logs, which survives even when the JSON fails to parse. Ancillary
    // diagnostics are named after their format, not a process.
    let fname = basename(path);
    if !special_format && bug_type.as_deref() != Some("210") && !body_identified && !panic_signal {
        if let Some(name) = filename_process(fname) {
            add_candidate(&mut candidates, &mut candidate_sources, name, "filename");
        }
    }

    // The body is the substantive document (procPath, parentProc,
    // panicString); a crash whose body did not parse had most of its
    // signal unchecked, and must not count as a fully analyzed artifact
    // even when the one-line header parsed. Parsing alone is not enough:
    // syntactically valid JSON that names no crashing process ("{}") was
    // never really checked either - every real crash log identifies its
    // process (procName/procPath) or, for kernel panics, names pids in
    // the panic string. The identification must come from the BODY: the
    // header's name field alone (which every .ips carries, panics included)
    // would satisfy this for a body whose real payload keys drifted and
    // went entirely unread.
    let identified = body_identified || panic_signal;
    if !special_format {
        processes_seen = usize::from(identified);
        if panic_signal {
            format = "kernel_panic";
        }
    }
    let status = if if special_format {
        special_complete
    } else {
        header.as_ref().is_some_and(Value::is_object)
            && body.is_some()
            && identified
            && !header_identity_malformed
            && !body_identity_malformed
            && !body_identity_mismatch
            && !header_body_identity_mismatch
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
        "paired_device": paired_device,
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
            let mut evidence = candidate_pids.get(cand).map_or_else(
                || evidence_base.clone(),
                |pid| {
                    json!({
                        "crash_file": fname,
                        "process": cand,
                        "pid": pid,
                        "bug_type": bug_type,
                        "timestamp": timestamp,
                        "format": format,
                        "paired_device": paired_device,
                    })
                },
            );
            evidence["matched_process"] = Value::String(cand.clone());
            if let Some(fields) = candidate_sources.get(cand) {
                if let Some(field) = fields.first() {
                    evidence["matched_field"] = Value::String((*field).to_string());
                }
                if fields.contains("parentProc") || fields.contains("Parent") {
                    evidence["parent_process"] = Value::String(cand.clone());
                }
            }
            let diagnostic = if paired_device {
                "Paired-device diagnostic"
            } else {
                "iOS diagnostic"
            };
            findings.push(Finding::ioc_match(
                path,
                format!(
                    "{diagnostic} involves process \u{2018}{}\u{2019} - matches a published {} indicator",
                    shown, ind.campaign,
                ),
                evidence,
                ind,
            ));
        }
    }

    // Same yardstick as the ps and shutdown.log surfaces.
    let process_location = if paired_device {
        "The paired-device crashing process ran from"
    } else {
        "The crashing process ran from"
    };
    if let Some(f) = proc_path
        .as_deref()
        .and_then(|p| path_flag_finding(path, p, process_location, &evidence_base))
    {
        findings.push(f);
    }
    // A staging path seen only inside a kernel panic string has no process
    // path to cite; suppressed when the path-based flag already raised it.
    if panic_staging && proc_path.as_deref().and_then(path_flag) != Some(PathFlag::Staging) {
        let panic_subject = if paired_device {
            "A paired-device kernel panic report"
        } else {
            "A kernel panic report"
        };
        findings.push(Finding::heuristic(
            Severity::Suspicious,
            path,
            format!("{panic_subject} references the roleaccountd.staging directory - it is strongly associated with Pegasus infections in published research (Kaspersky iShutdown, 2024)"),
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
                "paired_device": paired_device,
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
    fn parent_process_match_identifies_the_matched_candidate() {
        let sample = r#"{"name":"safe","app_name":"safe","bug_type":"309"}
{"procName":"safe","procPath":"/usr/libexec/safe","parentProc":"bh"}"#;
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/safe-2026.ips",
            sample,
            &db_with_bh(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed");
        let matching = findings
            .iter()
            .find(|finding| finding.severity == Severity::Match)
            .unwrap();
        assert_eq!(matching.evidence["process"], "safe");
        assert_eq!(matching.evidence["matched_process"], "bh");
        assert_eq!(matching.evidence["matched_field"], "parentProc");
        assert_eq!(matching.evidence["parent_process"], "bh");
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
    fn panic_pid_requires_a_token_boundary() {
        let panic = r#"{"name":"kernel","bug_type":"210"}
{"panicString":"rapid 1: bh exited unexpectedly"}"#;
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/Panics/panic-full-2026.ips",
            panic,
            &db_with_bh(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed_partial");
        assert!(!findings
            .iter()
            .any(|finding| finding.severity == Severity::Match));
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
        assert_eq!(
            filename_process("bh-2024-01-01-helper-2026-07-17-120000.ips"),
            Some("bh-2024-01-01-helper"),
            "an embedded date belongs to the process name; only the final report timestamp is removed"
        );
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
    fn authoritative_body_identity_suppresses_filename_candidate() {
        let sample = r#"{"name":"safe","app_name":"safe","bug_type":"309"}
{"procName":"safe","procPath":"/usr/bin/safe","parentProc":"launchd"}"#;
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/bh-2026-07-01-120311.ips",
            sample,
            &db_with_bh(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed");
        assert!(!findings
            .iter()
            .any(|finding| finding.severity == Severity::Match));
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
    fn malformed_header_with_valid_body_is_partial() {
        let sample = "not-json\n{\"procName\":\"safe\",\"procPath\":\"/usr/bin/safe\"}";
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/safe-2026.ips",
            sample,
            &IocDb::new(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed_partial");
    }

    #[test]
    fn header_name_with_empty_body_is_parsed_partial() {
        // "{}" parses as JSON but names no process; the header's own name
        // must not stand in for the unread body payload.
        let sample = r#"{"name":"app","app_name":"app","bug_type":"309"}
{}"#;
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/app-2026.ips",
            sample,
            &IocDb::new(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed_partial");
    }

    #[test]
    fn empty_or_invalid_body_identity_is_parsed_partial() {
        for body in [
            r#"{"procName":""}"#,
            r#"{"procName":"   "}"#,
            r#"{"procPath":""}"#,
            r#"{"procPath":"relative/path"}"#,
            r#"{"procPath":"/   "}"#,
            r#"{"procPath":"/usr/bin/safe/../bh"}"#,
            // One valid identity field must not hide a malformed sibling:
            // otherwise that unchecked path/name can contain the IOC.
            r#"{"procName":"safe","procPath":"relative/path"}"#,
            r#"{"procName":"","procPath":"/usr/libexec/safe"}"#,
            r#"{"procName":7,"procPath":"/usr/libexec/safe"}"#,
            r#"{"procName":"safe","procPath":7}"#,
            r#"{"procName":"safe","parentProc":""}"#,
        ] {
            let sample =
                format!("{{\"name\":\"app\",\"app_name\":\"app\",\"bug_type\":\"309\"}}\n{body}");
            let mut findings = Findings::new();
            let (summary, _) = analyze(
                "root/crashes_and_spins/app-2026.ips",
                &sample,
                &IocDb::new(),
                &mut findings,
            );
            assert_eq!(summary.status, "parsed_partial", "body: {body}");
        }
    }

    #[test]
    fn dot_segment_proc_path_is_not_an_ioc_candidate() {
        let sample = r#"{"name":"safe","app_name":"safe","bug_type":"309"}
{"procName":"safe","procPath":"/usr/bin/safe/../bh","parentProc":"launchd"}"#;
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/safe-2026.ips",
            sample,
            &db_with_bh(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed_partial");
        assert!(!findings
            .iter()
            .any(|finding| finding.severity == Severity::Match));
    }

    #[test]
    fn paired_device_findings_and_details_are_labeled() {
        let sample = r#"{"name":"bh","app_name":"bh","bug_type":"309"}
{"procName":"bh","procPath":"/usr/libexec/bh"}"#;
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/logs/ProxiedDevice-ABC123/bh-2026.ips",
            sample,
            &db_with_bh(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed");
        assert_eq!(summary.details["paired_device"], true);
        assert!(findings
            .iter()
            .any(|finding| finding.summary.starts_with("Paired-device diagnostic")));
        assert!(is_paired_device_path(
            "./root/logs/ProxiedDevice-ABC123/bh-2026.ips"
        ));
        assert!(!is_paired_device_path(
            "ProxiedDevice/root/crashes_and_spins/bh-2026.ips"
        ));
        assert!(!is_paired_device_path(
            "root/logs/ProxiedDevice-ABC123/../crashes_and_spins/bh-2026.ips"
        ));
        assert!(!is_paired_device_path(
            "root//logs/ProxiedDevice-ABC123/bh-2026.ips"
        ));
        assert!(!is_paired_device_path(
            "root/logs/ProxiedDeviceBackup/bh-2026.ips"
        ));
        assert!(!is_paired_device_path(
            "root/logs/ProxiedDevice-/bh-2026.ips"
        ));
    }

    #[test]
    fn body_identity_is_preferred_and_header_disagreement_is_partial() {
        let sample = r#"{"name":"headerd","app_name":"headerd","bug_type":"309"}
{"procName":"bodyd","procPath":"/usr/libexec/bodyd","parentProc":"launchd"}"#;
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"indicator","pattern":"[process:name='bodyd']"}]}"#,
        )
        .unwrap();
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/bodyd-2026.ips",
            sample,
            &db,
            &mut findings,
        );
        assert_eq!(summary.status, "parsed_partial");
        assert_eq!(summary.details["process"], "bodyd");
        let matching = findings
            .iter()
            .find(|finding| finding.severity == Severity::Match)
            .unwrap();
        assert_eq!(matching.evidence["process"], "bodyd");
    }

    #[test]
    fn body_path_identity_suppresses_a_contradictory_header_candidate() {
        let sample = r#"{"name":"bh","app_name":"bh","bug_type":"309"}
{"procPath":"/usr/bin/safe"}"#;
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/safe-2026.ips",
            sample,
            &db_with_bh(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed_partial");
        assert_eq!(summary.details["process"], "safe");
        assert_eq!(summary.details["process_path"], "/usr/bin/safe");
        assert!(!findings
            .iter()
            .any(|finding| finding.severity == Severity::Match));
    }

    #[test]
    fn name_fields_cannot_impersonate_file_paths() {
        let sample = r#"{"name":"safe","app_name":"safe","bug_type":"309"}
{"procName":"/private/var/tmp/bh","parentProc":"/private/var/tmp/bh"}"#;
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"indicator","pattern":"[file:path='/private/var/tmp/bh']"}]}"#,
        )
        .unwrap();
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/safe-2026.ips",
            sample,
            &db,
            &mut findings,
        );
        assert_eq!(summary.status, "parsed_partial");
        assert!(!findings
            .iter()
            .any(|finding| finding.severity == Severity::Match));
    }

    #[test]
    fn body_name_path_disagreement_is_partial_but_findings_survive() {
        let sample = r#"{"name":"safe","app_name":"safe","bug_type":"309"}
{"procName":"safe","procPath":"/private/var/tmp/bh","parentProc":"launchd"}"#;
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/safe-2026.ips",
            sample,
            &db_with_bh(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed_partial");
        assert_eq!(summary.details["process"], "safe");
        assert_eq!(summary.details["process_path"], "/private/var/tmp/bh");
        assert!(findings
            .iter()
            .any(|finding| finding.severity == Severity::Match));
    }

    #[test]
    fn panic_with_drifted_panic_string_key_is_parsed_partial() {
        // A 210 header always carries name:"kernel". If the body's
        // panicString key drifts, nothing process-bearing was read and the
        // artifact must not count as parsed.
        let sample = r#"{"name":"kernel","bug_type":"210"}
{"panic_string":"pid 2143: bh ran from /private/var/db/com.apple.xpc.roleaccountd.staging/bh"}"#;
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/Panics/panic-full-2026.ips",
            sample,
            &db_with_bh(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed_partial");
    }

    #[test]
    fn kernel_panic_format_labels_are_never_process_candidates() {
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[
                {"type":"indicator","pattern":"[process:name='kernel']"},
                {"type":"indicator","pattern":"[process:name='panic-full']"}
            ]}"#,
        )
        .unwrap();
        for body in [
            r#"{"panicString":"pid 1: safe exited"}"#,
            r#"{"panic_string":"pid 1: safe exited"}"#,
        ] {
            let sample = format!(
                "{{\"name\":\"kernel\",\"app_name\":\"kernel\",\"bug_type\":\"210\"}}\n{body}"
            );
            let mut findings = Findings::new();
            let (summary, _) = analyze(
                "root/crashes_and_spins/Panics/panic-full-2026.ips",
                &sample,
                &db,
                &mut findings,
            );
            assert!(!findings
                .iter()
                .any(|finding| finding.severity == Severity::Match));
            if body.contains("panic_string") {
                assert_eq!(summary.status, "parsed_partial");
            } else {
                assert_eq!(summary.status, "parsed");
            }
        }
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
    fn whitespace_inventory_names_are_partial() {
        for (bug_type, body) in [
            (
                "288",
                r#"{"bug_type":"288","processByPid":{"1":{"pid":1,"procname":"   "}}}"#,
            ),
            (
                "151",
                r#"{"bug_type":"151","processByPid":{"1":{"pid":1,"procname":"   "}}}"#,
            ),
            (
                "298",
                r#"{"bug_type":"298","processes":[{"name":"   ","pid":1}]}"#,
            ),
        ] {
            let sample = format!("{{\"bug_type\":\"{bug_type}\"}}\n{body}");
            let mut findings = Findings::new();
            let (summary, _) = analyze(
                "root/crashes_and_spins/diagnostic-2026.ips",
                &sample,
                &IocDb::new(),
                &mut findings,
            );
            assert_eq!(summary.status, "parsed_partial", "bug type {bug_type}");
            assert_eq!(summary.details["processes"], 0);
            assert_eq!(summary.details["skipped_processes"], 1);
            assert!(findings.is_empty());
        }
    }

    #[test]
    fn special_formats_ignore_unvalidated_header_process_labels() {
        for (path, sample) in [
            (
                "root/crashes_and_spins/stacks-2026.ips",
                r#"{"name":"bh","app_name":"bh","bug_type":"288"}
{"bug_type":"288","processByPid":{"1":{"pid":1,"procname":"safe"}}}"#,
            ),
            (
                "root/crashes_and_spins/forceReset-2026.ips",
                r#"{"name":"bh","app_name":"bh","bug_type":"151"}
{"bug_type":"151","processByPid":{"1":{"pid":1,"procname":"safe"}}}"#,
            ),
            (
                "root/crashes_and_spins/JetsamEvent-2026.ips",
                r#"{"name":"bh","app_name":"bh","bug_type":"298"}
{"bug_type":"298","processes":[{"name":"safe","pid":1}]}"#,
            ),
            (
                "root/crashes_and_spins/safe.diskwrites_resource-2026.ips",
                r#"{"name":"bh","app_name":"bh","bug_type":"145"}
Report Version: 1
Command: safe
Path: /usr/libexec/safe
PID: 1
Event: disk writes
Steps: 1
"#,
            ),
            (
                "root/crashes_and_spins/safe.cpu_resource-2026.ips",
                r#"{"name":"bh","app_name":"bh","bug_type":"202"}
Report Version: 1
Command: safe
Path: /usr/libexec/safe
PID: 1
Event: cpu usage
Steps: 1
"#,
            ),
        ] {
            let mut findings = Findings::new();
            analyze(path, sample, &db_with_bh(), &mut findings);
            assert!(
                !findings
                    .iter()
                    .any(|finding| finding.severity == Severity::Match),
                "path: {path}"
            );
        }
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
    fn resource_report_dot_segment_path_is_partial_and_not_matched() {
        for (bug_type, event, suffix) in [
            ("145", "disk writes", "diskwrites_resource"),
            ("202", "cpu usage", "cpu_resource"),
        ] {
            let sample = format!(
                "{{\"app_name\":\"bh\",\"name\":\"bh\",\"bug_type\":\"{bug_type}\"}}\n\
Report Version: 1\n\
Command: bh\n\
Path: /usr/bin/safe/../bh\n\
PID: 2143\n\
Event: {event}\n\
Steps: 1\n"
            );
            let mut findings = Findings::new();
            let (summary, _) = analyze(
                &format!("root/crashes_and_spins/bh.{suffix}-2026.ips"),
                &sample,
                &db_with_bh(),
                &mut findings,
            );
            assert_eq!(summary.status, "parsed_partial", "bug type {bug_type}");
            assert!(
                !findings
                    .iter()
                    .any(|finding| finding.severity == Severity::Match),
                "bug type {bug_type}"
            );
        }
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
    fn cpu_resource_report_checks_validated_command_and_path() {
        let sample = r#"{"app_name":"bh","name":"bh","bug_type":"202","timestamp":"2026-07-16 18:32:51.00 -0400","os_version":"iPhone OS 26.5.2 (23F84)"}
Date/Time:        2026-07-16 18:30:12.807 -0400
OS Version:       iPhone OS 26.5.2 (Build 23F84)
Architecture:     arm64e
Report Version:   72
Command:          bh
Path:             /private/var/db/com.apple.xpc.roleaccountd.staging/bh
Parent:           UNKNOWN [1]
PID:              22488
Event:            cpu usage
Action taken:     none
CPU:              90 seconds cpu time over 155 seconds (58% cpu average), exceeding limit of 50% cpu over 180 seconds
Steps:            79 (10 gigacycles/step)
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
            "root/crashes_and_spins/Retired/bh.cpu_resource-2026-07-16-183251.ips",
            sample,
            &db,
            &mut findings,
        );
        assert_eq!(summary.status, "parsed");
        assert_eq!(summary.details["format"], "cpu_resource");
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
    fn cpu_resource_event_mismatch_is_partial() {
        // A 202 report whose Event line says something other than cpu usage
        // is a shape the parser has not validated; it must stay partial.
        let sample = r#"{"app_name":"duetexpertd","name":"duetexpertd","bug_type":"202"}
Report Version:   72
Command:          duetexpertd
Path:             /usr/libexec/duetexpertd
Parent:           UNKNOWN [1]
PID:              22488
Event:            wakeups
Steps:            79 (10 gigacycles/step)
"#;
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/Retired/duetexpertd.cpu_resource-2026.ips",
            sample,
            &IocDb::new(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed_partial");
    }

    #[test]
    fn cpu_resource_empty_or_malformed_steps_is_partial() {
        for steps in ["", "not-a-number"] {
            let sample = format!(
                r#"{{"app_name":"duetexpertd","name":"duetexpertd","bug_type":"202"}}
Report Version:   72
Command:          duetexpertd
Path:             /usr/libexec/duetexpertd
Parent:           UNKNOWN [1]
PID:              22488
Event:            cpu usage
Steps:            {steps}
"#
            );
            let mut findings = Findings::new();
            let (summary, _) = analyze(
                "root/crashes_and_spins/Retired/duetexpertd.cpu_resource-2026.ips",
                &sample,
                &IocDb::new(),
                &mut findings,
            );
            assert_eq!(summary.status, "parsed_partial", "steps: {steps:?}");
        }
    }

    #[test]
    fn security_analytics_is_recognized_without_inventing_a_process() {
        let sample = r#"{"bug_type":"226","timestamp":"2026-07-17 04:11:39.00 -0400","os_version":"iPhone OS 26.5.2 (23F84)","roots_installed":0}
{"postTime":1784275899161,"events":[{"Manatee-numTLKShares":25,"OATrust":2},{"inCircle":0,"lastKeystateReady":"Pending"}]}"#;
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"indicator","pattern":"[process:name='SFA-ckks.json']"}]}"#,
        )
        .unwrap();
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/Retired/SFA-ckks.json-2026-07-17-041139.ips",
            sample,
            &db,
            &mut findings,
        );
        assert_eq!(summary.status, "parsed");
        assert_eq!(summary.details["format"], "security_analytics");
        assert_eq!(summary.details["processes"], 0);
        assert_eq!(summary.details["detection_relevant"], false);
        assert!(findings.is_empty());
    }

    #[test]
    fn security_analytics_concatenated_documents_parse() {
        // Real SFA files can carry several JSON documents back-to-back with
        // no separator; a single-document body parse fails on them.
        let sample = r#"{"bug_type":"226","timestamp":"2026-07-16 18:13:25.00 -0400","os_version":"iPhone OS 26.5.2 (23F84)"}
{"postTime":1784240005192,"events":[{"KTFetchCloudStorage-s":4}]}{"postTime":1784240005500,"events":[{"IDSKTPending-f":6}]}"#;
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/Retired/SFA-transparency.json-2026-07-16-181325.ips",
            sample,
            &IocDb::new(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed");
        assert_eq!(summary.details["format"], "security_analytics");
    }

    #[test]
    fn security_analytics_schema_drift_is_partial() {
        for body in [
            // extra top-level key
            r#"{"postTime":1,"events":[{}],"new_field":true}"#,
            // events element that is not an object
            r#"{"postTime":1,"events":["x"]}"#,
            // trailing non-JSON garbage after a valid document
            "{\"postTime\":1,\"events\":[{}]}\nnot json",
            // empty body
            "",
        ] {
            let sample = format!("{{\"bug_type\":\"226\"}}\n{body}");
            let mut findings = Findings::new();
            let (summary, _) = analyze(
                "root/crashes_and_spins/Retired/SFA-sos.json-2026.ips",
                &sample,
                &IocDb::new(),
                &mut findings,
            );
            assert_eq!(summary.status, "parsed_partial", "body: {body:?}");
        }
    }

    #[test]
    fn proactive_events_recognized_without_inventing_a_process() {
        let sample = r#"{"bug_type":"303","timestamp":"2026-07-16 23:13:17.00 -0400","os_version":"iPhone OS 26.5.2 (23F84)"}
Message Group: com.apple.Trial-com.apple.triald
Message Name: TRILogEvent
Message Type: 984eb588
Message Body:
1 {
  1: 1
  2: "799C0138-5E63-4698-964E-E2BF2465FEB7"
}
Message Grouping succeeded
Message Namespace: free-form payload
Message Group: com.apple.Trial-com.apple.triald
Message Name: TRILogEvent
Message Type: 984eb588
Message Body:
2: "task_status"
"#;
        let mut findings = Findings::new();
        let (summary, _) = analyze(
            "root/crashes_and_spins/Retired/proactive_event_tracker-com_apple_Trial-com_apple_triald-2026-07-16-231317.ips",
            sample,
            &IocDb::new(),
            &mut findings,
        );
        assert_eq!(summary.status, "parsed");
        assert_eq!(summary.details["format"], "proactive_events");
        assert_eq!(summary.details["processes"], 0);
        assert_eq!(summary.details["detection_relevant"], false);
        assert!(findings.is_empty());
    }

    #[test]
    fn proactive_events_malformed_block_is_partial() {
        for body in [
            // block opener missing its Message Body line
            "Message Group: com.apple.Trial\nMessage Name: TRILogEvent\nMessage Type: 984eb588\n1: 1\n",
            // content before the first block was never understood
            "stray preamble\nMessage Group: com.apple.Trial\nMessage Name: TRILogEvent\nMessage Type: 984eb588\nMessage Body:\n",
            // empty group value
            "Message Group:\nMessage Name: TRILogEvent\nMessage Type: 984eb588\nMessage Body:\n",
            // valid opener but no message payload
            "Message Group: com.apple.Trial\nMessage Name: TRILogEvent\nMessage Type: 984eb588\nMessage Body:\n",
            // reserved label outside an opener sequence
            "Message Group: com.apple.Trial\nMessage Name: TRILogEvent\nMessage Type: 984eb588\nMessage Body:\n1: payload\nMessage Name: orphan\n",
            // a double colon must not turn into a non-empty group value
            "Message Group:: com.apple.Trial\nMessage Name: TRILogEvent\nMessage Type: 984eb588\nMessage Body:\n1: payload\n",
            // whitespace before the second separator is malformed too
            "Message Group: : com.apple.Trial\nMessage Name: TRILogEvent\nMessage Type: 984eb588\nMessage Body:\n1: payload\n",
            // every block, not just the final one, needs payload
            "Message Group: com.apple.Trial\nMessage Name: First\nMessage Type: 984eb588\nMessage Body:\nMessage Group: com.apple.Trial\nMessage Name: Second\nMessage Type: 984eb588\nMessage Body:\n1: payload\n",
            // no blocks at all
            "",
        ] {
            let sample = format!("{{\"bug_type\":\"303\"}}\n{body}");
            let mut findings = Findings::new();
            let (summary, _) = analyze(
                "root/crashes_and_spins/Retired/proactive_event_tracker-x-2026.ips",
                &sample,
                &IocDb::new(),
                &mut findings,
            );
            assert_eq!(summary.status, "parsed_partial", "body: {body:?}");
        }
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
