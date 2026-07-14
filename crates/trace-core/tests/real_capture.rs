//! Integration check against a real sysdiagnose. Real captures are personal
//! data and are never committed, so this test is ignored by default and
//! runs only when pointed at one:
//!
//!   TRACE_REAL_SYSDIAGNOSE=path/to/sysdiagnose_….tar.gz \
//!     cargo test --release --test real_capture -- --ignored --nocapture
//!
//! It loads the eight bundled indicator sets, so a passing run reproduces
//! the VALIDATION.md claim end to end: a clean capture must parse fully and
//! produce zero indicator matches and zero suspicious findings.

use std::io::Read;
use trace_core::engine::Engine;
use trace_core::report::{Severity, Verdict};

#[test]
#[ignore = "needs TRACE_REAL_SYSDIAGNOSE pointing at a real capture"]
fn real_capture_end_to_end() {
    let path = std::env::var("TRACE_REAL_SYSDIAGNOSE")
        .expect("set TRACE_REAL_SYSDIAGNOSE to a sysdiagnose .tar.gz");
    let mut engine = Engine::new();

    let iocs_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../web/iocs");
    let mut sets = 0usize;
    for entry in std::fs::read_dir(iocs_dir).expect("read web/iocs") {
        let p = entry.expect("dir entry").path();
        if p.extension().and_then(|e| e.to_str()) != Some("stix2") {
            continue;
        }
        let name = p.file_stem().unwrap().to_string_lossy().into_owned();
        let json = std::fs::read_to_string(&p).expect("read STIX file");
        let stats = engine.load_stix(&name, &json).expect("load STIX set");
        sets += 1;
        println!(
            "loaded {}: {} indicators, {} applicable",
            stats.name, stats.extracted, stats.applicable
        );
    }
    assert_eq!(sets, 8, "all bundled indicator sets must load");

    let mut file = std::fs::File::open(&path).expect("open capture");
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf).expect("read capture");
        if n == 0 {
            break;
        }
        engine.push(&buf[..n]).expect("stream capture");
    }
    let report = engine.finish().expect("finish scan");

    assert!(
        report.scan_limits.is_empty(),
        "real capture must not trip limits: {:?}",
        report.scan_limits
    );
    assert!(
        report.missing_artifacts.is_empty(),
        "a full sysdiagnose carries all four surfaces: {:?}",
        report
            .missing_artifacts
            .iter()
            .map(|m| &m.kind)
            .collect::<Vec<_>>()
    );
    let unified = report
        .artifacts
        .iter()
        .find(|a| a.kind == "unified_log")
        .expect("unified log summary present");
    assert_eq!(unified.status, "parsed");
    let seen = unified.details["processes_seen"].as_u64().unwrap();
    let resolved = unified.details["processes_resolved_to_path"]
        .as_u64()
        .unwrap();
    let failures = unified.details["tracev3_parse_failures"].as_u64().unwrap();
    println!(
        "unified log: {} tracev3 files ({} failures), {} catalogs, {} uuidtext files ({} failures), {} processes seen, {} resolved to paths",
        unified.details["tracev3_files"],
        failures,
        unified.details["catalogs"],
        unified.details["uuidtext_files"],
        unified.details["uuidtext_parse_failures"],
        seen,
        resolved
    );
    assert!(seen > 50, "a real device logs from many binaries");
    assert!(
        resolved * 100 >= seen * 80,
        "most binaries should resolve to paths"
    );
    assert_eq!(failures, 0, "real tracev3 files should all parse");

    // The false-positive bar: a clean capture against the full bundled
    // indicator load must produce no matches and no suspicious findings.
    for f in report
        .findings
        .iter()
        .filter(|f| f.severity != Severity::Note)
    {
        println!("unexpected finding [{:?}]: {}", f.severity, f.summary);
    }
    assert!(
        report.findings.iter().all(|f| f.severity == Severity::Note),
        "clean capture must yield no match/suspicious findings"
    );
    assert_eq!(report.verdict, Verdict::Clear);
}
