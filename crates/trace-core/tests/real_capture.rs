//! Integration check against a real sysdiagnose. Real captures are personal
//! data and are never committed, so this test is ignored by default and
//! runs only when pointed at one:
//!
//!   TRACE_REAL_SYSDIAGNOSE=path/to/sysdiagnose_….tar.gz \
//!     cargo test --release --test real_capture -- --ignored --nocapture

use std::io::Read;
use trace_core::engine::Engine;

#[test]
#[ignore = "needs TRACE_REAL_SYSDIAGNOSE pointing at a real capture"]
fn real_capture_end_to_end() {
    let path = std::env::var("TRACE_REAL_SYSDIAGNOSE")
        .expect("set TRACE_REAL_SYSDIAGNOSE to a sysdiagnose .tar.gz");
    let mut engine = Engine::new();
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
        "unified log: {} tracev3 files ({} failures), {} processes seen, {} resolved to paths",
        unified.details["tracev3_files"], failures, seen, resolved
    );
    assert!(seen > 50, "a real device logs from many binaries");
    assert!(
        resolved * 100 >= seen * 80,
        "most binaries should resolve to paths"
    );
    assert_eq!(failures, 0, "real tracev3 files should all parse");
}
