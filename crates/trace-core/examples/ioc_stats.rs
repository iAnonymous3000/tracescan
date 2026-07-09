//! Prints per-set indicator counts for the bundled STIX snapshots. Use it
//! to regenerate the `min_indicators` / `min_applicable` floors in
//! web/iocs/manifest.json after a snapshot update:
//!
//!   cargo run --example ioc_stats
//!
//! The floors gate the browser's "upstream update available" notice (a
//! hollow upstream file is not an update) and are pinned against the
//! snapshots themselves by tests/bundled_iocs.rs in CI. Scans only ever
//! use the bundled, reviewed snapshots.

use trace_core::ioc::IocDb;

fn main() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../web/iocs");
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .expect("read web/iocs")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("stix2"))
        .collect();
    files.sort();
    for p in files {
        let name = p.file_stem().unwrap().to_string_lossy().into_owned();
        let mut db = IocDb::new();
        let stats = db
            .load_stix(&name, &std::fs::read_to_string(&p).expect("read set"))
            .expect("parse set");
        println!(
            "{}: extracted={} applicable={}",
            stats.name, stats.extracted, stats.applicable
        );
    }
}
