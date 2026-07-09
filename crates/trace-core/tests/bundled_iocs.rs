//! The bundled STIX snapshots are the reviewed indicator floor: the browser
//! rejects a live-fetched file that would drop a set below the manifest's
//! `min_indicators` / `min_applicable`. This test keeps that contract
//! honest in both directions - every bundled snapshot must itself meet its
//! declared floor, so a snapshot-update PR that regresses a set fails CI
//! until the floor is consciously adjusted (`cargo run --example ioc_stats`
//! prints the current numbers).

use trace_core::ioc::IocDb;

#[test]
fn bundled_snapshots_meet_their_manifest_floors() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../web/iocs");
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(format!("{dir}/manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");
    let sets = manifest["sets"].as_array().expect("manifest sets array");
    assert!(!sets.is_empty());

    for set in sets {
        let name = set["name"].as_str().expect("set name");
        let file = set["file"].as_str().expect("set file");
        let min_indicators = set["min_indicators"]
            .as_u64()
            .unwrap_or_else(|| panic!("{name}: manifest is missing min_indicators"));
        let min_applicable = set["min_applicable"]
            .as_u64()
            .unwrap_or_else(|| panic!("{name}: manifest is missing min_applicable"));

        let path = format!("{dir}/../{file}");
        let json = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{name}: cannot read {path}: {e}"));
        let mut db = IocDb::new();
        let stats = db
            .load_stix(name, &json)
            .unwrap_or_else(|e| panic!("{name}: bundled snapshot must parse: {e}"));

        assert!(
            stats.extracted as u64 >= min_indicators,
            "{name}: bundled snapshot extracts {} indicators, below its floor of {min_indicators} - review the snapshot change, then regenerate floors",
            stats.extracted
        );
        assert!(
            stats.applicable as u64 >= min_applicable,
            "{name}: bundled snapshot has {} applicable indicators, below its floor of {min_applicable}",
            stats.applicable
        );
    }
}
