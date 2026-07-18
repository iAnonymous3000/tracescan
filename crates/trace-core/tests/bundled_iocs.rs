//! The bundled STIX snapshots are the reviewed indicator floor - the only
//! indicators scans ever use. The manifest's `min_indicators` /
//! `min_applicable` gate two things: the browser's "upstream update
//! available" notice (a hollow upstream file is not an update), and this
//! test. Runtime update checks use the values as minimum plausibility floors;
//! CI requires the reviewed bundled snapshot to match them exactly, so count
//! inflation, substitution, and regression all require a conscious review
//! and floor update (`cargo run --example ioc_stats` prints the numbers).

use trace_core::ioc::IocDb;

#[test]
fn bundled_snapshots_match_reviewed_manifest_counts() {
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
        let bundle: serde_json::Value = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("{name}: bundled snapshot must be JSON: {e}"));
        let malware_objects = bundle["objects"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|object| object["type"].as_str() == Some("malware"))
            .count();
        assert_eq!(
            malware_objects, 1,
            "{name}: each reviewed single-campaign snapshot must identify exactly one malware object"
        );

        let mut db = IocDb::new();
        let stats = db
            .load_stix(name, &json)
            .unwrap_or_else(|e| panic!("{name}: bundled snapshot must parse: {e}"));

        assert_eq!(
            stats.extracted as u64, min_indicators,
            "{name}: reviewed snapshot count changed - review the snapshot diff, then regenerate its floor"
        );
        assert_eq!(
            stats.applicable as u64, min_applicable,
            "{name}: reviewed applicable-indicator count changed - review the snapshot diff, then regenerate its floor"
        );
    }
}
