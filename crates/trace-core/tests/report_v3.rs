//! Report v3 contract tests: the exported report validates against the
//! checked-in JSON Schema, and its field shape matches the golden path
//! list that the browser producers (worker and inline, see
//! e2e/tests/trace.spec.js) are held to as well. A shape change that
//! shows up here without a schema_version discussion is a regression.
//!
//! Regenerate the golden after an intentional change:
//!   TRACE_UPDATE_GOLDEN=1 cargo test --test report_v3

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use trace_core::engine::{Engine, ScanMeta, SetMeta};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Runs a scan the way the browser producers do: all bundled sets with
/// catalog metadata, streamed archive, scan metadata set before finish.
fn scan_fixture(fixture: &str) -> serde_json::Value {
    let root = repo_root();
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("web/iocs/manifest.json")).unwrap(),
    )
    .unwrap();
    let mut engine = Engine::new();
    for set in manifest["sets"].as_array().unwrap() {
        let name = set["name"].as_str().unwrap();
        let text =
            std::fs::read_to_string(root.join("web").join(set["file"].as_str().unwrap())).unwrap();
        engine
            .load_stix_with_meta(
                name,
                &text,
                SetMeta {
                    date: manifest["bundled_date"].as_str().map(String::from),
                    url: set["url"].as_str().map(String::from),
                    source: set["source"].as_str().map(String::from),
                    loaded_from: Some("bundled".into()),
                    upstream: Some("unknown".into()),
                },
            )
            .unwrap();
    }
    let data = std::fs::read(root.join("web/fixtures").join(fixture)).unwrap();
    let started = std::time::Instant::now();
    engine.set_clock(Box::new(move || started.elapsed().as_secs_f64() * 1000.0));
    for chunk in data.chunks(65536) {
        engine.push(chunk).unwrap();
    }
    engine.set_scan_meta(ScanMeta {
        source_name: Some(fixture.into()),
        source_size: Some(data.len() as u64),
        scanned_via: Some("native".into()),
    });
    engine.set_generated_at("2026-01-01T00:00:00Z".into());
    serde_json::to_value(engine.finish().unwrap()).unwrap()
}

/// Flattens a report to its set of field paths; array indices normalize to
/// `[]`. Paths whose contents legitimately vary (parser-specific evidence
/// and details, per-set indicator-kind tallies) are treated as opaque
/// leaves so the golden pins the envelope, not parser internals.
fn field_paths(v: &serde_json::Value, prefix: String, out: &mut BTreeSet<String>) {
    const OPAQUE: [&str; 3] = [
        "/findings[]/evidence",
        "/artifacts[]/details",
        "/indicator_sets[]/by_kind",
    ];
    if OPAQUE.contains(&prefix.as_str()) {
        out.insert(prefix);
        return;
    }
    match v {
        serde_json::Value::Object(m) if !m.is_empty() => {
            for (k, val) in m {
                field_paths(val, format!("{prefix}/{k}"), out);
            }
        }
        serde_json::Value::Array(a) if !a.is_empty() => {
            for val in a {
                field_paths(val, format!("{prefix}[]"), out);
            }
        }
        _ => {
            out.insert(prefix);
        }
    }
}

fn paths_of(report: &serde_json::Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    field_paths(report, String::new(), &mut out);
    out
}

#[test]
fn reports_validate_against_checked_in_schema() {
    let schema: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo_root().join("web/report.schema.json")).unwrap(),
    )
    .unwrap();
    let validator = jsonschema::validator_for(&schema).expect("schema itself must be valid");
    for fixture in [
        "sysdiagnose_demo_infected.tar.gz",
        "sysdiagnose_demo_clean.tar.gz",
    ] {
        let report = scan_fixture(fixture);
        let errors: Vec<String> = validator
            .iter_errors(&report)
            .map(|e| format!("{}: {e}", e.instance_path()))
            .collect();
        assert!(
            errors.is_empty(),
            "{fixture} report violates web/report.schema.json:\n{}",
            errors.join("\n")
        );
    }
}

#[test]
fn artifact_status_contract_matches_the_engine() {
    let schema: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo_root().join("web/report.schema.json")).unwrap(),
    )
    .unwrap();
    let validator = jsonschema::validator_for(&schema).expect("schema itself must be valid");
    let base = scan_fixture("sysdiagnose_demo_clean.tar.gz");

    for status in ["parsed", "parsed_partial", "unparsed", "truncated"] {
        let mut report = base.clone();
        report["artifacts"][0]["status"] = serde_json::Value::String(status.into());
        assert!(
            validator.is_valid(&report),
            "engine artifact status {status:?} must remain valid in report v3"
        );
    }

    let mut report = base;
    report["artifacts"][0]["status"] = serde_json::Value::String("clean".into());
    assert!(
        !validator.is_valid(&report),
        "unknown artifact statuses must fail the closed report contract"
    );
}

#[test]
fn field_shape_matches_golden() {
    let golden_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/report_fields_v3.json");
    let report = scan_fixture("sysdiagnose_demo_infected.tar.gz");
    let paths = paths_of(&report);
    if std::env::var("TRACE_UPDATE_GOLDEN").is_ok() {
        std::fs::write(
            &golden_path,
            serde_json::to_string_pretty(&paths.iter().collect::<Vec<_>>()).unwrap() + "\n",
        )
        .unwrap();
        return;
    }
    let golden: BTreeSet<String> = serde_json::from_str(
        &std::fs::read_to_string(&golden_path)
            .expect("golden missing - run with TRACE_UPDATE_GOLDEN=1 to create it"),
    )
    .unwrap();
    let missing: Vec<&String> = golden.difference(&paths).collect();
    let extra: Vec<&String> = paths.difference(&golden).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "report field shape drifted from tests/report_fields_v3.json\nmissing: {missing:?}\nextra: {extra:?}\nIf intentional, regenerate with TRACE_UPDATE_GOLDEN=1 and update the browser parity test expectations."
    );
}

#[test]
fn producer_metadata_lands_in_envelope() {
    let report = scan_fixture("sysdiagnose_demo_clean.tar.gz");
    assert_eq!(report["schema_version"], 3);
    assert_eq!(report["scanned_via"], "native");
    assert_eq!(
        report["source_file"]["name"],
        "sysdiagnose_demo_clean.tar.gz"
    );
    // The engine hashed the real bytes: 64 lowercase hex chars.
    let sha = report["source_file"]["sha256"].as_str().unwrap();
    assert_eq!(sha.len(), 64);
    assert!(sha
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    // Engine-measured duration: present whenever a clock was injected.
    assert!(report["duration_ms"].as_u64().is_some());
    // Every loaded set has engine-computed provenance.
    assert_eq!(
        report["indicator_provenance"].as_array().unwrap().len(),
        report["indicator_sets"].as_array().unwrap().len()
    );
    // Assurance mirrors the demo fixture: no unified logs, rest complete.
    assert_eq!(report["assurance"]["complete"], true);
    assert_eq!(report["assurance"]["surfaces_total"], 4);
    assert_eq!(report["assurance"]["surfaces_examined"], 3);
}
