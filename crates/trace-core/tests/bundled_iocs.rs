//! The bundled STIX snapshots are Trace's reviewed indicator contract. The
//! manifest must name the exact expected roster, pin each snapshot's bytes,
//! and record the exact extraction and process-observable coverage counts.
//! A snapshot update therefore requires an intentional review of the file,
//! its SHA-256 pin, and both counts (`cargo run --example ioc_stats` prints
//! the replacement values).

use serde::Deserialize;
use sha2::{Digest, Sha256};
use trace_core::ioc::IocDb;

#[derive(Debug, Deserialize)]
struct Manifest {
    sets: Vec<ManifestSet>,
}

#[derive(Debug, Deserialize)]
struct ManifestSet {
    name: String,
    file: String,
    sha256: String,
    min_indicators: u64,
    min_applicable: u64,
}

#[derive(Debug)]
struct ReviewedSet {
    name: &'static str,
    file: &'static str,
    extracted: u64,
    applicable: u64,
}

const REVIEWED_SETS: &[ReviewedSet] = &[
    ReviewedSet {
        name: "pegasus",
        file: "iocs/pegasus.stix2",
        extracted: 1549,
        applicable: 81,
    },
    ReviewedSet {
        name: "predator",
        file: "iocs/predator.stix2",
        extracted: 585,
        applicable: 4,
    },
    ReviewedSet {
        name: "kingspawn",
        file: "iocs/kingspawn.stix2",
        extracted: 167,
        applicable: 3,
    },
    ReviewedSet {
        name: "triangulation",
        file: "iocs/triangulation.stix2",
        extracted: 112,
        applicable: 1,
    },
    ReviewedSet {
        name: "rcs",
        file: "iocs/rcs.stix2",
        extracted: 40,
        applicable: 0,
    },
    ReviewedSet {
        name: "wintego_helios",
        file: "iocs/wintego_helios.stix2",
        extracted: 175,
        applicable: 0,
    },
    ReviewedSet {
        name: "coruna",
        file: "iocs/coruna.stix2",
        extracted: 216,
        applicable: 0,
    },
    ReviewedSet {
        name: "darksword",
        file: "iocs/darksword.stix2",
        extracted: 43,
        applicable: 0,
    },
];

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[test]
fn bundled_snapshots_match_reviewed_contract() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../web/iocs");
    let manifest: Manifest = serde_json::from_slice(
        &std::fs::read(format!("{dir}/manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");

    assert_eq!(
        manifest.sets.len(),
        REVIEWED_SETS.len(),
        "manifest set roster changed: review additions/removals and update the exact contract"
    );

    for (position, (set, reviewed)) in manifest.sets.iter().zip(REVIEWED_SETS).enumerate() {
        assert_eq!(
            set.name, reviewed.name,
            "manifest set #{position} has an unexpected name or order"
        );
        assert_eq!(
            set.file, reviewed.file,
            "{}: manifest file changed",
            reviewed.name
        );
        assert!(
            is_lowercase_sha256(&set.sha256),
            "{}: sha256 must be exactly 64 lowercase hexadecimal characters",
            reviewed.name
        );
        assert_eq!(
            set.min_indicators, reviewed.extracted,
            "{}: reviewed extraction count changed",
            reviewed.name
        );
        assert_eq!(
            set.min_applicable, reviewed.applicable,
            "{}: reviewed process-observable coverage count changed",
            reviewed.name
        );

        let path = format!("{dir}/../{}", set.file);
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|error| panic!("{}: cannot read {path}: {error}", reviewed.name));
        let actual_sha256 = sha256_hex(&bytes);
        assert_eq!(
            actual_sha256, set.sha256,
            "{}: bundled snapshot bytes do not match the reviewed manifest pin",
            reviewed.name
        );

        let json = std::str::from_utf8(&bytes)
            .unwrap_or_else(|error| panic!("{}: snapshot is not UTF-8: {error}", reviewed.name));
        let bundle: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            panic!("{}: bundled snapshot must be JSON: {error}", reviewed.name)
        });
        let malware: Vec<_> = bundle["objects"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|object| object["type"].as_str() == Some("malware"))
            .collect();
        assert_eq!(
            malware.len(),
            1,
            "{}: each reviewed single-campaign snapshot must identify exactly one malware object",
            reviewed.name
        );
        assert!(
            malware[0]["name"]
                .as_str()
                .is_some_and(|name| !name.trim().is_empty()),
            "{}: the reviewed malware object must have a non-empty name",
            reviewed.name
        );

        let mut db = IocDb::new();
        let stats = db.load_stix(&set.name, json).unwrap_or_else(|error| {
            panic!("{}: bundled snapshot must parse: {error}", reviewed.name)
        });
        assert_eq!(
            stats.extracted as u64, reviewed.extracted,
            "{}: extraction changed; review the snapshot/parser diff before updating the contract",
            reviewed.name
        );
        assert_eq!(
            stats.applicable as u64, reviewed.applicable,
            "{}: process-observable coverage changed; review before updating the contract",
            reviewed.name
        );
    }
}
