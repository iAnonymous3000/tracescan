//! Prints the exact roster, SHA-256 pins, extraction counts, and
//! process-observable coverage counts for the bundled STIX snapshots. Use it
//! when reviewing a snapshot update and copying the new contract values into
//! `web/iocs/manifest.json`:
//!
//!   cargo run --example ioc_stats
//!
//! Scans only ever use the bundled, reviewed snapshots. The companion
//! `tests/bundled_iocs.rs` test requires the manifest and files to match the
//! reviewed contract exactly.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use trace_core::ioc::IocDb;

#[derive(Deserialize)]
struct Manifest {
    sets: Vec<ManifestSet>,
}

#[derive(Deserialize)]
struct ManifestSet {
    name: String,
    file: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn main() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../web/iocs");
    let manifest: Manifest = serde_json::from_slice(
        &std::fs::read(format!("{dir}/manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");

    for set in manifest.sets {
        let path = format!("{dir}/../{}", set.file);
        let bytes = std::fs::read(&path).unwrap_or_else(|error| panic!("read {path}: {error}"));
        let json = std::str::from_utf8(&bytes).expect("snapshot must be UTF-8");
        let mut db = IocDb::new();
        let stats = db
            .load_stix(&set.name, json)
            .unwrap_or_else(|error| panic!("{}: parse set: {error}", set.name));

        println!(
            "{}: file={} sha256={} extracted={} applicable={}",
            stats.name,
            set.file,
            sha256_hex(&bytes),
            stats.extracted,
            stats.applicable
        );
    }
}
