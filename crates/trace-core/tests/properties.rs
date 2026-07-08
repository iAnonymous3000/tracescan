//! Property tests for the hostile-input surface: the scanner ingests
//! attacker-controlled bytes (archives) and semi-trusted JSON (STIX), so the
//! core invariant is "never panic, never runaway, same result regardless of
//! chunking". The tar builder here is written independently of the crate's
//! internal test_util so these tests cross-check the reader.

use proptest::prelude::*;
use std::io::Write;
use trace_core::engine::Engine;
use trace_core::ioc::IocDb;
use trace_core::tar_stream::{Limits, TarCollector};

/// Independent minimal ustar writer.
fn tar_entry(name: &str, data: &[u8]) -> Vec<u8> {
    assert!(name.len() < 100);
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..108].copy_from_slice(b"0000644\0");
    h[108..116].copy_from_slice(b"0000000\0");
    h[116..124].copy_from_slice(b"0000000\0");
    let size = format!("{:011o}\0", data.len());
    h[124..136].copy_from_slice(size.as_bytes());
    h[136..148].copy_from_slice(b"00000000000\0");
    h[148..156].copy_from_slice(b"        ");
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    let sum: u32 = h.iter().map(|&b| b as u32).sum();
    let cks = format!("{:06o}\0 ", sum);
    h[148..156].copy_from_slice(cks.as_bytes());
    let mut out = h.to_vec();
    out.extend_from_slice(data);
    out.resize(out.len() + (512 - data.len() % 512) % 512, 0);
    out
}

fn finish_tar(mut a: Vec<u8>) -> Vec<u8> {
    a.resize(a.len() + 1024, 0);
    a
}

const MINI_STIX: &str = r#"{"objects":[
    {"type":"malware","name":"Pegasus"},
    {"type":"indicator","pattern":"[process:name='bh']"}
]}"#;

proptest! {
    /// Arbitrary bytes through the tar state machine: no panics, no
    /// retention beyond the caps.
    #[test]
    fn tar_collector_survives_arbitrary_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..4096),
        chunk in 1usize..512,
    ) {
        let mut col = TarCollector::with_limits(Limits::default());
        for c in data.chunks(chunk) {
            col.write_all(c).unwrap();
        }
        let retained: usize = col.files.iter().map(|f| f.data.len()).sum();
        prop_assert!(retained <= Limits::default().total_retain_cap);
    }

    /// Arbitrary bytes through the full engine (raw and gzip-magic-prefixed):
    /// push/finish may error, but must never panic.
    #[test]
    fn engine_survives_arbitrary_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..4096),
        gz_prefix in any::<bool>(),
        chunk in 1usize..512,
    ) {
        let mut engine = Engine::new();
        engine.load_stix("t", MINI_STIX).unwrap();
        let mut all = if gz_prefix { vec![0x1f, 0x8b] } else { Vec::new() };
        all.extend_from_slice(&data);
        let mut failed = false;
        for c in all.chunks(chunk) {
            if engine.push(c).is_err() {
                failed = true;
                break;
            }
        }
        if !failed {
            let _ = engine.finish();
        }
    }

    /// The STIX loader accepts attacker-shaped JSON without panicking, for
    /// both arbitrary text and arbitrary pattern strings inside a valid
    /// indicator object.
    #[test]
    fn stix_loader_survives_arbitrary_input(raw in ".{0,300}", pattern in ".{0,120}") {
        let mut db = IocDb::new();
        let _ = db.load_stix("a", &raw);
        let obj = serde_json::json!({"objects": [
            {"type": "indicator", "pattern": pattern},
            {"type": "malware", "name": pattern},
        ]});
        let _ = db.load_stix("b", &obj.to_string());
    }

    /// Chunking invariance: the same well-formed archive yields the same
    /// artifacts and findings no matter how the stream is sliced. The file
    /// contents are arbitrary bytes, so parser robustness rides along.
    #[test]
    fn report_is_chunk_size_invariant(
        ps_body in proptest::collection::vec(any::<u8>(), 0..1024),
        ips_body in proptest::collection::vec(any::<u8>(), 0..1024),
        chunk in 1usize..2048,
    ) {
        let mut a = Vec::new();
        a.extend_from_slice(&tar_entry("root/ps.txt", &ps_body));
        a.extend_from_slice(&tar_entry("root/crashes_and_spins/x-1.ips", &ips_body));
        a.extend_from_slice(&tar_entry("root/ignored.bin", b"zzz"));
        let tar = finish_tar(a);

        let run = |chunk: usize| {
            let mut engine = Engine::new();
            engine.load_stix("t", MINI_STIX).unwrap();
            for c in tar.chunks(chunk) {
                engine.push(c).unwrap();
            }
            let r = engine.finish().unwrap();
            (r.stats.artifacts_found, r.findings.len())
        };
        let baseline = run(tar.len());
        prop_assert_eq!(baseline.0, 2);
        prop_assert_eq!(run(chunk), baseline);
    }
}
