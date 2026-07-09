//! Native CLI harness around the same engine the browser runs.
//! Useful for validating against real sysdiagnose archives and for
//! debugging without a browser in the loop. Nothing here is shipped.
//!
//! Usage:
//!   cargo run --release --example scan -- <archive.tar.gz> <set.stix2>...

use std::io::Read;
use trace_core::engine::{Engine, ScanMeta, SetMeta};

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(archive_path) = args.next() else {
        eprintln!("usage: scan <archive.tar.gz> <set.stix2>...");
        std::process::exit(2);
    };

    let mut engine = Engine::new();
    for stix_path in args {
        let json = std::fs::read_to_string(&stix_path).expect("read STIX file");
        let name = stix_path
            .rsplit('/')
            .next()
            .unwrap_or(&stix_path)
            .trim_end_matches(".stix2")
            .to_string();
        let meta = SetMeta {
            source: Some("local file".into()),
            url: Some(stix_path.clone()),
            ..Default::default()
        };
        let stats = engine
            .load_stix_with_meta(&name, &json, meta)
            .expect("parse STIX file");
        eprintln!(
            "loaded {}: {} indicators, {} applicable",
            stats.name, stats.extracted, stats.applicable
        );
    }

    let started = std::time::Instant::now();
    // Same contract as the browser wrapper: the engine measures duration
    // itself, through the end of report assembly.
    engine.set_clock(Box::new(move || started.elapsed().as_secs_f64() * 1000.0));
    let mut file = std::fs::File::open(&archive_path).expect("open archive");
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf).expect("read archive");
        if n == 0 {
            break;
        }
        if let Err(e) = engine.push(&buf[..n]) {
            eprintln!("scan failed: {e}");
            std::process::exit(1);
        }
    }
    let size = std::fs::metadata(&archive_path).ok().map(|m| m.len());
    engine.set_scan_meta(ScanMeta {
        source_name: Some(
            archive_path
                .rsplit('/')
                .next()
                .unwrap_or(&archive_path)
                .to_string(),
        ),
        source_size: size,
        scanned_via: Some("native".into()),
    });
    engine.set_generated_at(
        humantime::format_rfc3339_seconds(std::time::SystemTime::now()).to_string(),
    );
    match engine.finish() {
        Ok(report) => {
            eprintln!("scanned in {:.1?}", started.elapsed());
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        }
        Err(e) => {
            eprintln!("scan failed: {e}");
            std::process::exit(1);
        }
    }
}
