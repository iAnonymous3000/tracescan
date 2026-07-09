# Design: unified log (tracev3) analysis

Status: implemented in v0.5.0 (`crates/trace-core/src/unified_log.rs`),
following the architecture below. This documents the spike results and the
design rationale; it is kept as the record of why catalog-level analysis
was chosen over full log reconstruction.

## Spike results (2026-07-08)

- `macos-unifiedlogs` 0.6.0 (Mandiant's parser, pure Rust) compiles to
  `wasm32-unknown-unknown` unmodified.
- Its `FileProvider` trait is explicitly designed for non-filesystem
  sources: consumers supply `Read` implementations, and uuidtext/dsc reads
  are on-demand by UUID, "avoiding having to read all UUIDText files into
  memory".
- `parse_log(reader, evidence)` parses a single `.tracev3` file to
  `UnifiedLogData`, whose catalogs carry `catalog_process_info_entries`
  (pid, `main_uuid`, effective UID) without any string resolution.

## Why not full log reconstruction

Rendering log *messages* requires the shared string caches (`dsc`, commonly
100 MB+) and the full uuidtext tree. That budget does not exist in a browser
tab, and messages are not where the v1 indicator value is: domains/URLs in
message bodies are backup-artifact territory, already declared out of scope.

## Chosen architecture: catalog-level process inventory

The high-value slice is the **process inventory**: every process that
emitted a log entry during the archive window (typically days of history),
with pid and binary path - matched against exactly the same process/path
indicators and location heuristics as the other three surfaces. This needs
only the tracev3 catalogs plus the uuidtext footer (which stores the binary
path), and never touches dsc.

Streaming plan, single pass, bounded memory:

1. `tar_stream` learns two artifact kinds it does NOT retain:
   - `*.tracev3` under `system_logs.logarchive/` - on file completion, hand
     the bytes to a consumer callback, run `parse_log`, harvest
     `(main_uuid, pid)` pairs from catalog process entries, drop the bytes.
     Individual files are ~10 MB; only one is ever held.
   - `uuidtext` files (`XX/YYYY…`, 32-hex layout) - parse the footer path
     on completion (files are KB-sized), keep a `uuid -> path` map, drop the
     bytes. Tar ordering conveniently delivers tracev3 (`Persist/`,
     `Special/`) before `uuidtext/`, so needed UUIDs are known first; the
     map can be filtered to them, capped, and any overflow surfaces in
     `scan_limits`.
2. At `finish()`, join the two: a deduplicated process inventory
   `(path, pids, entry count, first/last timestamp)` feeds
   `IocDb::match_process` and `heuristics::path_flag_finding`, emitting
   findings with the same severity semantics as the other surfaces, plus an
   `ArtifactSummary` (processes seen, files parsed, window covered).
3. Missing-artifact handling: a sysdiagnose without a logarchive reports the
   surface as unavailable, same as the other three.

## Open needs

- **Real test data.** No public sysdiagnose ships real tracev3 content, and
  synthesizing tracev3 is not realistic. Development and validation need a
  real capture: either the maintainer's sysdiagnose, or a logarchive from
  `sudo log collect` on a Mac (same format family). Test fixtures committed
  to the repo must be reviewed for personal data first; catalog-level
  fixtures (no message strings) carry far less.
- **Version bump and coverage copy.** Shipping this moves the "unified
  system logs" line from `not_examined` to `examined`, changes the
  README/about copy, and warrants a minor version.
