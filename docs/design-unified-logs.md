# Design: unified-log process inventory

Status: implemented in `crates/trace-core/src/unified_log.rs` and
`crates/trace-core/src/tar_stream.rs`. This document describes the current
architecture and the reason Trace performs catalog-level analysis instead of
full unified-log reconstruction.

## Scope decision

An iOS `system_logs.logarchive` contains tracev3 catalogs that identify a
process by PID and main-binary UUID. A corresponding uuidtext footer can map
that UUID to the binary's path. Trace joins those two sources to create a
process inventory and applies the same process-name, file-name, file-path, and
path-location checks used by the other process-bearing surfaces.

Trace does not reconstruct or search unified-log messages. Message rendering
would require substantially more supporting data, including large shared
string caches, and would create a different resource and validation problem.
Consequently, domain and URL values that might appear in message text are not
checked. Trace also does not parse iPhone backups or reconstruct messages from
backup databases; those are separate, out-of-scope acquisition and analysis
paths.

The implementation uses the pure-Rust `macos-unifiedlogs` parser, which builds
for `wasm32-unknown-unknown`. Trace consumes only the catalog and uuidtext
structures needed for this bounded inventory and does not load the `dsc`
shared-string cache.

## Streaming and reduction

The gzip and tar layers are streamed. Unified-log members are handled one file
at a time and dropped after their durable process facts have been retained:

1. A `.tracev3` member under the archive root's direct
   `system_logs.logarchive` child is buffered only up to the outer 32 MiB member
   cap. Nested or paired-device lookalikes are ignored. Trace validates complete
   top-level chunk framing, recognized chunk types, and declared decompression
   sizes before invoking the upstream parser. It then retains
   `(main_uuid, pid)` observations and catalog-appearance counts.
2. A canonical uuidtext member has a two-character uppercase-hex directory and
   a 30-character uppercase-hex filename. Trace parses its footer, validates
   its version and path, and retains a `uuid -> canonical binary path` mapping.
3. At finalization, the two maps are joined by UUID. Correctness does not
   depend on tar member ordering: tracev3 observations and uuidtext mappings
   are both retained until the join.
4. Each resolved path is checked against applicable indicators: exact,
   case-sensitive process/file basenames and full paths, plus canonical
   descendants of trailing-slash directory path indicators. Path heuristics are
   applied separately. Report evidence includes the path, UUID, retained PID
   count and sample, and catalog-appearance count.

The resulting `ArtifactSummary` reports file, catalog, process, resolution,
failure, truncation, and conflict counts, plus retained PID/path-byte counts and
cap state. It does not claim first or last event timestamps or a precisely
measured log window, because this catalog-only path does not derive those
fields.

## Bounds and fail-closed behavior

The unified-log path applies both archive-wide limits and its own reduction
limits:

- 32 MiB buffered per tracev3 or uuidtext member;
- 64 MiB declared inner decompression per compressed tracev3 chunkset;
- 256 MiB aggregate declared inner decompression per tracev3 file;
- 65,536 tracked process UUIDs and 65,536 retained uuidtext mappings;
- 4,096 retained PIDs per process and 262,144 retained PIDs in aggregate;
- 4,096 bytes per retained path and 16 MiB of retained path bytes in
  aggregate; and
- the tar reader's 1,000,000-header and 8 GiB decompressed-stream ceilings.

A tracev3 file cut short by the outer member cap or rejected by framing
validation is not partially inventoried. Trace also degrades the surface when
the parser drops or collapses catalog data, a UUID or uuidtext file is invalid,
conflicting UUID mappings appear, an inventory cap is reached, no process is
inventoried, or any inventoried process cannot be resolved to a path. Surviving
findings from structurally usable catalogs remain visible, but a no-finding
result with one of these conditions is inconclusive rather than reassuring.

These limits close known single-declaration allocation hazards; they do not
prove bounded aggregate CPU time or browser responsiveness for an archive with
many individually valid hostile members. Availability loss remains a residual
risk and must produce a visible error or incomplete result, never a trustworthy
negative.

## Validation status

Public fixtures and CI cover framing, truncation, unsupported chunks, declared
decompression limits, catalog integrity, UUID/path validation, conflicts,
inventory caps, matching, and degraded-surface verdict behavior. Sanitized
aggregates from private real captures and the command for an ignored local
real-capture test are recorded in [`VALIDATION.md`](../VALIDATION.md). The
private archives are not published, so those results are receipts rather than
independently replayable public evidence.
