//! Unified log (tracev3) analysis: catalog-level process inventory.
//!
//! Every tracev3 chunk carries a catalog listing the processes that emitted
//! the entries in it (pid plus the UUID of the main binary), and each
//! uuidtext file's footer stores that binary's full path. Joining the two
//! yields process identities represented in the parsed catalog data without
//! rendering a single log message or claiming a precise time window - so the
//! 155 MB dsc shared-string cache is never loaded and peak
//! memory stays at one file. Design: docs/design-unified-logs.md.
//!
//! Files are consumed as they stream out of the tar (see `tar_stream`):
//! tracev3 files arrive before the uuidtext tree, so process UUIDs are
//! collected first and paths attach afterwards.

use crate::heuristics::path_flag_finding;
use crate::ioc::{basename, IocDb};
use crate::report::{ArtifactSummary, Finding, Findings};
use macos_unifiedlogs::parser::parse_log;
use macos_unifiedlogs::uuidtext::UUIDText;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};

/// A real logarchive holds a few hundred binaries. Identity/path caps only
/// matter for hostile input and make the scan incomplete. PID history is
/// evidence sampling: a long-lived binary can legitimately appear under many
/// PIDs, while matching still depends only on its retained UUID and path.
const MAX_TRACKED_UUIDS: usize = 65_536;
const MAX_PIDS_PER_PROCESS: usize = 4_096;
/// Aggregate budgets keep the per-process/per-path caps from multiplying into
/// an allocation far larger than a browser tab can sustain.
const MAX_TOTAL_TRACKED_PIDS: usize = 262_144;
const MAX_TOTAL_PATH_BYTES: usize = 16 * 1024 * 1024;
/// Real binary paths are well under 1 KB; a crafted uuidtext footer must not
/// be able to store megabytes per tracked UUID.
const MAX_PATH_BYTES: usize = 4_096;
/// Kernel entries carry an all-zeros main UUID and no binary path.
const ZERO_UUID: &str = "00000000000000000000000000000000";
/// The upstream crate's UUIDText fixtures (High Sierra and Big Sur) and
/// logarchive integration fixture all use the same on-disk layout version.
const UUIDTEXT_MAJOR_VERSION: u32 = 2;
const UUIDTEXT_MINOR_VERSION: u32 = 1;

/// tracev3 container chunk tags (mirroring the upstream parser's constants).
const CHUNK_HEADER: u32 = 0x1000;
const CHUNK_CATALOG: u32 = 0x600b;
const CHUNK_CHUNKSET: u32 = 0x600d;
/// Bytes after the chunk preamble and before the catalog UUID array.
const CATALOG_FIXED_BODY_SIZE: usize = 24;

fn u16_at(data: &[u8], offset: usize) -> Result<u16, &'static str> {
    let end = offset.checked_add(2).ok_or("catalog offset overflow")?;
    let bytes = data
        .get(offset..end)
        .ok_or("catalog field exceeds its declared body")?;
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32, &'static str> {
    let end = offset.checked_add(4).ok_or("catalog offset overflow")?;
    let bytes = data
        .get(offset..end)
        .ok_or("catalog field exceeds its declared body")?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn checked_region_end(start: usize, len: usize, region_end: usize) -> Result<usize, &'static str> {
    start
        .checked_add(len)
        .filter(|&end| end <= region_end)
        .ok_or("catalog entry exceeds its declared region")
}

/// Mirrors the upstream process-entry byte layout without allocating. Nested
/// counts are bounded against the process region before the dependency sees
/// them, and the returned cursor includes the format-defined 8-byte alignment
/// after subsystem entries.
fn validate_catalog_process_entry(
    data: &[u8],
    start: usize,
    region_end: usize,
) -> Result<usize, &'static str> {
    // Four u16 fields, one u64, and six u32 fields through `unknown3`.
    let fixed_end = checked_region_end(start, 40, region_end)?;
    let uuid_count = usize::try_from(u32_at(data, start + 32)?)
        .map_err(|_| "catalog UUID-entry count is too large")?;
    let uuid_bytes = uuid_count
        .checked_mul(16)
        .ok_or("catalog UUID-entry size overflow")?;
    let uuid_end = checked_region_end(fixed_end, uuid_bytes, region_end)?;

    // `number_subsystems` and `unknown4` follow the UUID entries.
    let subsystem_header_end = checked_region_end(uuid_end, 8, region_end)?;
    let subsystem_count = usize::try_from(u32_at(data, uuid_end)?)
        .map_err(|_| "catalog subsystem count is too large")?;
    let subsystem_bytes = subsystem_count
        .checked_mul(6)
        .ok_or("catalog subsystem size overflow")?;
    let subsystem_end = checked_region_end(subsystem_header_end, subsystem_bytes, region_end)?;
    let padding = (8 - (subsystem_bytes % 8)) % 8;
    checked_region_end(subsystem_end, padding, region_end)
}

/// Mirrors the upstream catalog-subchunk layout without allocating. Its two
/// attacker-controlled array counts are checked against the declared catalog
/// body before upstream's repeated parsers run.
fn validate_catalog_subchunk(
    data: &[u8],
    start: usize,
    region_end: usize,
) -> Result<usize, &'static str> {
    // start, end, uncompressed size, compression algorithm, and index count.
    let fixed_end = checked_region_end(start, 28, region_end)?;
    let index_count = usize::try_from(u32_at(data, start + 24)?)
        .map_err(|_| "catalog subchunk index count is too large")?;
    let index_bytes = index_count
        .checked_mul(2)
        .ok_or("catalog subchunk index size overflow")?;
    let indexes_end = checked_region_end(fixed_end, index_bytes, region_end)?;

    let strings_header_end = checked_region_end(indexes_end, 4, region_end)?;
    let string_count = usize::try_from(u32_at(data, indexes_end)?)
        .map_err(|_| "catalog subchunk string count is too large")?;
    let string_bytes = string_count
        .checked_mul(2)
        .ok_or("catalog subchunk string size overflow")?;
    let strings_end = checked_region_end(strings_header_end, string_bytes, region_end)?;
    let array_bytes = index_bytes
        .checked_add(string_bytes)
        .ok_or("catalog subchunk array size overflow")?;
    let padding = (8 - (array_bytes % 8)) % 8;
    checked_region_end(strings_end, padding, region_end)
}

/// Validates the catalog's offset relationships and consumes every declared
/// process entry and subchunk exactly. The dependency trusts several offsets,
/// ignores the declared process/subchunk boundary, and accepts a parsed prefix
/// with trailing body bytes, so these invariants must hold before parsing.
fn validate_catalog_body(body: &[u8]) -> Result<(), &'static str> {
    if body.len() < CATALOG_FIXED_BODY_SIZE {
        return Err("catalog body is shorter than its fixed header");
    }
    let subsystem_offset = usize::from(u16_at(body, 0)?);
    let process_offset = usize::from(u16_at(body, 2)?);
    let process_count = usize::from(u16_at(body, 4)?);
    let subchunk_offset = usize::from(u16_at(body, 6)?);
    let subchunk_count = usize::from(u16_at(body, 8)?);
    let payload = &body[CATALOG_FIXED_BODY_SIZE..];

    if subsystem_offset % 16 != 0 {
        return Err("catalog UUID region is not a whole number of UUIDs");
    }
    if subsystem_offset > process_offset
        || process_offset > subchunk_offset
        || subchunk_offset > payload.len()
    {
        return Err("catalog internal offsets are unordered or out of bounds");
    }

    let mut cursor = process_offset;
    for _ in 0..process_count {
        cursor = validate_catalog_process_entry(payload, cursor, subchunk_offset)?;
    }
    if cursor != subchunk_offset {
        return Err("catalog process inventory does not consume its declared region");
    }

    for _ in 0..subchunk_count {
        cursor = validate_catalog_subchunk(payload, cursor, payload.len())?;
    }
    if cursor != payload.len() {
        return Err("catalog subchunks do not consume the declared body");
    }
    Ok(())
}

/// Validates one top-level tracev3 frame and returns its tag and the offset of
/// its body end and the next frame (including source padding).
fn tracev3_chunk_at(data: &[u8], i: usize) -> Result<(u32, usize, usize), &'static str> {
    let remaining = data.get(i..).ok_or("chunk offset overruns the file")?;
    if remaining.len() < 16 {
        return Err("truncated chunk preamble");
    }
    let tag = u32::from_le_bytes(remaining[0..4].try_into().unwrap());
    if !matches!(tag, CHUNK_HEADER | CHUNK_CATALOG | CHUNK_CHUNKSET) {
        return Err("unknown top-level chunk type");
    }
    let size = u64::from_le_bytes(remaining[8..16].try_into().unwrap());
    let body_start = i + 16;
    let Some(body_end) = (body_start as u64)
        .checked_add(size)
        .filter(|&e| e <= data.len() as u64)
        .map(|e| e as usize)
    else {
        return Err("chunk overruns the file");
    };
    let pad = ((8 - (size % 8)) % 8) as usize;
    let Some(next) = body_end.checked_add(pad).filter(|&next| next <= data.len()) else {
        return Err("chunk padding overruns the file");
    };
    Ok((tag, body_end, next))
}

/// Walks the original tracev3 framing and structurally validates every catalog
/// body without parsing message data. Returns the number of catalog chunks.
///
/// Complete framing and recognized top-level types are prerequisites for
/// using any catalog, so truncation or format drift cannot hide uninventoried
/// processes. Chunkset bodies contain message data that Trace does not use;
/// they are deliberately kept outside the parser boundary so their declared
/// decompressed sizes cannot allocate memory or retain parsed firehose data.
/// The caller compares this count with the catalogs that parse successfully.
fn validate_tracev3(data: &[u8]) -> Result<u64, &'static str> {
    let mut catalogs = 0u64;
    let mut i = 0usize;
    while i < data.len() {
        let (tag, body_end, next) = tracev3_chunk_at(data, i)?;
        if tag == CHUNK_CATALOG {
            validate_catalog_body(&data[i + 16..body_end])?;
            catalogs += 1;
        }
        i = next;
    }
    Ok(catalogs)
}

/// A zero-copy source view that emits only catalog frames. The upstream crate
/// exposes its catalog parser only through the full-log API, so filtering at
/// the Read boundary prevents that API from ever seeing (and decompressing)
/// CHUNK_CHUNKSET message data. The full source is validated first.
struct CatalogOnlyReader<'a> {
    data: &'a [u8],
    scan_offset: usize,
    emit_offset: usize,
    emit_end: usize,
}

impl<'a> CatalogOnlyReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            scan_offset: 0,
            emit_offset: 0,
            emit_end: 0,
        }
    }

    fn select_next_catalog(&mut self) -> bool {
        while self.scan_offset < self.data.len() {
            let start = self.scan_offset;
            let (tag, _, next) =
                tracev3_chunk_at(self.data, start).expect("tracev3 framing was already validated");
            self.scan_offset = next;
            if tag == CHUNK_CATALOG {
                self.emit_offset = start;
                self.emit_end = next;
                return true;
            }
        }
        false
    }
}

impl Read for CatalogOnlyReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut written = 0usize;
        while written < out.len() {
            if self.emit_offset == self.emit_end && !self.select_next_catalog() {
                break;
            }
            let available = self.emit_end - self.emit_offset;
            let copy = available.min(out.len() - written);
            out[written..written + copy]
                .copy_from_slice(&self.data[self.emit_offset..self.emit_offset + copy]);
            self.emit_offset += copy;
            written += copy;
        }
        Ok(written)
    }
}

#[derive(Default)]
struct ProcStat {
    pids: BTreeSet<u32>,
    catalog_appearances: u64,
    dropped_pid_samples: u64,
}

#[derive(Default)]
pub struct Aggregator {
    /// main binary UUID (32 hex chars) -> observations across all tracev3.
    procs: BTreeMap<String, ProcStat>,
    /// binary UUID -> full path, from uuidtext footers.
    paths: BTreeMap<String, String>,
    retained_pids: usize,
    retained_path_bytes: usize,
    pub(crate) tracev3_files: u64,
    pub(crate) tracev3_failures: u64,
    /// Files that parsed but where the upstream parser silently dropped a
    /// catalog, collapsed duplicate process keys, or produced an invalid
    /// process UUID. Surviving processes are still ingested, but the file was
    /// not fully inventoried.
    pub(crate) tracev3_incomplete: u64,
    pub(crate) uuidtext_files: u64,
    pub(crate) uuidtext_failures: u64,
    pub(crate) uuidtext_conflicts: u64,
    catalogs: u64,
    /// A process UUID, UUID-to-path mapping, or path byte budget was exhausted.
    /// Unlike PID evidence sampling, this means a matchable identity was lost.
    pub(crate) cap_hit: bool,
    /// PID observations dropped after their bounded evidence sample filled.
    /// The UUID/path identity remains retained and fully matchable.
    pub(crate) pid_retention_cap_hit: bool,
    dropped_pid_samples: u64,
    /// Files our own size cap cut short; parsing a partial file would
    /// silently under-report, so they are skipped and surfaced instead.
    /// Aggregate retained for the engine's shared unified-log limit message;
    /// the split counters preserve which detection/support surface was cut.
    pub truncated_files: u64,
    pub(crate) truncated_tracev3_files: u64,
    pub(crate) truncated_uuidtext_files: u64,
}

fn image_path(ut: &UUIDText) -> Result<Option<String>, &'static str> {
    // The footer holds the entry strings followed by the binary's path;
    // the path starts after the summed entry sizes (the same layout the
    // upstream parser reads for its LogData.process field).
    let offset = ut
        .entry_descriptors
        .iter()
        .try_fold(0u64, |sum, entry| {
            sum.checked_add(u64::from(entry.entry_size))
        })
        .ok_or("uuidtext descriptor sizes overflow")?;
    let offset = usize::try_from(offset).map_err(|_| "uuidtext path offset is too large")?;
    let footer = ut
        .footer_data
        .get(offset..)
        .ok_or("uuidtext path offset exceeds the footer")?;
    let end = footer
        .iter()
        .take(MAX_PATH_BYTES + 1)
        .position(|&b| b == 0)
        .ok_or("uuidtext path is not terminated within the path budget")?;
    let path =
        std::str::from_utf8(&footer[..end]).map_err(|_| "uuidtext path is not valid UTF-8")?;
    // A .dext DriverExtension bundle records its path with a trailing slash
    // (/System/Library/DriverExtensions/AppleCentauriControl.dext/); accept it
    // by dropping the single trailing separator so it reads as a normal path.
    let path = path.strip_suffix('/').unwrap_or(path);
    // Firmware coprocessors (AOP, DCP, AP, MTP, Centauri, ...) log through
    // unified logging under a short identity string ("AOP2", "DCP") instead of
    // a filesystem path. That is not a parse failure - the file is well formed
    // - there is simply no binary path to check against file:path indicators,
    // so it resolves to nothing. Non-canonical spellings (bare names,
    // dot-segment escapes) are treated the same way: never resolved, so they
    // can neither lexically match nor escape a directory, but not counted as
    // failures that would make every real iOS capture inconclusive. A whole
    // inventory that resolves nothing still degrades via the resolved==0 path.
    // The same canonical-path predicate the IOC matcher gates on, so an
    // observed binary path is judged safe to compare in exactly one place.
    if !crate::ioc::is_canonical_observed_path(path) {
        return Ok(None);
    }
    Ok(Some(path.to_string()))
}

fn valid_catalog_uuid(uuid: &str) -> bool {
    uuid.len() == 32
        && uuid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}

impl Aggregator {
    pub(crate) fn record_truncated_tracev3(&mut self) {
        self.truncated_tracev3_files += 1;
        self.truncated_files += 1;
    }

    pub(crate) fn record_truncated_uuidtext(&mut self) {
        self.truncated_uuidtext_files += 1;
        self.truncated_files += 1;
    }

    pub fn consume_tracev3(&mut self, source: &str, data: &[u8]) {
        self.tracev3_files += 1;
        let catalog_chunks = match validate_tracev3(data) {
            Ok(n) => n,
            Err(_) => {
                self.tracev3_failures += 1;
                return;
            }
        };
        // A real tracev3 member carries at least one catalog. Track this per
        // file: an empty member must still degrade a healthy aggregate that
        // also contains process-bearing files.
        let Ok(log) = parse_log(CatalogOnlyReader::new(data), source) else {
            self.tracev3_failures += 1;
            return;
        };
        let mut incomplete =
            catalog_chunks == 0 || (log.catalog_data.len() as u64) != catalog_chunks;
        for cat in &log.catalog_data {
            self.catalogs += 1;
            if usize::from(cat.catalog.number_process_information_entries)
                != cat.catalog.catalog_process_info_entries.len()
                || usize::from(cat.catalog.number_sub_chunks) != cat.catalog.catalog_subchunks.len()
            {
                incomplete = true;
            }
            for entry in cat.catalog.catalog_process_info_entries.values() {
                if entry.main_uuid == ZERO_UUID {
                    continue;
                }
                if !valid_catalog_uuid(&entry.main_uuid) {
                    incomplete = true;
                    continue;
                }
                if !self.procs.contains_key(&entry.main_uuid)
                    && self.procs.len() >= MAX_TRACKED_UUIDS
                {
                    self.cap_hit = true;
                    continue;
                }
                let stat = self.procs.entry(entry.main_uuid.clone()).or_default();
                stat.catalog_appearances += 1;
                if stat.pids.contains(&entry.pid) {
                    continue;
                }
                if stat.pids.len() < MAX_PIDS_PER_PROCESS
                    && self.retained_pids < MAX_TOTAL_TRACKED_PIDS
                {
                    stat.pids.insert(entry.pid);
                    self.retained_pids += 1;
                } else {
                    stat.dropped_pid_samples = stat.dropped_pid_samples.saturating_add(1);
                    self.dropped_pid_samples = self.dropped_pid_samples.saturating_add(1);
                    self.pid_retention_cap_hit = true;
                }
            }
        }
        if incomplete {
            self.tracev3_incomplete += 1;
        }
    }

    pub fn consume_uuidtext(&mut self, uuid: String, data: &[u8]) {
        self.uuidtext_files += 1;
        let Ok((_, ut)) = UUIDText::parse_uuidtext(data) else {
            self.uuidtext_failures += 1;
            return;
        };
        if (ut.major_version, ut.minor_version) != (UUIDTEXT_MAJOR_VERSION, UUIDTEXT_MINOR_VERSION)
        {
            self.uuidtext_failures += 1;
            return;
        }
        let path = match image_path(&ut) {
            Ok(Some(path)) => path,
            Ok(None) => return,
            Err(_) => {
                self.uuidtext_failures += 1;
                return;
            }
        };
        if let Some(existing) = self.paths.get(&uuid) {
            if existing != &path {
                self.uuidtext_conflicts += 1;
                // Reuse the existing engine-visible degradation counter so a
                // conflicting mapping cannot leave the verdict clear.
                self.uuidtext_failures += 1;
            }
            return;
        }
        if self.paths.len() >= MAX_TRACKED_UUIDS {
            self.cap_hit = true;
            return;
        }
        let Some(retained_path_bytes) = self.retained_path_bytes.checked_add(path.len()) else {
            self.cap_hit = true;
            return;
        };
        if retained_path_bytes > MAX_TOTAL_PATH_BYTES {
            self.cap_hit = true;
            return;
        }
        self.retained_path_bytes = retained_path_bytes;
        self.paths.insert(uuid, path);
    }

    /// True if unified-log *log data* was seen. Only tracev3 files carry
    /// the process inventory; uuidtext files are support data (UUID to
    /// binary-path mappings) and alone are not a detection surface - an
    /// archive with uuidtext but no tracev3 has nothing to check, and must
    /// not count this surface as examined.
    pub fn saw_content(&self) -> bool {
        self.tracev3_files > 0 || self.truncated_tracev3_files > 0
    }

    pub fn finalize(self, db: &IocDb, findings: &mut Findings) -> Option<ArtifactSummary> {
        if !self.saw_content() {
            return None;
        }
        let mut resolved = 0usize;
        for (uuid, stat) in &self.procs {
            let Some(path) = self.paths.get(uuid) else {
                // Binary no longer on device (rotated uuidtext); nothing to
                // match against, counted below as unresolved.
                continue;
            };
            resolved += 1;
            let pid_sample: Vec<&u32> = stat.pids.iter().take(16).collect();
            let evidence = json!({
                "process_path": path,
                "binary_uuid": uuid,
                // Retained sample count kept under the historical key for
                // report compatibility; the explicit name carries semantics.
                "pid_count": stat.pids.len(),
                "retained_pid_count": stat.pids.len(),
                "pids_sample": pid_sample,
                "pid_history_truncated": stat.dropped_pid_samples > 0,
                "pid_count_is_lower_bound": stat.dropped_pid_samples > 0,
                "pid_observations_dropped": stat.dropped_pid_samples,
                "catalog_appearances": stat.catalog_appearances,
            });
            for ind in db.match_process(path) {
                findings.push(Finding::ioc_match(
                    "system_logs.logarchive",
                    format!(
                        "Process \u{2018}{}\u{2019} wrote unified log entries - its observed name or path matches a published {} indicator",
                        basename(path),
                        ind.campaign
                    ),
                    evidence.clone(),
                    ind,
                ));
            }
            if let Some(f) = path_flag_finding(
                "system_logs.logarchive",
                path,
                "A process wrote unified log entries from",
                &evidence,
            ) {
                findings.push(f);
            }
        }

        let details = json!({
            "tracev3_files": self.tracev3_files,
            "tracev3_parse_failures": self.tracev3_failures,
            "tracev3_incomplete": self.tracev3_incomplete,
            "tracev3_truncated": self.truncated_tracev3_files,
            "uuidtext_files": self.uuidtext_files,
            "uuidtext_parse_failures": self.uuidtext_failures,
            "uuidtext_conflicts": self.uuidtext_conflicts,
            "uuidtext_truncated": self.truncated_uuidtext_files,
            "catalogs": self.catalogs,
            "processes_seen": self.procs.len(),
            "processes_resolved_to_path": resolved,
            "processes_unresolved": self.procs.len().saturating_sub(resolved),
            "retained_pids": self.retained_pids,
            "pid_retention_cap_hit": self.pid_retention_cap_hit,
            "pid_observations_dropped": self.dropped_pid_samples,
            "retained_path_bytes": self.retained_path_bytes,
            "identity_cap_hit": self.cap_hit,
            // Legacy alias retained for report consumers.
            "cap_hit": self.cap_hit,
        });
        // Anything less than a fully readable surface downgrades the
        // status, which the engine turns into a scan limit and the
        // assurance block reports as partial: parse failures (whole or
        // partial), truncated files, a capped UUID/path inventory, an
        // inventory with any process unresolved to a binary path (that process
        // could not be matched), or tracev3 that parsed to an empty inventory
        // (real tracev3 always carries catalog processes).
        let degraded = self.tracev3_failures > 0
            || self.tracev3_incomplete > 0
            || self.uuidtext_failures > 0
            || self.truncated_files > 0
            || self.truncated_tracev3_files > 0
            || self.truncated_uuidtext_files > 0
            || self.cap_hit
            || self.procs.is_empty()
            || resolved < self.procs.len();
        Some(if degraded {
            ArtifactSummary::problem(
                "system_logs.logarchive",
                "unified_log",
                "parsed_partial",
                details,
            )
        } else {
            ArtifactSummary::parsed("system_logs.logarchive", "unified_log", details)
        })
    }
}

#[cfg(test)]
fn test_catalog_chunk(entries: &[(u16, u64, u32, u32)]) -> Vec<u8> {
    let process_region_size = entries
        .len()
        .checked_mul(48)
        .and_then(|size| size.checked_add(16))
        .and_then(|size| u16::try_from(size).ok())
        .expect("test catalog process region must fit its u16 offset");
    let mut body = Vec::new();
    body.extend_from_slice(&16u16.to_le_bytes());
    body.extend_from_slice(&16u16.to_le_bytes());
    body.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    body.extend_from_slice(&process_region_size.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&[0u8; 6]);
    body.extend_from_slice(&0u64.to_le_bytes());
    body.extend_from_slice(&[0xAA; 16]);
    for (main_uuid_index, first_proc_id, second_proc_id, pid) in entries {
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&main_uuid_index.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&first_proc_id.to_le_bytes());
        body.extend_from_slice(&second_proc_id.to_le_bytes());
        body.extend_from_slice(&pid.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
    }

    let mut out = Vec::new();
    out.extend_from_slice(&CHUNK_CATALOG.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(&body);
    out.extend(std::iter::repeat_n(0u8, (8 - body.len() % 8) % 8));
    out
}

#[cfg(test)]
pub(crate) fn test_pid_retention_cap_tracev3() -> Vec<u8> {
    let entries: Vec<_> = (0..=MAX_PIDS_PER_PROCESS)
        .map(|pid| (0, pid as u64, 0, pid as u32))
        .collect();
    let mut tracev3 = Vec::new();
    for entries in entries.chunks(1_024) {
        tracev3.extend_from_slice(&test_catalog_chunk(entries));
    }
    tracev3
}

#[cfg(test)]
pub(crate) fn test_uuidtext(path: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0x66778899u32.to_le_bytes());
    out.extend_from_slice(&UUIDTEXT_MAJOR_VERSION.to_le_bytes());
    out.extend_from_slice(&UUIDTEXT_MINOR_VERSION.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(path.as_bytes());
    out.push(0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Severity;
    use macos_unifiedlogs::uuidtext::UUIDTextEntry;

    fn seeded_db() -> IocDb {
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"malware","name":"Pegasus"},{"type":"indicator","pattern":"[process:name='bh']"}]}"#,
        )
        .unwrap();
        db
    }

    fn agg_with(procs: &[(&str, u32)], paths: &[(&str, &str)]) -> Aggregator {
        let mut a = Aggregator {
            tracev3_files: 1,
            ..Default::default()
        };
        for (uuid, pid) in procs {
            let stat = a.procs.entry(uuid.to_string()).or_default();
            stat.pids.insert(*pid);
            stat.catalog_appearances += 1;
        }
        for (uuid, path) in paths {
            a.paths.insert(uuid.to_string(), path.to_string());
        }
        a
    }

    fn uuidtext_bytes_with_version(path: &[u8], major: u32, minor: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x66778899u32.to_le_bytes());
        out.extend_from_slice(&major.to_le_bytes());
        out.extend_from_slice(&minor.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(path);
        out.push(0);
        out
    }

    fn uuidtext_bytes(path: &[u8]) -> Vec<u8> {
        uuidtext_bytes_with_version(path, UUIDTEXT_MAJOR_VERSION, UUIDTEXT_MINOR_VERSION)
    }

    #[test]
    fn no_content_yields_no_summary() {
        let mut findings = Findings::new();
        assert!(Aggregator::default()
            .finalize(&seeded_db(), &mut findings)
            .is_none());
        assert!(findings.is_empty());
    }

    #[test]
    fn empty_tracev3_inventory_is_partial() {
        let mut agg = Aggregator::default();
        agg.consume_tracev3("Persist/empty.tracev3", &[]);
        assert_eq!(agg.tracev3_files, 1);
        assert_eq!(agg.tracev3_failures, 0);
        let mut findings = Findings::new();
        let summary = agg.finalize(&seeded_db(), &mut findings).unwrap();
        assert_eq!(summary.details["processes_seen"], 0);
        assert_eq!(summary.status, "parsed_partial");
    }

    #[test]
    fn empty_tracev3_degrades_an_otherwise_healthy_aggregate() {
        let mut agg = agg_with(&[("AAAA", 1)], &[("AAAA", "/usr/libexec/a")]);
        agg.consume_tracev3("Persist/empty.tracev3", &[]);
        assert_eq!(agg.tracev3_incomplete, 1);
        let mut findings = Findings::new();
        let summary = agg.finalize(&seeded_db(), &mut findings).unwrap();
        assert_eq!(summary.details["processes_resolved_to_path"], 1);
        assert_eq!(summary.status, "parsed_partial");
    }

    #[test]
    fn resolved_process_matches_ioc_and_staging_heuristic() {
        let agg = agg_with(
            &[("AAAA", 2143), ("BBBB", 155)],
            &[
                (
                    "AAAA",
                    "/private/var/db/com.apple.xpc.roleaccountd.staging/bh",
                ),
                ("BBBB", "/usr/libexec/nfcd"),
            ],
        );
        let mut findings = Findings::new();
        let summary = agg.finalize(&seeded_db(), &mut findings).unwrap();
        assert_eq!(summary.kind, "unified_log");
        assert_eq!(summary.status, "parsed");
        assert_eq!(summary.details["processes_resolved_to_path"], 2);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.severity == Severity::Match)
                .count(),
            1
        );
        assert!(findings.iter().any(|f| f.severity == Severity::Suspicious));
        assert!(!findings.iter().any(|f| f.summary.contains("nfcd")));
    }

    #[test]
    fn directory_path_match_summary_does_not_claim_a_name_match() {
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"malware","name":"Pegasus"},{"type":"indicator","pattern":"[file:path='/private/var/db/com.apple.xpc.roleaccountd.staging/']"}]}"#,
        )
        .unwrap();
        let agg = agg_with(
            &[("AAAA", 2143)],
            &[(
                "AAAA",
                "/private/var/db/com.apple.xpc.roleaccountd.staging/bh",
            )],
        );
        let mut findings = Findings::new();
        agg.finalize(&db, &mut findings).unwrap();

        let matched = findings
            .iter()
            .find(|finding| finding.severity == Severity::Match)
            .unwrap();
        assert!(matched.summary.contains("observed name or path matches"));
        assert!(!matched.summary.contains("its name matches"));
    }

    #[test]
    fn unresolved_uuid_is_counted_not_matched() {
        let agg = agg_with(&[("CCCC", 42)], &[]);
        let mut findings = Findings::new();
        let summary = agg.finalize(&seeded_db(), &mut findings).unwrap();
        assert_eq!(summary.details["processes_seen"], 1);
        assert_eq!(summary.details["processes_resolved_to_path"], 0);
        assert!(findings.is_empty());
        // an inventory in which nothing resolved was never effectively
        // checked; the status must say so
        assert_eq!(summary.status, "parsed_partial");
    }

    #[test]
    fn partially_unresolved_inventory_is_partial() {
        let agg = agg_with(
            &[
                ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 1),
                ("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", 2),
            ],
            &[("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "/usr/libexec/a")],
        );
        let mut findings = Findings::new();
        let summary = agg.finalize(&seeded_db(), &mut findings).unwrap();
        assert_eq!(summary.details["processes_seen"], 2);
        assert_eq!(summary.details["processes_resolved_to_path"], 1);
        assert_eq!(summary.details["processes_unresolved"], 1);
        assert_eq!(summary.status, "parsed_partial");
    }

    #[test]
    fn uuidtext_path_validation_is_checked_and_strict() {
        let overflowing = UUIDText {
            entry_descriptors: vec![
                UUIDTextEntry {
                    entry_size: u32::MAX,
                    ..Default::default()
                },
                UUIDTextEntry {
                    entry_size: 1,
                    ..Default::default()
                },
            ],
            footer_data: b"/bin/x\0".to_vec(),
            ..Default::default()
        };
        assert!(image_path(&overflowing).is_err());

        let invalid_utf8 = UUIDText {
            footer_data: vec![b'/', 0xff, 0],
            ..Default::default()
        };
        assert!(image_path(&invalid_utf8).is_err());

        let unterminated = UUIDText {
            footer_data: vec![b'x'; MAX_PATH_BYTES + 1],
            ..Default::default()
        };
        assert!(image_path(&unterminated).is_err());

        let valid = UUIDText {
            footer_data: b"/usr/libexec/x\0ignored".to_vec(),
            ..Default::default()
        };
        assert_eq!(
            image_path(&valid).unwrap().as_deref(),
            Some("/usr/libexec/x")
        );

        // A real iOS .dext DriverExtension path carries a trailing slash and
        // must still resolve to its canonical form.
        let dext = UUIDText {
            footer_data: b"/System/Library/DriverExtensions/AppleCentauriControl.dext/\0".to_vec(),
            ..Default::default()
        };
        assert_eq!(
            image_path(&dext).unwrap().as_deref(),
            Some("/System/Library/DriverExtensions/AppleCentauriControl.dext")
        );

        // Firmware coprocessor identities, bare names, dot-segment escapes and
        // space-padded strings are well formed but have no filesystem path;
        // they resolve to nothing rather than counting as a parse failure.
        for footer_data in [
            b"AOP2\0".as_slice(),
            b"DCP\0".as_slice(),
            b"bh\0".as_slice(),
            b"/safe/../bh\0".as_slice(),
            b" /usr/libexec/x \0".as_slice(),
        ] {
            let unresolved = UUIDText {
                footer_data: footer_data.to_vec(),
                ..Default::default()
            };
            assert_eq!(image_path(&unresolved), Ok(None));
        }
    }

    #[test]
    fn noncanonical_uuidtext_paths_do_not_false_match_or_resolve() {
        const UUID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        // Bare names, dot-segment escapes and firmware identities never
        // resolve (so they cannot false-match or lexically escape) but are not
        // failures: a well-formed footer with a non-filesystem identity is the
        // norm on real iOS captures. The process stays unresolved, and an
        // inventory that resolves nothing degrades via the resolved==0 path.
        for path in [
            b"bh".as_slice(),
            b"/safe/../bh".as_slice(),
            b"AOP2".as_slice(),
        ] {
            let mut agg = agg_with(&[(UUID, 2143)], &[]);
            agg.consume_uuidtext(UUID.to_string(), &uuidtext_bytes(path));

            assert!(agg.paths.is_empty());
            assert_eq!(agg.uuidtext_failures, 0);

            let mut findings = Findings::new();
            let summary = agg.finalize(&seeded_db(), &mut findings).unwrap();
            assert_eq!(summary.status, "parsed_partial");
            assert_eq!(summary.details["processes_resolved_to_path"], 0);
            assert_eq!(summary.details["processes_unresolved"], 1);
            assert!(!findings.iter().any(|f| f.severity == Severity::Match));
        }
    }

    #[test]
    fn unsupported_uuidtext_version_does_not_match_or_resolve() {
        const UUID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let mut agg = agg_with(&[(UUID, 2143)], &[]);
        agg.consume_uuidtext(
            UUID.to_string(),
            &uuidtext_bytes_with_version(b"/usr/libexec/bh", 999, 999),
        );

        assert!(agg.paths.is_empty());
        assert_eq!(agg.uuidtext_failures, 1);

        let mut findings = Findings::new();
        let summary = agg.finalize(&seeded_db(), &mut findings).unwrap();
        assert_eq!(summary.status, "parsed_partial");
        assert_eq!(summary.details["uuidtext_parse_failures"], 1);
        assert_eq!(summary.details["processes_resolved_to_path"], 0);
        assert_eq!(summary.details["processes_unresolved"], 1);
        assert!(!findings.iter().any(|f| f.severity == Severity::Match));
    }

    #[test]
    fn conflicting_uuidtext_mapping_is_a_failure() {
        let mut agg = Aggregator::default();
        let uuid = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
        agg.consume_uuidtext(uuid.clone(), &uuidtext_bytes(b"/usr/libexec/a"));
        agg.consume_uuidtext(uuid.clone(), &uuidtext_bytes(b"/usr/libexec/b"));
        assert_eq!(
            agg.paths.get(&uuid).map(String::as_str),
            Some("/usr/libexec/a")
        );
        assert_eq!(agg.uuidtext_conflicts, 1);
        assert_eq!(agg.uuidtext_failures, 1);
    }

    #[test]
    fn aggregate_path_budget_sets_cap_hit() {
        let mut agg = Aggregator {
            retained_path_bytes: MAX_TOTAL_PATH_BYTES,
            ..Default::default()
        };
        agg.consume_uuidtext(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            &uuidtext_bytes(b"/usr/libexec/a"),
        );
        assert!(agg.cap_hit);
        assert!(agg.paths.is_empty());
    }

    #[test]
    fn truncated_tracev3_counts_as_seen_content() {
        let mut agg = Aggregator::default();
        agg.record_truncated_tracev3();
        assert!(agg.saw_content());
        assert_eq!(agg.truncated_files, 1);
        let mut findings = Findings::new();
        let summary = agg.finalize(&seeded_db(), &mut findings).unwrap();
        assert_eq!(summary.status, "parsed_partial");
    }

    #[test]
    fn truncated_uuidtext_alone_is_not_a_detection_surface() {
        let mut agg = Aggregator::default();
        agg.record_truncated_uuidtext();
        assert!(!agg.saw_content());
        assert_eq!(agg.truncated_files, 1);
    }

    /// Minimal chunk: 16-byte preamble (tag, sub_tag, data_size) + body,
    /// padded to 8 bytes like the real container format.
    fn chunk(tag: u32, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(body.len() as u64).to_le_bytes());
        out.extend_from_slice(body);
        out.extend(std::iter::repeat_n(0u8, (8 - body.len() % 8) % 8));
        out
    }

    fn catalog_chunk(entries: &[(u16, u64, u32, u32)]) -> Vec<u8> {
        let process_region_size = entries
            .len()
            .checked_mul(48)
            .and_then(|size| size.checked_add(16))
            .and_then(|size| u16::try_from(size).ok())
            .expect("test catalog process region must fit its u16 offset");
        let mut body = Vec::new();
        body.extend_from_slice(&16u16.to_le_bytes()); // one catalog UUID
        body.extend_from_slice(&16u16.to_le_bytes()); // no subsystem strings
        body.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        body.extend_from_slice(&process_region_size.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // no subchunks
        body.extend_from_slice(&[0u8; 6]);
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&[0xAA; 16]);
        for (main_uuid_index, first_proc_id, second_proc_id, pid) in entries {
            body.extend_from_slice(&0u16.to_le_bytes()); // index
            body.extend_from_slice(&0u16.to_le_bytes()); // unknown
            body.extend_from_slice(&main_uuid_index.to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes()); // dsc UUID index
            body.extend_from_slice(&first_proc_id.to_le_bytes());
            body.extend_from_slice(&second_proc_id.to_le_bytes());
            body.extend_from_slice(&pid.to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes()); // euid
            body.extend_from_slice(&0u32.to_le_bytes()); // unknown
            body.extend_from_slice(&0u32.to_le_bytes()); // UUID entries
            body.extend_from_slice(&0u32.to_le_bytes()); // unknown
            body.extend_from_slice(&0u32.to_le_bytes()); // subsystems
            body.extend_from_slice(&0u32.to_le_bytes()); // unknown
        }
        chunk(CHUNK_CATALOG, &body)
    }

    fn catalog_chunk_with_empty_subchunk() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&16u16.to_le_bytes()); // one catalog UUID
        body.extend_from_slice(&16u16.to_le_bytes()); // no subsystem strings
        body.extend_from_slice(&0u16.to_le_bytes()); // no process entries
        body.extend_from_slice(&16u16.to_le_bytes()); // subchunks follow the UUID
        body.extend_from_slice(&1u16.to_le_bytes()); // one subchunk
        body.extend_from_slice(&[0u8; 6]);
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&[0xAA; 16]);
        body.extend_from_slice(&0u64.to_le_bytes()); // start
        body.extend_from_slice(&0u64.to_le_bytes()); // end
        body.extend_from_slice(&0u32.to_le_bytes()); // uncompressed size
        body.extend_from_slice(&256u32.to_le_bytes()); // LZ4
        body.extend_from_slice(&0u32.to_le_bytes()); // no indexes
        body.extend_from_slice(&0u32.to_le_bytes()); // no string offsets
        chunk(CHUNK_CATALOG, &body)
    }

    #[test]
    fn strict_framing_rejects_tails_missing_padding_and_unknown_chunks() {
        let mut short_tail = chunk(CHUNK_HEADER, &[]);
        short_tail.push(0xAA);
        assert!(validate_tracev3(&short_tail).is_err());

        let mut missing_padding = chunk(CHUNK_HEADER, &[0xAA]);
        missing_padding.pop();
        assert!(validate_tracev3(&missing_padding).is_err());

        assert!(validate_tracev3(&chunk(0xDEAD, &[])).is_err());
        assert_eq!(validate_tracev3(&chunk(CHUNK_HEADER, &[])), Ok(0));
    }

    #[test]
    fn catalog_validation_rejects_malformed_offsets_before_parsing() {
        let valid = catalog_chunk(&[(0, 1, 2, 42)]);
        let cases = [
            (16u16, 15u16, 64u16), // process before subsystem: upstream u16 underflow
            (16, 16, 15),          // subchunks before process inventory
            (17, 17, 65),          // partial UUID in the UUID region
            (16, 16, u16::MAX),    // offset outside the declared body
        ];
        for (subsystems, processes, subchunks) in cases {
            let mut malformed = valid.clone();
            malformed[16..18].copy_from_slice(&subsystems.to_le_bytes());
            malformed[18..20].copy_from_slice(&processes.to_le_bytes());
            malformed[22..24].copy_from_slice(&subchunks.to_le_bytes());
            assert!(validate_tracev3(&malformed).is_err());

            let mut agg = Aggregator::default();
            agg.consume_tracev3("Persist/malformed-offset.tracev3", &malformed);
            assert_eq!(agg.tracev3_failures, 1);
            assert!(agg.procs.is_empty());
        }
    }

    #[test]
    fn catalog_validation_rejects_underdeclared_or_trailing_body_data() {
        // Keep two complete process entries in the declared process region but
        // claim only one. Upstream otherwise accepts the first entry and then
        // starts parsing subchunks from the second because it ignores the
        // catalog's declared subchunk offset.
        let mut underdeclared = catalog_chunk(&[(0, 1, 2, 42), (0, 3, 4, 43)]);
        underdeclared[20..22].copy_from_slice(&1u16.to_le_bytes());
        assert!(validate_tracev3(&underdeclared).is_err());

        // A fully valid prefix plus non-padding bytes inside the top-level
        // declared body must not be accepted as a complete inventory.
        let mut trailing = catalog_chunk(&[(0, 1, 2, 42)]);
        let old_size = u64::from_le_bytes(trailing[8..16].try_into().unwrap());
        trailing[8..16].copy_from_slice(&(old_size + 8).to_le_bytes());
        trailing.extend_from_slice(&[0xA5; 8]);
        assert!(validate_tracev3(&trailing).is_err());

        for malformed in [&underdeclared, &trailing] {
            let mut agg = Aggregator::default();
            agg.consume_tracev3("Persist/incomplete-body.tracev3", malformed);
            assert_eq!(agg.tracev3_failures, 1);
            assert!(agg.procs.is_empty());
        }
    }

    #[test]
    fn catalog_validation_bounds_nested_counts_and_allows_outer_padding() {
        let valid = catalog_chunk(&[(0, 1, 2, 42)]);

        // number_uuids_entries sits 32 bytes into the process entry. A hostile
        // count must be rejected against the declared process region before
        // upstream's repeated parser sees it.
        let mut hostile_uuid_count = valid.clone();
        let count_offset = 16 + CATALOG_FIXED_BODY_SIZE + 16 + 32;
        hostile_uuid_count[count_offset..count_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(validate_tracev3(&hostile_uuid_count).is_err());

        let mut hostile_subsystem_count = valid.clone();
        let count_offset = 16 + CATALOG_FIXED_BODY_SIZE + 16 + 40;
        hostile_subsystem_count[count_offset..count_offset + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(validate_tracev3(&hostile_subsystem_count).is_err());

        let subchunk = catalog_chunk_with_empty_subchunk();
        assert_eq!(validate_tracev3(&subchunk), Ok(1));
        let mut hostile_index_count = subchunk.clone();
        let count_offset = 16 + CATALOG_FIXED_BODY_SIZE + 16 + 24;
        hostile_index_count[count_offset..count_offset + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(validate_tracev3(&hostile_index_count).is_err());

        let mut hostile_string_count = subchunk;
        let count_offset = 16 + CATALOG_FIXED_BODY_SIZE + 16 + 28;
        hostile_string_count[count_offset..count_offset + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(validate_tracev3(&hostile_string_count).is_err());

        // Insert one legitimate subsystem-string byte. That makes the catalog
        // body non-aligned and requires seven bytes of top-level source
        // padding. The dependency treats those bytes as framing, not body, and
        // does not require a particular padding value.
        let body_size =
            usize::try_from(u64::from_le_bytes(valid[8..16].try_into().unwrap())).unwrap();
        let mut body = valid[16..16 + body_size].to_vec();
        body.insert(CATALOG_FIXED_BODY_SIZE + 16, b'x');
        body[2..4].copy_from_slice(&17u16.to_le_bytes());
        body[6..8].copy_from_slice(&65u16.to_le_bytes());
        let mut padded = chunk(CHUNK_CATALOG, &body);
        *padded.last_mut().unwrap() = 0xA5;
        assert_eq!(validate_tracev3(&padded), Ok(1));

        let mut agg = Aggregator::default();
        agg.consume_tracev3("Persist/padded.tracev3", &padded);
        assert_eq!(agg.tracev3_failures, 0);
        assert_eq!(agg.tracev3_incomplete, 0);
        assert_eq!(agg.procs.len(), 1);
    }

    #[test]
    fn malformed_catalog_entries_mark_file_incomplete() {
        let invalid_uuid_index = catalog_chunk(&[(1, 1, 2, 42)]);
        let mut agg = Aggregator::default();
        agg.consume_tracev3("Persist/invalid.tracev3", &invalid_uuid_index);
        assert_eq!(agg.tracev3_failures, 0);
        assert_eq!(agg.tracev3_incomplete, 1);
        assert!(agg.procs.is_empty());

        let duplicate_process_key = catalog_chunk(&[(0, 1, 2, 42), (0, 1, 2, 43)]);
        let mut agg = Aggregator::default();
        agg.consume_tracev3("Persist/duplicate.tracev3", &duplicate_process_key);
        assert_eq!(agg.tracev3_failures, 0);
        assert_eq!(agg.tracev3_incomplete, 1);
    }

    #[test]
    fn per_process_pid_retention_cap_is_disclosed_without_dropping_identity() {
        const UUID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let entries: Vec<_> = (0..=MAX_PIDS_PER_PROCESS)
            .map(|pid| (0, pid as u64, 0, pid as u32))
            .collect();
        let mut tracev3 = Vec::new();
        for entries in entries.chunks(1_024) {
            tracev3.extend_from_slice(&catalog_chunk(entries));
        }
        let mut agg = Aggregator::default();
        agg.consume_tracev3("Persist/per-process-cap.tracev3", &tracev3);
        assert!(!agg.cap_hit);
        assert!(agg.pid_retention_cap_hit);
        assert_eq!(agg.dropped_pid_samples, 1);
        assert_eq!(agg.procs[UUID].pids.len(), MAX_PIDS_PER_PROCESS);
        assert_eq!(agg.procs[UUID].dropped_pid_samples, 1);

        // The retained UUID/path is still fully matchable. Sampling the PID
        // history changes evidence only and must not degrade the surface.
        agg.paths.insert(UUID.into(), "/usr/libexec/bh".into());
        let mut findings = Findings::new();
        let summary = agg.finalize(&seeded_db(), &mut findings).unwrap();
        assert_eq!(summary.status, "parsed");
        assert_eq!(summary.details["cap_hit"], false);
        assert_eq!(summary.details["pid_retention_cap_hit"], true);
        assert_eq!(summary.details["pid_observations_dropped"], 1);
        let hit = findings
            .iter()
            .find(|finding| finding.severity == Severity::Match)
            .unwrap();
        assert_eq!(hit.evidence["pid_history_truncated"], true);
        assert_eq!(hit.evidence["retained_pid_count"], MAX_PIDS_PER_PROCESS);
        assert_eq!(hit.evidence["pid_count_is_lower_bound"], true);
        assert_eq!(hit.evidence["pid_observations_dropped"], 1);
    }

    #[test]
    fn aggregate_pid_retention_cap_is_disclosed_without_dropping_identity() {
        const TARGET_UUID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        const SINGLETON_UUID: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let mut agg = Aggregator::default();

        // Construct a reachable aggregate state: 63 full per-process samples,
        // one target with one slot left, and one singleton together retain the
        // exact aggregate maximum. The next target PID must be dropped solely
        // because of the aggregate evidence budget, not the per-process cap.
        for index in 1..=63u32 {
            let uuid = format!("{index:032X}");
            let pids = (0..MAX_PIDS_PER_PROCESS as u32).collect();
            let path = format!("/usr/libexec/safe-process-{index}");
            agg.retained_path_bytes += path.len();
            agg.paths.insert(uuid.clone(), path);
            agg.procs.insert(
                uuid,
                ProcStat {
                    pids,
                    catalog_appearances: 1,
                    dropped_pid_samples: 0,
                },
            );
            agg.retained_pids += MAX_PIDS_PER_PROCESS;
        }
        let target_pids = (0..(MAX_PIDS_PER_PROCESS as u32 - 1)).collect();
        let target_path = "/usr/libexec/bh".to_string();
        agg.retained_path_bytes += target_path.len();
        agg.paths.insert(TARGET_UUID.into(), target_path);
        agg.procs.insert(
            TARGET_UUID.into(),
            ProcStat {
                pids: target_pids,
                catalog_appearances: 1,
                dropped_pid_samples: 0,
            },
        );
        agg.retained_pids += MAX_PIDS_PER_PROCESS - 1;
        let singleton_path = "/usr/libexec/singleton".to_string();
        agg.retained_path_bytes += singleton_path.len();
        agg.paths.insert(SINGLETON_UUID.into(), singleton_path);
        agg.procs.insert(
            SINGLETON_UUID.into(),
            ProcStat {
                pids: std::iter::once(7).collect(),
                catalog_appearances: 1,
                dropped_pid_samples: 0,
            },
        );
        agg.retained_pids += 1;
        assert_eq!(agg.retained_pids, MAX_TOTAL_TRACKED_PIDS);
        assert!(agg.procs[TARGET_UUID].pids.len() < MAX_PIDS_PER_PROCESS);

        agg.consume_tracev3(
            "Persist/aggregate-cap.tracev3",
            &catalog_chunk(&[(0, 9_999, 0, 9_999)]),
        );
        assert!(!agg.cap_hit);
        assert!(agg.pid_retention_cap_hit);
        assert_eq!(agg.dropped_pid_samples, 1);
        assert_eq!(agg.procs[TARGET_UUID].dropped_pid_samples, 1);

        let mut findings = Findings::new();
        let summary = agg.finalize(&seeded_db(), &mut findings).unwrap();
        assert_eq!(summary.status, "parsed");
        assert_eq!(summary.details["cap_hit"], false);
        assert_eq!(summary.details["pid_retention_cap_hit"], true);
        assert_eq!(summary.details["pid_observations_dropped"], 1);
        assert_eq!(summary.details["retained_pids"], MAX_TOTAL_TRACKED_PIDS);
        let hit = findings
            .iter()
            .find(|finding| finding.severity == Severity::Match)
            .unwrap();
        assert_eq!(hit.evidence["process_path"], "/usr/libexec/bh");
        assert_eq!(hit.evidence["pid_history_truncated"], true);
        assert_eq!(hit.evidence["retained_pid_count"], MAX_PIDS_PER_PROCESS - 1);
        assert_eq!(hit.evidence["pid_observations_dropped"], 1);
    }

    #[test]
    fn chunkset_payloads_stay_outside_the_catalog_parser_boundary() {
        // The full-log parser would hand this attacker-controlled size to
        // lz4_flex and attempt an enormous allocation. Trace needs only the
        // preceding catalog, so even deliberately invalid message data must
        // never cross that parser boundary.
        let mut body = Vec::new();
        body.extend_from_slice(&825_521_762u32.to_le_bytes()); // "bv41"
        body.extend_from_slice(&u32::MAX.to_le_bytes()); // uncompress_size
        body.extend_from_slice(&8u32.to_le_bytes()); // block_size
        body.extend_from_slice(&[0u8; 8]); // invalid lz4, no footer
        let catalog = catalog_chunk(&[(0, 1, 2, 42)]);
        let mut file = catalog.clone();
        file.extend_from_slice(&chunk(CHUNK_CHUNKSET, &body));

        assert_eq!(validate_tracev3(&file), Ok(1));
        let mut parser_input = Vec::new();
        CatalogOnlyReader::new(&file)
            .read_to_end(&mut parser_input)
            .unwrap();
        assert_eq!(parser_input, catalog, "chunkset bytes reached the parser");
        let mut agg = Aggregator::default();
        agg.consume_tracev3("Persist/0.tracev3", &file);
        assert_eq!(agg.tracev3_failures, 0);
        assert_eq!(agg.tracev3_incomplete, 0);
        assert_eq!(agg.catalogs, 1);
        assert_eq!(agg.procs.len(), 1);
    }

    #[test]
    fn chunksets_without_a_catalog_never_claim_inventory_coverage() {
        let mut body = Vec::new();
        body.extend_from_slice(&825_521_762u32.to_le_bytes()); // "bv41"
        body.extend_from_slice(&u32::MAX.to_le_bytes());
        body.extend_from_slice(&8u32.to_le_bytes());
        body.extend_from_slice(&[0u8; 8]);
        let one = chunk(CHUNK_CHUNKSET, &body);
        let mut file = Vec::new();
        for _ in 0..5 {
            file.extend_from_slice(&one);
        }
        assert_eq!(validate_tracev3(&file), Ok(0));
        let mut agg = Aggregator::default();
        agg.consume_tracev3("Persist/0.tracev3", &file);
        assert_eq!(agg.tracev3_failures, 0);
        assert_eq!(agg.tracev3_incomplete, 1);
        assert!(agg.procs.is_empty());
    }

    #[test]
    fn malformed_catalog_body_is_rejected_before_upstream_parsing() {
        // Malformed catalogs are rejected before they can reach dependency
        // arithmetic or its log-and-continue path.
        let file = chunk(CHUNK_CATALOG, &[0xFFu8; 32]);
        assert!(validate_tracev3(&file).is_err());
        let mut agg = Aggregator::default();
        agg.consume_tracev3("Persist/0.tracev3", &file);
        assert_eq!(agg.tracev3_failures, 1);
        assert_eq!(agg.tracev3_incomplete, 0);
        let mut findings = Findings::new();
        let summary = agg.finalize(&seeded_db(), &mut findings).unwrap();
        assert_eq!(summary.status, "parsed_partial");
    }

    #[test]
    fn chunk_overrunning_the_file_is_rejected() {
        let mut file = chunk(CHUNK_CATALOG, &[0u8; 8]);
        // Forge the size field to point past the end of the file.
        file[8..16].copy_from_slice(&(1u64 << 40).to_le_bytes());
        assert!(validate_tracev3(&file).is_err());
    }

    #[test]
    fn garbage_bytes_count_as_failures_not_panics() {
        let mut agg = Aggregator::default();
        agg.consume_tracev3("Persist/0.tracev3", &[0xAB; 512]);
        agg.consume_uuidtext("DEAD".into(), &[0xCD; 64]);
        assert_eq!(agg.tracev3_failures, 1);
        assert_eq!(agg.uuidtext_failures, 1);
        // wholesale failure downgrades the artifact status
        let mut findings = Findings::new();
        let summary = agg.finalize(&seeded_db(), &mut findings).unwrap();
        assert_eq!(summary.status, "parsed_partial");
    }
}
