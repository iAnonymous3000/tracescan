//! Unified log (tracev3) analysis: catalog-level process inventory.
//!
//! Every tracev3 chunk carries a catalog listing the processes that emitted
//! the entries in it (pid plus the UUID of the main binary), and each
//! uuidtext file's footer stores that binary's full path. Joining the two
//! yields every process that wrote a log entry during the archive window
//! (typically days of device history) without rendering a single log
//! message - so the 155 MB dsc shared-string cache is never loaded and peak
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
use std::io::Cursor;

/// A real logarchive holds a few hundred binaries; these caps only matter
/// for hostile input, and hitting one surfaces in the artifact details.
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
/// "bv41": lz4-compressed chunkset block.
const BV41_COMPRESSED: u32 = 825_521_762;
/// Real chunkset blocks decompress to at most a few megabytes; the sizes
/// below are far above anything a genuine logarchive produces, so hitting
/// one means hostile input, surfaced as a parse failure (fail-closed).
const MAX_CHUNKSET_UNCOMPRESS: u64 = 64 * 1024 * 1024;
const MAX_FILE_UNCOMPRESS: u64 = 256 * 1024 * 1024;

/// Walks the tracev3 chunk framing without parsing chunk bodies. Returns the
/// number of catalog chunks in the file.
///
/// Three jobs, all prerequisites for handing the bytes to the upstream
/// parser. First, require complete framing and only chunk types the parser
/// understands, so its log-and-continue behavior cannot hide truncation or
/// format drift. Second, bound declared decompression sizes: upstream passes each
/// chunkset's attacker-controlled u32 uncompress_size straight to
/// lz4_flex::decompress, which eagerly allocates it - up to ~4.3 GB, a
/// capacity-overflow panic on wasm32 that would abort the whole scan.
/// Third, the caller compares the returned catalog count against what the
/// upstream parser actually yielded: upstream silently drops catalogs whose
/// internal structure fails to parse (log-and-continue), and a dropped
/// catalog is an uninventoried set of processes that must not read as a
/// fully checked surface.
fn validate_tracev3(data: &[u8]) -> Result<u64, &'static str> {
    let mut catalogs = 0u64;
    let mut total_uncompress = 0u64;
    let mut i = 0usize;
    while i < data.len() {
        if data.len() - i < 16 {
            return Err("truncated chunk preamble");
        }
        let tag = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        if !matches!(tag, CHUNK_HEADER | CHUNK_CATALOG | CHUNK_CHUNKSET) {
            return Err("unknown top-level chunk type");
        }
        let size = u64::from_le_bytes(data[i + 8..i + 16].try_into().unwrap());
        let body_start = i + 16;
        let Some(body_end) = (body_start as u64)
            .checked_add(size)
            .filter(|&e| e <= data.len() as u64)
            .map(|e| e as usize)
        else {
            return Err("chunk overruns the file");
        };
        if tag == CHUNK_CATALOG {
            catalogs += 1;
        }
        if tag == CHUNK_CHUNKSET {
            let body = &data[body_start..body_end];
            if body.len() >= 8 {
                let sig = u32::from_le_bytes(body[0..4].try_into().unwrap());
                let uncompress = u32::from_le_bytes(body[4..8].try_into().unwrap()) as u64;
                if sig == BV41_COMPRESSED {
                    if uncompress > MAX_CHUNKSET_UNCOMPRESS {
                        return Err("chunkset declares an implausible decompressed size");
                    }
                    total_uncompress += uncompress;
                    if total_uncompress > MAX_FILE_UNCOMPRESS {
                        return Err("file declares an implausible total decompressed size");
                    }
                }
            }
        }
        let pad = ((8 - (size % 8)) % 8) as usize;
        if data.len() - body_end < pad {
            return Err("chunk padding overruns the file");
        }
        i = body_end + pad;
    }
    Ok(catalogs)
}

#[derive(Default)]
struct ProcStat {
    pids: BTreeSet<u32>,
    catalog_appearances: u64,
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
    pub(crate) cap_hit: bool,
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
        let Ok(log) = parse_log(Cursor::new(data), source) else {
            self.tracev3_failures += 1;
            return;
        };
        // A real tracev3 member carries at least one catalog. Track this per
        // file: an empty member must still degrade a healthy aggregate that
        // also contains process-bearing files.
        let mut incomplete =
            catalog_chunks == 0 || (log.catalog_data.len() as u64) != catalog_chunks;
        for cat in &log.catalog_data {
            self.catalogs += 1;
            if usize::from(cat.catalog.number_process_information_entries)
                != cat.catalog.catalog_process_info_entries.len()
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
                    self.cap_hit = true;
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
                "pid_count": stat.pids.len(),
                "pids_sample": pid_sample,
                "catalog_appearances": stat.catalog_appearances,
            });
            for ind in db.match_process(path) {
                findings.push(Finding::ioc_match(
                    "system_logs.logarchive",
                    format!(
                        "Process \u{2018}{}\u{2019} wrote unified log entries - its name matches a published {} indicator",
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
            "retained_path_bytes": self.retained_path_bytes,
            "cap_hit": self.cap_hit,
        });
        // Anything less than a fully readable surface downgrades the
        // status, which the engine turns into a scan limit and the
        // assurance block reports as partial: parse failures (whole or
        // partial), truncated files, a capped inventory, an inventory in
        // with any process unresolved to a binary path (that process could
        // not be matched), or tracev3 that parsed to an empty inventory
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
        let mut body = Vec::new();
        body.extend_from_slice(&16u16.to_le_bytes()); // one catalog UUID
        body.extend_from_slice(&16u16.to_le_bytes()); // no subsystem strings
        body.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
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
    fn pid_retention_caps_are_disclosed() {
        let mut agg = Aggregator {
            retained_pids: MAX_TOTAL_TRACKED_PIDS,
            ..Default::default()
        };
        agg.consume_tracev3(
            "Persist/global-cap.tracev3",
            &catalog_chunk(&[(0, 1, 2, 42)]),
        );
        assert!(agg.cap_hit);

        let entries: Vec<_> = (0..=MAX_PIDS_PER_PROCESS)
            .map(|pid| (0, pid as u64, 0, pid as u32))
            .collect();
        let mut agg = Aggregator::default();
        agg.consume_tracev3("Persist/per-process-cap.tracev3", &catalog_chunk(&entries));
        assert!(agg.cap_hit);
        assert_eq!(
            agg.procs["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"].pids.len(),
            MAX_PIDS_PER_PROCESS
        );
    }

    #[test]
    fn hostile_chunkset_decompress_size_is_a_parse_failure_not_a_panic() {
        // Upstream hands the declared u32 uncompress_size straight to
        // lz4_flex, which eagerly allocates it: u32::MAX would be a
        // capacity-overflow panic on wasm32, aborting the whole scan.
        let mut body = Vec::new();
        body.extend_from_slice(&BV41_COMPRESSED.to_le_bytes());
        body.extend_from_slice(&u32::MAX.to_le_bytes()); // uncompress_size
        body.extend_from_slice(&8u32.to_le_bytes()); // block_size
        body.extend_from_slice(&[0u8; 8]);
        let file = chunk(CHUNK_CHUNKSET, &body);
        assert!(validate_tracev3(&file).is_err());
        let mut agg = Aggregator::default();
        agg.consume_tracev3("Persist/0.tracev3", &file);
        assert_eq!(agg.tracev3_failures, 1, "rejected before upstream parse");
    }

    #[test]
    fn many_large_chunksets_exceed_the_file_budget() {
        let mut body = Vec::new();
        body.extend_from_slice(&BV41_COMPRESSED.to_le_bytes());
        body.extend_from_slice(&(MAX_CHUNKSET_UNCOMPRESS as u32).to_le_bytes());
        body.extend_from_slice(&8u32.to_le_bytes());
        body.extend_from_slice(&[0u8; 8]);
        let one = chunk(CHUNK_CHUNKSET, &body);
        let mut file = Vec::new();
        for _ in 0..5 {
            file.extend_from_slice(&one); // 5 * 64 MiB declared > 256 MiB cap
        }
        assert!(validate_tracev3(&file).is_err());
    }

    #[test]
    fn silently_dropped_catalog_marks_file_incomplete() {
        // A catalog chunk whose body fails the upstream catalog parser is
        // dropped log-and-continue: parse_log still returns Ok, minus that
        // catalog's process inventory. The framing count must catch it.
        let file = chunk(CHUNK_CATALOG, &[0xFFu8; 32]);
        assert_eq!(validate_tracev3(&file), Ok(1));
        let mut agg = Aggregator::default();
        agg.consume_tracev3("Persist/0.tracev3", &file);
        assert_eq!(agg.tracev3_failures, 0);
        assert_eq!(
            agg.tracev3_incomplete, 1,
            "dropped catalog must be detected"
        );
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
