//! Push-based streaming tar reader. Sysdiagnose archives are a few hundred
//! megabytes compressed and expand to gigabytes, so nothing is materialized:
//! bytes stream through and only the handful of files we know how to analyze
//! are retained. Handles ustar prefixes, PAX extended headers (Apple's tar
//! emits these for the long paths inside sysdiagnose), and GNU long names.

use serde::Serialize;
use std::io::{self, Write};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    ShutdownLog,
    CrashLog,
    PairedCrashLog,
    PsListing,
}

/// Matches "shutdown.log" and the rotated names iOS 26 introduced
/// ("shutdown.0.log", "shutdown.1.log", ...). Verified against a real
/// iOS 26.5.2 sysdiagnose, which carries only the rotated form.
fn is_shutdown_log(base: &str) -> bool {
    if base == "shutdown.log" {
        return true;
    }
    base.strip_prefix("shutdown.")
        .and_then(|rest| rest.strip_suffix(".log"))
        .is_some_and(|mid| !mid.is_empty() && mid.bytes().all(|b| b.is_ascii_digit()))
}

/// Tar member names in a sysdiagnose are relative canonical paths. Reject
/// absolute, empty-component, and dot-segment spellings before any scope
/// classification: raw component matching on those names can attribute an
/// artifact to a directory it lexically escapes.
fn canonical_member_path(path: &str) -> Option<&str> {
    // A single conventional `./` archive prefix is harmless. Any additional
    // dot component remains visible to the validation below.
    let p = path.strip_prefix("./").unwrap_or(path);
    if p.is_empty()
        || p.starts_with('/')
        || p.split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return None;
    }
    Some(p)
}

fn is_paired_device_component(component: &str) -> bool {
    component == "ProxiedDevice"
        || component
            .strip_prefix("ProxiedDevice-")
            .is_some_and(|suffix| !suffix.is_empty())
}

pub(crate) fn is_paired_device_path(path: &str) -> bool {
    let Some(p) = canonical_member_path(path) else {
        return false;
    };
    let components: Vec<&str> = p.split('/').collect();
    components
        .windows(2)
        .any(|pair| pair[0] == "logs" && is_paired_device_component(pair[1]))
}

pub fn classify(path: &str) -> Option<ArtifactKind> {
    let p = canonical_member_path(path)?;
    let components: Vec<&str> = p.split('/').collect();
    let base = *components.last()?;
    // AppleDouble metadata companions ("._foo.ips") appear in archives that
    // passed through a Mac; they are resource forks, not artifacts.
    if base.starts_with("._") {
        return None;
    }

    // Primary process artifacts have fixed locations in a sysdiagnose. Do
    // not let an unrelated or paired-device file with a familiar basename
    // substitute for phone evidence and earn a negative verdict.
    if components.len() == 4
        && components[1] == "system_logs.logarchive"
        && components[2] == "Extra"
        && is_shutdown_log(base)
    {
        return Some(ArtifactKind::ShutdownLog);
    }
    if !base.ends_with(".ips") {
        return if components.len() == 2 && (base == "ps.txt" || base == "ps_thread.txt") {
            Some(ArtifactKind::PsListing)
        } else {
            None
        };
    }

    // ProxiedDevice directories under logs/ carry reports from a paired
    // device (normally Apple Watch). They are scanned, but must not substitute
    // for the phone's crash-report surface or supply phone device metadata.
    if is_paired_device_path(p) {
        return Some(ArtifactKind::PairedCrashLog);
    }

    // Phone crash reports live under the archive root's direct
    // `crashes_and_spins` child (optionally in nested categories such as
    // `Panics`). A familiar directory name deeper in an unrelated subtree
    // must not substitute for the primary crash surface.
    if components.len() >= 3 && components[1] == "crashes_and_spins" {
        return Some(ArtifactKind::CrashLog);
    }
    None
}

/// Unified-log files are consumed as they stream by rather than retained:
/// a real logarchive carries hundreds of megabytes of tracev3 and uuidtext,
/// far past the retention budget, but each file can be reduced to a few
/// process facts and dropped (see `unified_log`).
enum ConsumeKind {
    Tracev3,
    /// Payload is the 32-hex binary UUID encoded by the file's location
    /// (`XX/` directory plus 30-char filename).
    UuidText(String),
}

fn is_upper_hex(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}

fn classify_consume(path: &str) -> Option<ConsumeKind> {
    let p = canonical_member_path(path)?;
    let components: Vec<&str> = p.split('/').collect();
    // The phone's unified logarchive is a direct child of the sysdiagnose
    // root. A nested lookalike (especially beneath logs/ProxiedDevice*) is
    // not primary iPhone evidence and must never earn unified-log coverage.
    if components.get(1) != Some(&"system_logs.logarchive") {
        return None;
    }
    let rest = components.get(2..)?;
    let base = *rest.last()?;
    if base.starts_with("._") {
        return None;
    }
    if base.ends_with(".tracev3") {
        return Some(ConsumeKind::Tracev3);
    }
    if let [dir, name] = rest {
        if dir.len() == 2 && name.len() == 30 && is_upper_hex(dir) && is_upper_hex(name) {
            return Some(ConsumeKind::UuidText(format!("{dir}{name}")));
        }
    }
    None
}

pub struct CollectedFile {
    pub path: String,
    pub kind: ArtifactKind,
    pub data: Vec<u8>,
    pub truncated: bool,
}

/// Guardrails against a hostile archive. Real sysdiagnose artifacts are tiny
/// (shutdown.log and .ips diagnostics are kilobytes, a few hundred .ips files
/// at most), so a scan that hits any of these caps is by definition not a
/// normal sysdiagnose - the caps exist so a crafted archive cannot exhaust
/// browser memory, and hitting one must surface as an incomplete scan.
#[derive(Clone, Copy)]
pub struct Limits {
    /// Per retained file.
    pub file_cap: usize,
    /// Across all retained files combined.
    pub total_retain_cap: usize,
    /// Number of files retained for analysis.
    pub max_retained_files: usize,
    /// Archive header blocks walked before parsing stops. Counts every
    /// entry type - directories, links, and PAX/GNU metadata included - so
    /// a metadata flood cannot bypass it.
    pub max_entries: u64,
    /// Total (decompressed) bytes accepted before parsing stops: the
    /// decompression-ratio ceiling against gzip bombs. A real sysdiagnose
    /// expands to a few gigabytes.
    pub max_stream_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            file_cap: 32 * 1024 * 1024,
            total_retain_cap: 192 * 1024 * 1024,
            max_retained_files: 4096,
            max_entries: 1_000_000,
            max_stream_bytes: 8 * 1024 * 1024 * 1024,
        }
    }
}

const META_CAP: u64 = 1024 * 1024;

enum Keep {
    No,
    Retain(String, ArtifactKind),
    Consume(String, ConsumeKind),
}

enum State {
    Header,
    Data {
        keep: Keep,
        buf: Vec<u8>,
        real: u64,
        total: u64,
        truncated: bool,
    },
    Meta {
        kind: MetaKind,
        buf: Vec<u8>,
        real: u64,
        total: u64,
        capped: bool,
    },
    Done,
}

#[derive(Clone, Copy)]
enum MetaKind {
    Pax,
    PaxGlobal,
    LongName,
}

#[derive(Default, Debug, PartialEq, Eq)]
struct LocalMeta {
    path: Option<String>,
    size: Option<u64>,
}

pub struct TarCollector {
    pending: Vec<u8>,
    state: State,
    /// A local PAX/GNU header applies to exactly the next archive member.
    /// Keeping the metadata as an Option also records that an otherwise-empty
    /// (for our purposes) xheader is still waiting for its target.
    next_meta: Option<LocalMeta>,
    limits: Limits,
    retained_bytes: usize,
    pub files: Vec<CollectedFile>,
    /// Streaming consumer for unified-log files (never retained; each file
    /// is reduced to process facts on completion and dropped).
    pub(crate) unified: crate::unified_log::Aggregator,
    /// Regular-file entries seen (user-facing "files in archive" stat).
    pub entries: u64,
    /// Every header block walked, metadata and directories included; this
    /// is what the entry cap applies to.
    headers: u64,
    /// Total bytes accepted, for the stream-size budget.
    stream_bytes: u64,
    /// Artifact files the scanner wanted but dropped because a global cap
    /// was already reached. Any nonzero value means the scan is incomplete.
    pub dropped_artifacts: u64,
    /// Kinds among the dropped artifacts. A kind that was present but
    /// entirely dropped must not be reported as "not found in the archive".
    pub dropped_kinds: std::collections::HashSet<ArtifactKind>,
    /// PAX/GNU metadata headers that could not be fully understood (bad
    /// record structure, undecodable path, or larger than META_CAP). Parsing
    /// stops before the affected member and the scan must not read as clean.
    pub meta_malformed: u64,
    /// Regular members with absolute, empty-component, or dot-segment paths.
    /// Their scope cannot be classified without normalization assumptions, so
    /// parsing stops before they can hide an artifact.
    pub malformed_paths: u64,
    /// Parsing stopped early because the archive had too many entries.
    pub entry_cap_hit: bool,
    /// Parsing stopped early because the stream exceeded the total byte
    /// budget (decompression bomb).
    pub stream_cap_hit: bool,
    /// Parsing stopped at a header whose checksum did not verify. On the
    /// first header this means "not a tar"; after valid entries it means
    /// the archive is corrupt and the remainder was never seen.
    pub bad_checksum: bool,
    /// Parsing stopped at a checksum-valid header whose numeric framing
    /// fields were malformed or outside the supported non-negative range.
    pub malformed_header: bool,
    zero_blocks: u8,
}

fn cstr_utf8(bytes: &[u8]) -> Result<&str, ()> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end]).map_err(|_| ())
}

/// Tar numeric field: octal text, or a non-negative GNU base-256 value when
/// the high bit is set. Framing must never guess that malformed input means
/// zero bytes: doing so changes every following header boundary.
fn parse_num(field: &[u8]) -> Option<u64> {
    if !field.is_empty() && field[0] & 0x80 != 0 {
        if field[0] & 0x40 != 0 {
            return None;
        }
        let mut v: u128 = (field[0] & 0x7f) as u128;
        for &b in &field[1..] {
            v = (v << 8) | b as u128;
        }
        u64::try_from(v).ok()
    } else {
        let s = std::str::from_utf8(field).ok()?;
        let t = s.trim_matches(|c: char| c == '\0' || c == ' ');
        if t.is_empty() || !t.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
            return None;
        }
        u64::from_str_radix(t, 8).ok()
    }
}

/// Strict local PAX extended-header parser. Records are length-delimited, so
/// unrelated values may contain arbitrary binary bytes (Apple xattrs do), but
/// the record envelope itself must be exact. `path` and `size` affect archive
/// framing/classification and therefore receive stricter semantic validation.
fn pax_local_meta(data: &[u8]) -> Result<LocalMeta, ()> {
    if data.is_empty() {
        return Err(());
    }

    let mut meta = LocalMeta::default();
    let mut i = 0;
    while i < data.len() {
        let sp = data[i..]
            .iter()
            .position(|&b| b == b' ')
            .map(|p| p + i)
            .ok_or(())?;
        let len_bytes = &data[i..sp];
        if len_bytes.is_empty() || !len_bytes.iter().all(u8::is_ascii_digit) {
            return Err(());
        }
        let len = std::str::from_utf8(len_bytes)
            .map_err(|_| ())?
            .parse::<usize>()
            .map_err(|_| ())?;
        // Checked arithmetic: a crafted length near usize::MAX would wrap
        // on 32-bit wasm, slip past the bounds check, and trap on the slice.
        let end = i
            .checked_add(len)
            .filter(|&e| e <= data.len() && e > sp + 1)
            .ok_or(())?;
        if data[end - 1] != b'\n' {
            return Err(());
        }
        let record = &data[sp + 1..end - 1];
        let eq = record.iter().position(|&b| b == b'=').ok_or(())?;
        if eq == 0 {
            return Err(());
        }
        let key = &record[..eq];
        let value = &record[eq + 1..];
        match key {
            b"path" => {
                if value.is_empty() || value.contains(&0) {
                    return Err(());
                }
                meta.path = Some(std::str::from_utf8(value).map_err(|_| ())?.to_string());
            }
            b"size" => {
                if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                    return Err(());
                }
                meta.size = Some(
                    std::str::from_utf8(value)
                        .map_err(|_| ())?
                        .parse::<u64>()
                        .map_err(|_| ())?,
                );
            }
            // Other keys are irrelevant to classification/framing. Their
            // values are deliberately not decoded: vendor xattrs can be raw
            // binary, including invalid UTF-8 and NUL bytes.
            _ => {}
        }
        i = end;
    }
    Ok(meta)
}

/// GNU `L` body. The extension stores exactly one NUL-terminated path; a
/// missing terminator or trailing bytes mean the following member cannot be
/// classified reliably.
fn gnu_long_path(data: &[u8]) -> Result<String, ()> {
    let end = data.iter().position(|&b| b == 0).ok_or(())?;
    if end == 0 || end + 1 != data.len() {
        return Err(());
    }
    Ok(std::str::from_utf8(&data[..end])
        .map_err(|_| ())?
        .to_string())
}

/// Tar header checksum: sum of all header bytes with the checksum field
/// itself read as spaces. Historic tar implementations wrote a signed-byte
/// sum, so both are accepted; anything else is a corrupt or fabricated
/// header, and parsing must not continue past it on guessed offsets.
fn checksum_ok(block: &[u8]) -> bool {
    let Some(stored) = parse_num(&block[148..156]) else {
        return false;
    };
    let mut unsigned: u64 = 0;
    let mut signed: i64 = 0;
    for (i, &b) in block.iter().enumerate() {
        let v = if (148..156).contains(&i) { b' ' } else { b };
        unsigned += v as u64;
        signed += (v as i8) as i64;
    }
    stored == unsigned || (signed >= 0 && stored == signed as u64)
}

impl TarCollector {
    pub fn with_limits(limits: Limits) -> Self {
        TarCollector {
            pending: Vec::new(),
            state: State::Header,
            next_meta: None,
            limits,
            retained_bytes: 0,
            files: Vec::new(),
            unified: Default::default(),
            entries: 0,
            headers: 0,
            stream_bytes: 0,
            dropped_artifacts: 0,
            dropped_kinds: Default::default(),
            meta_malformed: 0,
            malformed_paths: 0,
            entry_cap_hit: false,
            stream_cap_hit: false,
            bad_checksum: false,
            malformed_header: false,
            zero_blocks: 0,
        }
    }

    /// True once parsing reached a terminal state: the end-of-archive marker,
    /// or a deliberate early stop (entry cap, byte budget, bad checksum, or
    /// malformed metadata - each raises its own scan-limit flag/message).
    /// False means the stream just stopped mid-archive: it may have been
    /// truncated in transit, and the scan must not be presented as complete.
    pub fn terminated_cleanly(&self) -> bool {
        matches!(self.state, State::Done)
    }

    fn process(&mut self) {
        let mut cur = 0usize;
        loop {
            let state = std::mem::replace(&mut self.state, State::Header);
            match state {
                State::Done => {
                    self.state = State::Done;
                    cur = self.pending.len();
                    break;
                }
                State::Header => {
                    if self.pending.len() - cur < 512 {
                        self.state = State::Header;
                        break;
                    }
                    let block = &self.pending[cur..cur + 512];
                    if block.iter().all(|&b| b == 0) {
                        cur += 512;
                        self.zero_blocks += 1;
                        if self.zero_blocks >= 2 {
                            // A local extended header without a following
                            // member is a damaged archive, not a clean EOA.
                            if self.next_meta.take().is_some() {
                                self.meta_malformed += 1;
                            }
                            self.state = State::Done;
                        }
                        continue;
                    }
                    self.zero_blocks = 0;
                    if !checksum_ok(block) {
                        // Offsets derived from a corrupt header are garbage;
                        // continuing would misparse everything after it.
                        self.bad_checksum = true;
                        self.state = State::Done;
                        continue;
                    }
                    self.headers += 1;
                    if self.headers > self.limits.max_entries {
                        self.entry_cap_hit = true;
                        self.state = State::Done;
                        continue;
                    }
                    let Some(header_size) = parse_num(&block[124..136]) else {
                        self.malformed_header = true;
                        self.state = State::Done;
                        continue;
                    };
                    let typeflag = block[156];
                    cur += 512;

                    // Local metadata applies to one ordinary member. A
                    // second local/global metadata header cannot safely be
                    // combined with it by this reader, so stop rather than
                    // silently consuming the first override as the second
                    // metadata header's own name.
                    if self.next_meta.is_some() && matches!(typeflag, b'x' | b'g' | b'L') {
                        self.next_meta = None;
                        self.meta_malformed += 1;
                        self.state = State::Done;
                        continue;
                    }

                    let LocalMeta {
                        path: local_path,
                        size: local_size,
                    } = self.next_meta.take().unwrap_or_default();
                    let size = local_size.unwrap_or(header_size);
                    // Saturate: a base-256 size field can encode u64::MAX,
                    // where rounding up to the 512 boundary would overflow
                    // (panic in debug, silent wrap to 0 and a misparse
                    // cascade in release). Saturating instead makes the
                    // bogus entry swallow the rest of the stream, which is
                    // the safe outcome for garbage input.
                    let total = size.div_ceil(512).saturating_mul(512);

                    match typeflag {
                        b'0' | 0 | b'7' => {
                            self.entries += 1;
                            let path = match local_path {
                                Some(path) => path,
                                None => {
                                    let Ok(name) = cstr_utf8(&block[0..100]) else {
                                        self.malformed_paths += 1;
                                        self.state = State::Done;
                                        continue;
                                    };
                                    let prefix = if &block[257..262] == b"ustar" {
                                        let Ok(prefix) = cstr_utf8(&block[345..500]) else {
                                            self.malformed_paths += 1;
                                            self.state = State::Done;
                                            continue;
                                        };
                                        prefix
                                    } else {
                                        ""
                                    };
                                    if prefix.is_empty() {
                                        name.to_owned()
                                    } else {
                                        format!("{prefix}/{name}")
                                    }
                                }
                            };
                            let Some(path) = canonical_member_path(&path).map(str::to_owned) else {
                                self.malformed_paths += 1;
                                self.state = State::Done;
                                continue;
                            };
                            let at_cap = self.files.len() >= self.limits.max_retained_files
                                || self.retained_bytes >= self.limits.total_retain_cap;
                            let keep = match classify(&path) {
                                Some(k) if at_cap => {
                                    self.dropped_artifacts += 1;
                                    self.dropped_kinds.insert(k);
                                    Keep::No
                                }
                                Some(k) => Keep::Retain(path, k),
                                // Consumables are transient (bounded by
                                // file_cap, one at a time), so the retention
                                // caps do not apply to them.
                                None => match classify_consume(&path) {
                                    Some(k) => Keep::Consume(path, k),
                                    None => Keep::No,
                                },
                            };
                            if total == 0 {
                                match keep {
                                    Keep::Retain(p, k) => self.files.push(CollectedFile {
                                        path: p,
                                        kind: k,
                                        data: Vec::new(),
                                        truncated: false,
                                    }),
                                    // Empty unified-log members are still
                                    // evidence that the surface was present;
                                    // pass them through so validation records
                                    // the parse failure instead of erasing it.
                                    Keep::Consume(p, ConsumeKind::Tracev3) => {
                                        self.unified.consume_tracev3(&p, &[])
                                    }
                                    Keep::Consume(_, ConsumeKind::UuidText(uuid)) => {
                                        self.unified.consume_uuidtext(uuid, &[])
                                    }
                                    Keep::No => {}
                                }
                            } else {
                                self.state = State::Data {
                                    keep,
                                    buf: Vec::new(),
                                    real: size,
                                    total,
                                    truncated: false,
                                };
                            }
                        }
                        b'x' | b'g' | b'L' => {
                            let kind = match typeflag {
                                b'x' => MetaKind::Pax,
                                b'g' => MetaKind::PaxGlobal,
                                _ => MetaKind::LongName,
                            };
                            if total == 0 {
                                // A local/global PAX header has no records,
                                // and a GNU long-name header has no name.
                                self.meta_malformed += 1;
                                self.state = State::Done;
                            } else {
                                self.state = State::Meta {
                                    kind,
                                    buf: Vec::new(),
                                    real: size,
                                    total,
                                    capped: false,
                                };
                            }
                        }
                        // Directories, links, devices, and FIFOs carry no
                        // data blocks (POSIX), and mainstream readers
                        // (libarchive/bsdtar) ignore their size field on
                        // read. Honoring it here let a crafted archive give
                        // a directory a "payload" sized to swallow the next
                        // real entry - an artifact bsdtar extracts but this
                        // reader would never see.
                        b'1' | b'2' | b'3' | b'4' | b'5' | b'6' => {}
                        _ => {
                            // Unknown types: treated as data-bearing, per POSIX.
                            if total > 0 {
                                self.state = State::Data {
                                    keep: Keep::No,
                                    buf: Vec::new(),
                                    real: 0,
                                    total,
                                    truncated: false,
                                };
                            }
                        }
                    }
                }
                State::Data {
                    keep,
                    mut buf,
                    mut real,
                    mut total,
                    mut truncated,
                } => {
                    let avail = (self.pending.len() - cur) as u64;
                    let n = avail.min(total);
                    let r = n.min(real);
                    if r > 0 {
                        // Retained files count against the global retention
                        // budget; consumables only against the per-file cap,
                        // since at most one is buffered and then dropped.
                        let room = match &keep {
                            Keep::Retain(..) => self.limits.file_cap.saturating_sub(buf.len()).min(
                                self.limits
                                    .total_retain_cap
                                    .saturating_sub(self.retained_bytes),
                            ),
                            Keep::Consume(..) => self.limits.file_cap.saturating_sub(buf.len()),
                            Keep::No => 0,
                        };
                        let take = (r as usize).min(room);
                        buf.extend_from_slice(&self.pending[cur..cur + take]);
                        if matches!(keep, Keep::Retain(..)) {
                            self.retained_bytes += take;
                        }
                        if !matches!(keep, Keep::No) && take < r as usize {
                            truncated = true;
                        }
                    }
                    cur += n as usize;
                    real -= r;
                    total -= n;
                    if total == 0 {
                        match keep {
                            Keep::Retain(p, k) => self.files.push(CollectedFile {
                                path: p,
                                kind: k,
                                data: buf,
                                truncated,
                            }),
                            // A partially buffered unified-log file would
                            // parse to an under-count, not an error; skip
                            // it and let the engine surface the gap.
                            Keep::Consume(_, ConsumeKind::Tracev3) if truncated => {
                                self.unified.record_truncated_tracev3();
                            }
                            Keep::Consume(_, ConsumeKind::UuidText(_)) if truncated => {
                                self.unified.record_truncated_uuidtext();
                            }
                            Keep::Consume(p, kind) => match kind {
                                ConsumeKind::Tracev3 => self.unified.consume_tracev3(&p, &buf),
                                ConsumeKind::UuidText(uuid) => {
                                    self.unified.consume_uuidtext(uuid, &buf)
                                }
                            },
                            Keep::No => {}
                        }
                        self.state = State::Header;
                        continue;
                    }
                    self.state = State::Data {
                        keep,
                        buf,
                        real,
                        total,
                        truncated,
                    };
                    break; // consumed everything available
                }
                State::Meta {
                    kind,
                    mut buf,
                    mut real,
                    mut total,
                    mut capped,
                } => {
                    let avail = (self.pending.len() - cur) as u64;
                    let n = avail.min(total);
                    let r = n.min(real);
                    if r > 0 {
                        let room = (META_CAP as usize).saturating_sub(buf.len());
                        let take = (r as usize).min(room);
                        buf.extend_from_slice(&self.pending[cur..cur + take]);
                        if take < r as usize {
                            // A header larger than META_CAP was only
                            // partially read: whatever the unread tail
                            // declared (possibly the path itself) is lost,
                            // so the header cannot count as understood.
                            capped = true;
                        }
                    }
                    cur += n as usize;
                    real -= r;
                    total -= n;
                    if total == 0 {
                        let parsed = if capped {
                            Err(())
                        } else {
                            match kind {
                                MetaKind::Pax => pax_local_meta(&buf),
                                MetaKind::LongName => gnu_long_path(&buf).map(|path| LocalMeta {
                                    path: Some(path),
                                    size: None,
                                }),
                                // Persistent path/size overrides would change
                                // classification or framing for every later
                                // member. This reader does not model that
                                // state, so reject them rather than silently
                                // scanning different bytes than an extractor.
                                MetaKind::PaxGlobal => pax_local_meta(&buf).and_then(|meta| {
                                    if meta.path.is_some() || meta.size.is_some() {
                                        Err(())
                                    } else {
                                        Ok(LocalMeta::default())
                                    }
                                }),
                            }
                        };
                        match parsed {
                            Ok(meta) => {
                                if !matches!(kind, MetaKind::PaxGlobal) {
                                    self.next_meta = Some(meta);
                                }
                                self.state = State::Header;
                            }
                            Err(()) => {
                                // Once metadata that controls a following
                                // member is malformed or truncated, offsets
                                // and names are no longer trustworthy. Stop
                                // before guessing where the next header is.
                                self.next_meta = None;
                                self.meta_malformed += 1;
                                self.state = State::Done;
                            }
                        }
                        continue;
                    }
                    self.state = State::Meta {
                        kind,
                        buf,
                        real,
                        total,
                        capped,
                    };
                    break;
                }
            }
        }
        self.pending.drain(..cur);
    }
}

impl Write for TarCollector {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Every decompressed byte counts against the budget, including
        // bytes arriving after the end-of-archive marker: a gzip bomb with
        // an early tar end must not stream an unbounded tail through the
        // decompressor. The write that crosses the budget mid-archive
        // still yields a report (surfaced as a scan limit); anything past
        // that point halts the pipeline with an error.
        self.stream_bytes += buf.len() as u64;
        if self.stream_bytes > self.limits.max_stream_bytes {
            if !matches!(self.state, State::Done) {
                self.stream_cap_hit = true;
                self.state = State::Done;
                self.pending = Vec::new();
                return Ok(buf.len());
            }
            return Err(io::Error::other(
                "the archive decompressed past the scanner's safety budget; a real sysdiagnose is far smaller",
            ));
        }
        // Once parsing is done (end marker or an early stop), the rest of
        // the stream is accepted and dropped without buffering.
        if matches!(self.state, State::Done) {
            return Ok(buf.len());
        }
        self.pending.extend_from_slice(buf);
        self.process();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
pub mod test_util {
    /// Minimal ustar writer for tests and fixtures.
    pub fn header(name: &str, size: usize, typeflag: u8) -> [u8; 512] {
        assert!(name.len() < 100);
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(b"0000644\0");
        h[108..116].copy_from_slice(b"0000000\0");
        h[116..124].copy_from_slice(b"0000000\0");
        let size_o = format!("{:011o}\0", size);
        h[124..136].copy_from_slice(size_o.as_bytes());
        h[136..148].copy_from_slice(b"00000000000\0");
        h[148..156].copy_from_slice(b"        ");
        h[156] = typeflag;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        let cks = format!("{:06o}\0 ", sum);
        h[148..156].copy_from_slice(cks.as_bytes());
        h
    }

    pub fn entry(name: &str, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&header(name, data.len(), b'0'));
        out.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
        out
    }

    /// PAX-style entry: an 'x' extended header carrying the real (long) path,
    /// followed by the file entry under a truncated name.
    pub fn pax_entry(long_path: &str, data: &[u8]) -> Vec<u8> {
        let record_body = format!("path={}\n", long_path);
        // PAX record length is self-inclusive: "<len> <body>".
        let mut len = record_body.len() + 3; // rough first guess
        loop {
            let candidate = format!("{} {}", len, record_body);
            if candidate.len() == len {
                break;
            }
            len = candidate.len();
        }
        let record = format!("{} {}", len, record_body);
        let mut out = Vec::new();
        out.extend_from_slice(&header("PaxHeaders/x", record.len(), b'x'));
        out.extend_from_slice(record.as_bytes());
        let pad = (512 - record.len() % 512) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
        out.extend_from_slice(&entry("truncated-name", data));
        out
    }

    pub fn finish(mut archive: Vec<u8>) -> Vec<u8> {
        archive.extend(std::iter::repeat_n(0u8, 1024));
        archive
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn pax_record(key: &[u8], value: &[u8]) -> Vec<u8> {
        let content_len = 1 + key.len() + 1 + value.len() + 1; // space + key=value\n
        let mut len = content_len + 1;
        while len.to_string().len() + content_len != len {
            len = len.to_string().len() + content_len;
        }
        let mut record = format!("{len} ").into_bytes();
        record.extend_from_slice(key);
        record.push(b'=');
        record.extend_from_slice(value);
        record.push(b'\n');
        assert_eq!(record.len(), len);
        record
    }

    fn typed_entry(name: &str, typeflag: u8, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&test_util::header(name, data.len(), typeflag));
        out.extend_from_slice(data);
        out.extend(std::iter::repeat_n(0u8, (512 - data.len() % 512) % 512));
        out
    }

    fn resign_header(header: &mut [u8; 512]) {
        header[148..156].copy_from_slice(b"        ");
        let sum: u32 = header.iter().map(|&b| u32::from(b)).sum();
        let checksum = format!("{sum:06o}\0 ");
        header[148..156].copy_from_slice(checksum.as_bytes());
    }

    #[test]
    fn collects_only_selected_files_and_handles_pax() {
        let mut archive = Vec::new();
        archive.extend_from_slice(&test_util::header("sysdiagnose_x/", 0, b'5'));
        archive.extend_from_slice(&test_util::entry("sysdiagnose_x/ps.txt", b"PS CONTENT"));
        archive.extend_from_slice(&test_util::entry("sysdiagnose_x/ignored.bin", &[0xAB; 700]));
        archive.extend_from_slice(&test_util::pax_entry(
            "sysdiagnose_x/system_logs.logarchive/Extra/shutdown.log",
            b"SHUTDOWN CONTENT",
        ));
        archive.extend_from_slice(&test_util::entry(
            "sysdiagnose_x/crashes_and_spins/bh-2026-07-01.ips",
            b"{}\n{}",
        ));
        let archive = test_util::finish(archive);

        // Feed in awkward 7-byte chunks to stress the state machine.
        let mut col = TarCollector::with_limits(Limits::default());
        for chunk in archive.chunks(7) {
            col.write_all(chunk).unwrap();
        }

        assert_eq!(col.entries, 4); // ps.txt, ignored.bin, shutdown.log, .ips
        assert_eq!(col.files.len(), 3);
        let paths: Vec<&str> = col.files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&"sysdiagnose_x/system_logs.logarchive/Extra/shutdown.log"));
        let sd = col
            .files
            .iter()
            .find(|f| f.kind == ArtifactKind::ShutdownLog)
            .unwrap();
        assert_eq!(sd.data, b"SHUTDOWN CONTENT");
        let ps = col
            .files
            .iter()
            .find(|f| f.kind == ArtifactKind::PsListing)
            .unwrap();
        assert_eq!(ps.data, b"PS CONTENT");
    }

    #[test]
    fn retained_file_count_cap_drops_extra_artifacts() {
        let mut archive = Vec::new();
        for i in 0..3 {
            archive.extend_from_slice(&test_util::entry(
                &format!("root/crashes_and_spins/proc{i}-2026.ips"),
                b"{}\n{}",
            ));
        }
        let archive = test_util::finish(archive);
        let mut col = TarCollector::with_limits(Limits {
            max_retained_files: 2,
            ..Limits::default()
        });
        col.write_all(&archive).unwrap();
        assert_eq!(col.files.len(), 2);
        assert_eq!(col.dropped_artifacts, 1);
    }

    #[test]
    fn total_retain_cap_truncates_and_then_drops() {
        let mut archive = Vec::new();
        archive.extend_from_slice(&test_util::entry("root/ps.txt", &[b'a'; 40]));
        archive.extend_from_slice(&test_util::entry("root/ps_thread.txt", &[b'b'; 40]));
        let archive = test_util::finish(archive);
        let mut col = TarCollector::with_limits(Limits {
            total_retain_cap: 10,
            ..Limits::default()
        });
        col.write_all(&archive).unwrap();
        assert_eq!(col.files.len(), 1);
        assert_eq!(col.files[0].data.len(), 10);
        assert!(col.files[0].truncated);
        assert_eq!(col.dropped_artifacts, 1);
    }

    #[test]
    fn entry_cap_stops_parsing() {
        let mut archive = Vec::new();
        archive.extend_from_slice(&test_util::entry("root/a.txt", b"x"));
        archive.extend_from_slice(&test_util::entry("root/b.txt", b"x"));
        archive.extend_from_slice(&test_util::entry("root/ps.txt", b"would match"));
        let archive = test_util::finish(archive);
        let mut col = TarCollector::with_limits(Limits {
            max_entries: 2,
            ..Limits::default()
        });
        col.write_all(&archive).unwrap();
        assert!(col.entry_cap_hit);
        assert!(
            col.files.is_empty(),
            "nothing after the cap may be retained"
        );
    }

    #[test]
    fn metadata_flood_hits_entry_cap() {
        // Directories, links, and PAX/GNU metadata count against the entry
        // cap too; a flood of them must not walk unbounded.
        let mut archive = Vec::new();
        for i in 0..5 {
            archive.extend_from_slice(&test_util::header(&format!("root/d{i}/"), 0, b'5'));
        }
        let archive = test_util::finish(archive);
        let mut col = TarCollector::with_limits(Limits {
            max_entries: 3,
            ..Limits::default()
        });
        col.write_all(&archive).unwrap();
        assert!(col.entry_cap_hit);
    }

    #[test]
    fn bad_checksum_stops_parsing() {
        let mut archive = Vec::new();
        archive.extend_from_slice(&test_util::entry("root/ps.txt", b"PS"));
        let mut corrupt = test_util::entry("root/ps_thread.txt", b"PS2");
        corrupt[0] ^= 0xFF;
        archive.extend_from_slice(&corrupt);
        let archive = test_util::finish(archive);
        let mut col = TarCollector::with_limits(Limits::default());
        col.write_all(&archive).unwrap();
        assert!(col.bad_checksum);
        assert_eq!(col.files.len(), 1, "entries before the corruption stay");
    }

    #[test]
    fn malformed_numeric_size_stops_instead_of_guessing_zero() {
        assert_eq!(parse_num(b"zzzzzzzzzzz\0"), None);
        assert_eq!(parse_num(b"00000000002\0"), Some(2));

        let mut archive = test_util::entry("root/ps.txt", b"PS");
        let mut malformed = test_util::header("root/unknown.bin", 0, b'0');
        malformed[124..136].copy_from_slice(b"zzzzzzzzzzz\0");
        resign_header(&mut malformed);
        archive.extend_from_slice(&malformed);
        archive.extend_from_slice(&test_util::entry("root/ps_thread.txt", b"PS2"));
        let mut col = TarCollector::with_limits(Limits::default());
        col.write_all(&test_util::finish(archive)).unwrap();
        assert!(col.malformed_header);
        assert_eq!(
            col.files.len(),
            1,
            "nothing after malformed framing is read"
        );
    }

    #[test]
    fn invalid_utf8_in_ustar_path_stops_before_classification() {
        let mut header = test_util::header("root/ps.txt", 0, b'0');
        header[0] = 0xff;
        resign_header(&mut header);
        let archive = test_util::finish(header.to_vec());

        let mut col = TarCollector::with_limits(Limits::default());
        col.write_all(&archive).unwrap();

        assert_eq!(col.malformed_paths, 1);
        assert!(col.files.is_empty());
    }

    #[test]
    fn ambiguous_regular_member_path_stops_instead_of_hiding_artifacts() {
        let mut archive = test_util::entry("root/crashes_and_spins/../other/bh.ips", b"ambiguous");
        archive.extend_from_slice(&test_util::entry("root/ps.txt", b"PS"));
        let mut col = TarCollector::with_limits(Limits::default());
        col.write_all(&test_util::finish(archive)).unwrap();
        assert_eq!(col.malformed_paths, 1);
        assert!(col.files.is_empty());
    }

    #[test]
    fn stream_byte_budget_stops_parsing() {
        let mut archive = Vec::new();
        for i in 0..8 {
            archive.extend_from_slice(&test_util::entry(&format!("root/f{i}.bin"), &[0u8; 512]));
        }
        let archive = test_util::finish(archive);
        let mut col = TarCollector::with_limits(Limits {
            max_stream_bytes: 2048,
            ..Limits::default()
        });
        // The write crossing the budget flags the cap; anything past that
        // halts the pipeline with an error.
        let mut errored = false;
        for chunk in archive.chunks(700) {
            if col.write_all(chunk).is_err() {
                errored = true;
                break;
            }
        }
        assert!(col.stream_cap_hit);
        assert!(
            errored,
            "continuing past the budget must halt with an error"
        );
    }

    #[test]
    fn bytes_after_end_marker_still_count_against_budget() {
        // A gzip bomb can hide its payload after an early tar end-of-archive
        // marker; those bytes must not stream unbounded past the budget.
        let archive = test_util::finish(test_util::entry("root/ps.txt", b"PS"));
        let mut col = TarCollector::with_limits(Limits {
            max_stream_bytes: 8192,
            ..Limits::default()
        });
        col.write_all(&archive).unwrap();
        assert!(col.terminated_cleanly(), "end marker reached");
        let tail = [0xAAu8; 4096];
        let mut errored = false;
        for _ in 0..8 {
            if col.write_all(&tail).is_err() {
                errored = true;
                break;
            }
        }
        assert!(errored, "an unbounded post-marker tail must be refused");
        assert_eq!(col.files.len(), 1, "the completed scan data is intact");
    }

    #[test]
    fn pax_length_overflow_is_rejected_not_panicking() {
        // A record length near usize::MAX would wrap on 32-bit wasm and trap
        // on the slice; checked arithmetic must reject it instead.
        let huge = format!("{} path=/x\n", u64::MAX);
        assert_eq!(pax_local_meta(huge.as_bytes()), Err(()));
        let also_huge = b"99999999999999999999 path=/x\n"; // > u64::MAX: parse fails
        assert_eq!(pax_local_meta(also_huge), Err(()));
        // a well-formed record still parses (length is self-inclusive)
        assert_eq!(
            pax_local_meta(b"15 path=/a/b/c\n"),
            Ok(LocalMeta {
                path: Some("/a/b/c".into()),
                size: None,
            }),
            "sanity: valid record"
        );
    }

    #[test]
    fn pax_binary_record_before_path_does_not_hide_the_path() {
        // Apple's tar writes raw-binary xattr records (for example
        // SCHILY.xattr.com.apple.provenance); one ordered before path= used
        // to abort the whole header, dropping the long name and letting the
        // entry fall back to a truncated ustar name that may no longer
        // classify as an artifact.
        let mut body = Vec::new();
        let bin_value = [0x01u8, 0xFF, 0x00, 0xC3, 0x28]; // invalid UTF-8
        let key = "SCHILY.xattr.com.apple.provenance";
        let content_len = 1 + key.len() + 1 + bin_value.len() + 1; // ' ' key '=' value '\n'
        let mut len = content_len + 2;
        while (len.to_string().len() + content_len) != len {
            len = len.to_string().len() + content_len;
        }
        body.extend_from_slice(len.to_string().as_bytes());
        body.push(b' ');
        body.extend_from_slice(key.as_bytes());
        body.push(b'=');
        body.extend_from_slice(&bin_value);
        body.push(b'\n');
        // path record, length prefix computed to be self-inclusive
        let path_body = "path=/root/dir/long-name.ips\n";
        let mut plen = path_body.len() + 2;
        while plen.to_string().len() + 1 + path_body.len() != plen {
            plen = plen.to_string().len() + 1 + path_body.len();
        }
        body.extend_from_slice(format!("{plen} {path_body}").as_bytes());
        assert_eq!(
            pax_local_meta(&body),
            Ok(LocalMeta {
                path: Some("/root/dir/long-name.ips".into()),
                size: None,
            })
        );
    }

    #[test]
    fn pax_undecodable_path_is_malformed() {
        assert_eq!(pax_local_meta(b"11 path=\xFF\xFE\n"), Err(()));
    }

    #[test]
    fn pax_path_and_size_are_strict() {
        let mut both = pax_record(b"path", b"root/ignored.bin");
        both.extend_from_slice(&pax_record(b"size", b"2"));
        assert_eq!(
            pax_local_meta(&both),
            Ok(LocalMeta {
                path: Some("root/ignored.bin".into()),
                size: Some(2),
            })
        );
        assert_eq!(pax_local_meta(&pax_record(b"path", b"")), Err(()));
        assert_eq!(
            pax_local_meta(&pax_record(b"path", b"root/ps\0.txt")),
            Err(())
        );
        assert_eq!(pax_local_meta(b"10 path=/x"), Err(()));
        assert_eq!(pax_local_meta(&pax_record(b"size", b"2x")), Err(()));
    }

    #[test]
    fn pax_size_override_preserves_member_boundaries() {
        // The ustar header claims zero bytes, but PAX size=2 is authoritative.
        // Ignoring it would interpret the payload padding as headers and lose
        // the following process inventory.
        let mut meta = pax_record(b"path", b"root/ignored.bin");
        meta.extend_from_slice(&pax_record(b"size", b"2"));
        let mut archive = typed_entry("PaxHeaders/x", b'x', &meta);
        archive.extend_from_slice(&test_util::header("short", 0, b'0'));
        archive.extend_from_slice(b"XY");
        archive.extend(std::iter::repeat_n(0u8, 510));
        archive.extend_from_slice(&test_util::entry("root/ps.txt", b"PS CONTENT"));
        let archive = test_util::finish(archive);

        let mut col = TarCollector::with_limits(Limits::default());
        col.write_all(&archive).unwrap();
        assert_eq!(col.meta_malformed, 0);
        assert_eq!(col.files.len(), 1);
        assert_eq!(col.files[0].path, "root/ps.txt");
        assert_eq!(col.files[0].data, b"PS CONTENT");
    }

    #[test]
    fn malformed_or_dangling_local_metadata_stops_safely() {
        let path = pax_record(b"path", b"root/ps.txt");

        let dangling = test_util::finish(typed_entry("PaxHeaders/x", b'x', &path));
        let mut col = TarCollector::with_limits(Limits::default());
        col.write_all(&dangling).unwrap();
        assert_eq!(col.meta_malformed, 1, "metadata needs a target member");

        let mut consecutive = typed_entry("PaxHeaders/x", b'x', &path);
        consecutive.extend_from_slice(&typed_entry("././@LongLink", b'L', b"root/ps.txt\0"));
        consecutive.extend_from_slice(&test_util::entry("short", b"PS"));
        let mut col = TarCollector::with_limits(Limits::default());
        col.write_all(&test_util::finish(consecutive)).unwrap();
        assert_eq!(col.meta_malformed, 1);
        assert!(col.files.is_empty());
    }

    #[test]
    fn gnu_long_name_requires_one_utf8_nul_terminated_path() {
        assert_eq!(gnu_long_path(b"root/ps.txt\0"), Ok("root/ps.txt".into()));
        assert_eq!(gnu_long_path(b"root/ps.txt"), Err(()));
        assert_eq!(gnu_long_path(b"\0"), Err(()));
        assert_eq!(gnu_long_path(b"root/ps.txt\0junk"), Err(()));
        assert_eq!(gnu_long_path(b"root/\xFF\0"), Err(()));
    }

    #[test]
    fn global_pax_framing_override_is_rejected() {
        let global = pax_record(b"size", b"2");
        let mut archive = typed_entry("GlobalHead.0", b'g', &global);
        archive.extend_from_slice(&test_util::entry("root/ps.txt", b"PS"));
        let mut col = TarCollector::with_limits(Limits::default());
        col.write_all(&test_util::finish(archive)).unwrap();
        assert_eq!(col.meta_malformed, 1);
        assert!(col.files.is_empty());
    }

    #[test]
    fn malformed_pax_header_raises_counter_and_stops_before_target() {
        let mut archive = Vec::new();
        // 'x' header whose body has a garbage length prefix
        let body = b"not-a-length path=/x\n";
        archive.extend_from_slice(&test_util::header("PaxHeaders/x", body.len(), b'x'));
        archive.extend_from_slice(body);
        archive.extend(std::iter::repeat_n(0u8, (512 - body.len() % 512) % 512));
        archive.extend_from_slice(&test_util::entry("root/ps.txt", b"PS"));
        let archive = test_util::finish(archive);
        let mut col = TarCollector::with_limits(Limits::default());
        col.write_all(&archive).unwrap();
        assert_eq!(col.meta_malformed, 1);
        assert!(
            col.files.is_empty(),
            "members after untrusted metadata must not be guessed"
        );
    }

    #[test]
    fn directory_size_field_cannot_swallow_the_next_entry() {
        // POSIX directories have no data blocks and libarchive ignores their
        // size on read. A crafted type-'5' header with size=1024 used to make
        // this reader skip the next entry (here: ps.txt) as directory payload
        // while bsdtar would extract it - a silently unscanned artifact.
        let mut archive = Vec::new();
        let mut dir = test_util::header("root/x/", 1024, b'5');
        // recompute checksum after forging the size is handled by header();
        // (header() already wrote size 1024 and a valid checksum)
        let _ = &mut dir;
        archive.extend_from_slice(&dir);
        archive.extend_from_slice(&test_util::entry("root/ps.txt", b"PS CONTENT"));
        let archive = test_util::finish(archive);
        let mut col = TarCollector::with_limits(Limits::default());
        col.write_all(&archive).unwrap();
        assert_eq!(col.files.len(), 1, "ps.txt must not be swallowed");
        assert_eq!(col.files[0].data, b"PS CONTENT");
    }

    #[test]
    fn dropped_artifacts_record_their_kind() {
        let mut archive = Vec::new();
        archive.extend_from_slice(&test_util::entry("root/ps.txt", b"PS"));
        archive.extend_from_slice(&test_util::entry(
            "root/crashes_and_spins/a-2026.ips",
            b"{}\n{}",
        ));
        let archive = test_util::finish(archive);
        let mut col = TarCollector::with_limits(Limits {
            max_retained_files: 1,
            ..Limits::default()
        });
        col.write_all(&archive).unwrap();
        assert_eq!(col.dropped_artifacts, 1);
        assert!(col.dropped_kinds.contains(&ArtifactKind::CrashLog));
        assert!(!col.dropped_kinds.contains(&ArtifactKind::PsListing));
    }

    #[test]
    fn classify_consume_patterns() {
        let lp = "root/system_logs.logarchive";
        assert!(matches!(
            classify_consume(&format!("{lp}/Persist/0000000000000001.tracev3")),
            Some(ConsumeKind::Tracev3)
        ));
        assert!(matches!(
            classify_consume(&format!("{lp}/Special/0000000000000002.tracev3")),
            Some(ConsumeKind::Tracev3)
        ));
        match classify_consume(&format!("{lp}/AB/CDEF01234567890123456789012345")) {
            Some(ConsumeKind::UuidText(u)) => {
                assert_eq!(u, "ABCDEF01234567890123456789012345")
            }
            _ => panic!("uuidtext layout must classify"),
        }
        // dsc must never be consumed (155 MB shared string cache)
        assert!(classify_consume(&format!("{lp}/dsc/CDEF01234567890123456789012345")).is_none());
        // lowercase hex is not the uuidtext layout
        assert!(classify_consume(&format!("{lp}/ab/cdef01234567890123456789012345")).is_none());
        // tracev3 outside a logarchive is not ours
        assert!(classify_consume("root/other/x.tracev3").is_none());
        // component boundary: a lookalike suffix must not become the real
        // unified-log surface.
        assert!(classify_consume(
            "root/not-system_logs.logarchive/Persist/0000000000000001.tracev3"
        )
        .is_none());
        assert!(classify_consume(
            "root/random/system_logs.logarchive/Persist/0000000000000001.tracev3"
        )
        .is_none());
        assert!(classify_consume(
            "root/logs/ProxiedDevice/system_logs.logarchive/Persist/0000000000000001.tracev3"
        )
        .is_none());
        assert!(classify_consume(
            "root/logs/ProxiedDevice/system_logs.logarchive/AB/CDEF01234567890123456789012345"
        )
        .is_none());
        assert!(
            classify_consume("root/system_logs.logarchive/../other/0000000000000001.tracev3")
                .is_none()
        );
        // AppleDouble companions are ignored here too
        assert!(classify_consume(&format!("{lp}/Persist/._0000000000000001.tracev3")).is_none());
    }

    #[test]
    fn consumed_files_are_not_retained() {
        let lp = "root/system_logs.logarchive";
        let mut archive = Vec::new();
        archive.extend_from_slice(&test_util::entry(
            &format!("{lp}/Persist/0000000000000001.tracev3"),
            &[0xAB; 700], // garbage: parse failure, but must be consumed
        ));
        archive.extend_from_slice(&test_util::entry("root/ps.txt", b"PS"));
        let archive = test_util::finish(archive);
        let mut col = TarCollector::with_limits(Limits::default());
        col.write_all(&archive).unwrap();
        assert_eq!(col.files.len(), 1, "only ps.txt is retained");
        assert_eq!(col.unified.tracev3_files, 1);
        assert_eq!(col.unified.tracev3_failures, 1);
    }

    #[test]
    fn empty_and_truncated_unified_members_are_recorded() {
        let lp = "root/system_logs.logarchive";
        let empty = test_util::finish(test_util::entry(
            &format!("{lp}/Persist/0000000000000001.tracev3"),
            b"",
        ));
        let mut col = TarCollector::with_limits(Limits::default());
        col.write_all(&empty).unwrap();
        assert_eq!(col.unified.tracev3_files, 1);
        assert!(col.unified.saw_content());

        let mut archive =
            test_util::entry(&format!("{lp}/Persist/0000000000000002.tracev3"), b"XX");
        archive.extend_from_slice(&test_util::entry(
            &format!("{lp}/AB/CDEF01234567890123456789012345"),
            b"YY",
        ));
        let mut col = TarCollector::with_limits(Limits {
            file_cap: 1,
            ..Limits::default()
        });
        col.write_all(&test_util::finish(archive)).unwrap();
        assert_eq!(col.unified.truncated_tracev3_files, 1);
        assert_eq!(col.unified.truncated_uuidtext_files, 1);
        assert_eq!(col.unified.tracev3_files, 0);
        assert_eq!(col.unified.uuidtext_files, 0);
    }

    #[test]
    fn classify_paths() {
        assert_eq!(
            classify("root/system_logs.logarchive/Extra/shutdown.log"),
            Some(ArtifactKind::ShutdownLog)
        );
        // iOS 26 rotated form, and names that must not match it
        assert_eq!(
            classify("root/system_logs.logarchive/Extra/shutdown.0.log"),
            Some(ArtifactKind::ShutdownLog)
        );
        assert_eq!(
            classify("root/system_logs.logarchive/Extra/shutdown.12.log"),
            Some(ArtifactKind::ShutdownLog)
        );
        assert_eq!(classify("root/Extra/shutdown.old.log"), None);
        assert_eq!(classify("root/Extra/preshutdown.log"), None);
        assert_eq!(classify("root/Extra/shutdown.log"), None);
        assert_eq!(classify("root/random/shutdown.log"), None);
        assert_eq!(
            classify("root/logs/ProxiedDevice/system_logs.logarchive/Extra/shutdown.log"),
            None
        );
        assert_eq!(
            classify("./root/crashes_and_spins/Panics/panic-full.ips"),
            Some(ArtifactKind::CrashLog)
        );
        // paired-device (watchOS) crash reports proxied into the phone's
        // sysdiagnose are the same format and must be scanned
        assert_eq!(
            classify("root/logs/ProxiedDevice/TodoistWatchOS-2026-07-16-202231.ips"),
            Some(ArtifactKind::PairedCrashLog)
        );
        assert_eq!(
            classify("root/logs/ProxiedDevice-ABC123/app-2026.ips"),
            Some(ArtifactKind::PairedCrashLog)
        );
        assert_eq!(classify("root/logs/ProxiedDeviceBackup/app-2026.ips"), None);
        assert_eq!(classify("root/logs/ProxiedDevice-/app-2026.ips"), None);
        // A root directory that happens to contain the word ProxiedDevice
        // must not relabel a phone report nested under crashes_and_spins.
        assert_eq!(
            classify("ProxiedDevice-root/crashes_and_spins/app-2026.ips"),
            Some(ArtifactKind::CrashLog)
        );
        // OTA restore logs are a different, undocumented text format;
        // deliberately out of scope and disclosed in coverage.not_examined
        assert_eq!(classify("root/logs/OTAUpdateLogs/OTAUpdate-2026.ips"), None);
        assert_eq!(classify("root/ps.txt"), Some(ArtifactKind::PsListing));
        assert_eq!(
            classify("root/ps_thread.txt"),
            Some(ArtifactKind::PsListing)
        );
        assert_eq!(classify("ps.txt"), None);
        assert_eq!(classify("root/random/ps.txt"), None);
        assert_eq!(classify("root/logs/ProxiedDevice/ps.txt"), None);
        assert_eq!(classify("root/otherdir/x.ips"), None);
        // component boundary: a lookalike directory must not qualify
        assert_eq!(classify("root/notcrashes_and_spins/x.ips"), None);
        assert_eq!(classify("root/random/crashes_and_spins/x.ips"), None);
        assert_eq!(classify("/root/crashes_and_spins/app-2026.ips"), None);
        assert_eq!(classify("../root/crashes_and_spins/app-2026.ips"), None);
        assert_eq!(classify("./../root/crashes_and_spins/app-2026.ips"), None);
        assert_eq!(
            classify("root/crashes_and_spins/../other/app-2026.ips"),
            None
        );
        assert_eq!(
            classify("root/logs/ProxiedDevice/../../crashes_and_spins/app-2026.ips"),
            None
        );
        assert_eq!(classify("root/sysdiagnose.log"), None);
        // AppleDouble companions must be ignored even when the suffix matches
        assert_eq!(classify("root/crashes_and_spins/._bh-2026.ips"), None);
        assert_eq!(classify("root/._ps.txt"), None);
    }
}
