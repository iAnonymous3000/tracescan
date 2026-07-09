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

pub fn classify(path: &str) -> Option<ArtifactKind> {
    let p = path.trim_start_matches("./");
    let base = p.rsplit('/').next().unwrap_or(p);
    // AppleDouble metadata companions ("._foo.ips") appear in archives that
    // passed through a Mac; they are resource forks, not artifacts.
    if base.starts_with("._") {
        return None;
    }
    if is_shutdown_log(base) {
        return Some(ArtifactKind::ShutdownLog);
    }
    // Component-wise match: "notcrashes_and_spins/x.ips" must not qualify.
    if base.ends_with(".ips") && p.split('/').any(|seg| seg == "crashes_and_spins") {
        return Some(ArtifactKind::CrashLog);
    }
    if base == "ps.txt" || base == "ps_thread.txt" {
        return Some(ArtifactKind::PsListing);
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
    let p = path.trim_start_matches("./");
    let rest = &p[p.find("system_logs.logarchive/")? + "system_logs.logarchive/".len()..];
    let base = rest.rsplit('/').next().unwrap_or(rest);
    if base.starts_with("._") {
        return None;
    }
    if base.ends_with(".tracev3") {
        return Some(ConsumeKind::Tracev3);
    }
    let mut comps = rest.split('/');
    if let (Some(dir), Some(name), None) = (comps.next(), comps.next(), comps.next()) {
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
/// (shutdown.log and .ips crash logs are kilobytes, a few hundred crash logs
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
    },
    Done,
}

enum MetaKind {
    Pax,
    PaxGlobal,
    LongName,
}

pub struct TarCollector {
    pending: Vec<u8>,
    state: State,
    next_path: Option<String>,
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
    /// Parsing stopped early because the archive had too many entries.
    pub entry_cap_hit: bool,
    /// Parsing stopped early because the stream exceeded the total byte
    /// budget (decompression bomb).
    pub stream_cap_hit: bool,
    /// Parsing stopped at a header whose checksum did not verify. On the
    /// first header this means "not a tar"; after valid entries it means
    /// the archive is corrupt and the remainder was never seen.
    pub bad_checksum: bool,
    zero_blocks: u8,
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Tar numeric field: octal text, or GNU base-256 when the high bit is set.
fn parse_num(field: &[u8]) -> u64 {
    if !field.is_empty() && field[0] & 0x80 != 0 {
        let mut v: u128 = (field[0] & 0x7f) as u128;
        for &b in &field[1..] {
            v = (v << 8) | b as u128;
        }
        v.min(u64::MAX as u128) as u64
    } else {
        let s = String::from_utf8_lossy(field);
        let t = s.trim_matches(|c: char| c == '\0' || c == ' ');
        u64::from_str_radix(t, 8).unwrap_or(0)
    }
}

/// PAX extended header body: sequence of "<len> <key>=<value>\n" records.
fn pax_path(data: &[u8]) -> Option<String> {
    let mut i = 0;
    while i < data.len() {
        let sp = data[i..].iter().position(|&b| b == b' ')? + i;
        let len: usize = std::str::from_utf8(&data[i..sp])
            .ok()?
            .trim()
            .parse()
            .ok()?;
        // Checked arithmetic: a crafted length near usize::MAX would wrap
        // on 32-bit wasm, slip past the bounds check, and trap on the slice.
        let end = i.checked_add(len).filter(|&e| e <= data.len() && e > sp)?;
        let rec = std::str::from_utf8(&data[sp + 1..end]).ok()?;
        let rec = rec.strip_suffix('\n').unwrap_or(rec);
        if let Some(v) = rec.strip_prefix("path=") {
            return Some(v.to_string());
        }
        i = end;
    }
    None
}

/// Tar header checksum: sum of all header bytes with the checksum field
/// itself read as spaces. Historic tar implementations wrote a signed-byte
/// sum, so both are accepted; anything else is a corrupt or fabricated
/// header, and parsing must not continue past it on guessed offsets.
fn checksum_ok(block: &[u8]) -> bool {
    let stored = parse_num(&block[148..156]);
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
            next_path: None,
            limits,
            retained_bytes: 0,
            files: Vec::new(),
            unified: Default::default(),
            entries: 0,
            headers: 0,
            stream_bytes: 0,
            dropped_artifacts: 0,
            entry_cap_hit: false,
            stream_cap_hit: false,
            bad_checksum: false,
            zero_blocks: 0,
        }
    }

    /// True once parsing reached a terminal state: the end-of-archive marker,
    /// or a deliberate early stop (entry cap, byte budget, bad checksum -
    /// each of which raises its own flag and its own scan-limit message).
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
                    let size = parse_num(&block[124..136]);
                    let typeflag = block[156];
                    let name = cstr(&block[0..100]);
                    let prefix = if &block[257..262] == b"ustar" {
                        cstr(&block[345..500])
                    } else {
                        String::new()
                    };
                    let path = match self.next_path.take() {
                        Some(p) => p,
                        None if prefix.is_empty() => name,
                        None => format!("{}/{}", prefix, name),
                    };
                    // Saturate: a base-256 size field can encode u64::MAX,
                    // where rounding up to the 512 boundary would overflow
                    // (panic in debug, silent wrap to 0 and a misparse
                    // cascade in release). Saturating instead makes the
                    // bogus entry swallow the rest of the stream, which is
                    // the safe outcome for garbage input.
                    let total = size.div_ceil(512).saturating_mul(512);
                    cur += 512;

                    match typeflag {
                        b'0' | 0 | b'7' => {
                            self.entries += 1;
                            let at_cap = self.files.len() >= self.limits.max_retained_files
                                || self.retained_bytes >= self.limits.total_retain_cap;
                            let keep = match classify(&path) {
                                Some(_) if at_cap => {
                                    self.dropped_artifacts += 1;
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
                                if let Keep::Retain(p, k) = keep {
                                    self.files.push(CollectedFile {
                                        path: p,
                                        kind: k,
                                        data: Vec::new(),
                                        truncated: false,
                                    });
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
                            if total > 0 {
                                self.state = State::Meta {
                                    kind,
                                    buf: Vec::new(),
                                    real: size,
                                    total,
                                };
                            }
                        }
                        _ => {
                            // Directories, links, and unknown types: skip payload.
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
                            Keep::Consume(_, _) if truncated => {
                                self.unified.truncated_files += 1;
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
                } => {
                    let avail = (self.pending.len() - cur) as u64;
                    let n = avail.min(total);
                    let r = n.min(real);
                    if r > 0 {
                        let room = (META_CAP as usize).saturating_sub(buf.len());
                        let take = (r as usize).min(room);
                        buf.extend_from_slice(&self.pending[cur..cur + take]);
                    }
                    cur += n as usize;
                    real -= r;
                    total -= n;
                    if total == 0 {
                        match kind {
                            MetaKind::Pax => {
                                if let Some(p) = pax_path(&buf) {
                                    self.next_path = Some(p);
                                }
                            }
                            MetaKind::LongName => {
                                let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                                self.next_path =
                                    Some(String::from_utf8_lossy(&buf[..end]).into_owned());
                            }
                            MetaKind::PaxGlobal => {}
                        }
                        self.state = State::Header;
                        continue;
                    }
                    self.state = State::Meta {
                        kind,
                        buf,
                        real,
                        total,
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
        assert_eq!(pax_path(huge.as_bytes()), None);
        let also_huge = b"99999999999999999999 path=/x\n"; // > u64::MAX: parse fails
        assert_eq!(pax_path(also_huge), None);
        // a well-formed record still parses (length is self-inclusive)
        assert_eq!(
            pax_path(b"15 path=/a/b/c\n").as_deref(),
            Some("/a/b/c"),
            "sanity: valid record"
        );
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
        assert_eq!(
            classify("./root/crashes_and_spins/Panics/panic-full.ips"),
            Some(ArtifactKind::CrashLog)
        );
        assert_eq!(classify("root/ps.txt"), Some(ArtifactKind::PsListing));
        assert_eq!(classify("root/otherdir/x.ips"), None);
        // component boundary: a lookalike directory must not qualify
        assert_eq!(classify("root/notcrashes_and_spins/x.ips"), None);
        assert_eq!(classify("root/sysdiagnose.log"), None);
        // AppleDouble companions must be ignored even when the suffix matches
        assert_eq!(classify("root/crashes_and_spins/._bh-2026.ips"), None);
        assert_eq!(classify("root/._ps.txt"), None);
    }
}
