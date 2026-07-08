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

pub fn classify(path: &str) -> Option<ArtifactKind> {
    let p = path.trim_start_matches("./");
    let base = p.rsplit('/').next().unwrap_or(p);
    // AppleDouble metadata companions ("._foo.ips") appear in archives that
    // passed through a Mac; they are resource forks, not artifacts.
    if base.starts_with("._") {
        return None;
    }
    if base == "shutdown.log" {
        return Some(ArtifactKind::ShutdownLog);
    }
    if p.contains("crashes_and_spins/") && base.ends_with(".ips") {
        return Some(ArtifactKind::CrashLog);
    }
    if base == "ps.txt" || base == "ps_thread.txt" {
        return Some(ArtifactKind::PsListing);
    }
    None
}

pub struct CollectedFile {
    pub path: String,
    pub kind: ArtifactKind,
    pub data: Vec<u8>,
    pub truncated: bool,
}

/// Individual retained files are small (shutdown.log and .ips crash logs are
/// kilobytes); the cap is a guardrail against a hostile archive.
const FILE_CAP: usize = 32 * 1024 * 1024;
const META_CAP: u64 = 1024 * 1024;

enum State {
    Header,
    Data {
        keep: Option<(String, ArtifactKind)>,
        buf: Vec<u8>,
        real: u64,
        total: u64,
        truncated: bool,
    },
    Meta {
        kind: MetaKind,
        buf: Vec<u8>,
        cap: u64,
        real: u64,
        total: u64,
    },
    Done,
}

#[derive(PartialEq)]
enum MetaKind {
    Pax,
    PaxGlobal,
    LongName,
}

pub struct TarCollector {
    pending: Vec<u8>,
    state: State,
    next_path: Option<String>,
    pub files: Vec<CollectedFile>,
    pub entries: u64,
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
        if len == 0 || i + len > data.len() {
            return None;
        }
        let rec = std::str::from_utf8(&data[sp + 1..i + len]).ok()?;
        let rec = rec.strip_suffix('\n').unwrap_or(rec);
        if let Some(v) = rec.strip_prefix("path=") {
            return Some(v.to_string());
        }
        i += len;
    }
    None
}

impl TarCollector {
    pub fn new() -> Self {
        TarCollector {
            pending: Vec::new(),
            state: State::Header,
            next_path: None,
            files: Vec::new(),
            entries: 0,
            zero_blocks: 0,
        }
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
                    let total = size.div_ceil(512) * 512;
                    cur += 512;

                    match typeflag {
                        b'0' | 0 | b'7' => {
                            self.entries += 1;
                            let keep = classify(&path).map(|k| (path, k));
                            if total == 0 {
                                if let Some((p, k)) = keep {
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
                                    cap: META_CAP,
                                    real: size,
                                    total,
                                };
                            }
                        }
                        _ => {
                            // Directories, links, and unknown types: skip payload.
                            if total > 0 {
                                self.state = State::Data {
                                    keep: None,
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
                    if keep.is_some() && r > 0 {
                        let room = FILE_CAP.saturating_sub(buf.len());
                        let take = (r as usize).min(room);
                        buf.extend_from_slice(&self.pending[cur..cur + take]);
                        if take < r as usize {
                            truncated = true;
                        }
                    }
                    cur += n as usize;
                    real -= r;
                    total -= n;
                    if total == 0 {
                        if let Some((p, k)) = keep {
                            self.files.push(CollectedFile {
                                path: p,
                                kind: k,
                                data: buf,
                                truncated,
                            });
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
                    cap,
                    mut real,
                    mut total,
                } => {
                    let avail = (self.pending.len() - cur) as u64;
                    let n = avail.min(total);
                    let r = n.min(real);
                    if r > 0 {
                        let room = (cap as usize).saturating_sub(buf.len());
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
                        cap,
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
        let mut col = TarCollector::new();
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
    fn classify_paths() {
        assert_eq!(
            classify("root/system_logs.logarchive/Extra/shutdown.log"),
            Some(ArtifactKind::ShutdownLog)
        );
        assert_eq!(
            classify("./root/crashes_and_spins/Panics/panic-full.ips"),
            Some(ArtifactKind::CrashLog)
        );
        assert_eq!(classify("root/ps.txt"), Some(ArtifactKind::PsListing));
        assert_eq!(classify("root/otherdir/x.ips"), None);
        assert_eq!(classify("root/sysdiagnose.log"), None);
        // AppleDouble companions must be ignored even when the suffix matches
        assert_eq!(classify("root/crashes_and_spins/._bh-2026.ips"), None);
        assert_eq!(classify("root/._ps.txt"), None);
    }
}
