use regex_lite::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IocKind {
    ProcessName,
    FileName,
    FilePath,
    FileHash,
    Domain,
    Url,
    Email,
    Ip,
    Other,
}

pub fn kind_label(kind: IocKind) -> &'static str {
    match kind {
        IocKind::ProcessName => "process_name",
        IocKind::FileName => "file_name",
        IocKind::FilePath => "file_path",
        IocKind::FileHash => "file_hash",
        IocKind::Domain => "domain",
        IocKind::Url => "url",
        IocKind::Email => "email",
        IocKind::Ip => "ip",
        IocKind::Other => "other",
    }
}

pub struct Indicator {
    pub kind: IocKind,
    /// Lowercased for case-insensitive matching.
    pub value: String,
    pub set: String,
    pub campaign: String,
}

#[derive(Serialize, Clone)]
pub struct SetStats {
    pub name: String,
    pub campaign: String,
    pub stix_indicators: usize,
    pub extracted: usize,
    pub by_kind: HashMap<String, usize>,
    /// Indicators that can actually be checked against v1 artifacts
    /// (process names, file names/paths). Domains, URLs, emails cannot.
    pub applicable: usize,
}

#[derive(Default)]
pub struct IocDb {
    all: Vec<Indicator>,
    by_name: HashMap<String, Vec<usize>>,
    by_path: HashMap<String, Vec<usize>>,
    pub sets: Vec<SetStats>,
}

pub fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// Extracts comparison clauses like `[process:name = 'bh']` from a STIX2
/// pattern string. Handles quoted fields such as `file:hashes.'SHA-256'`.
fn clause_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"([a-z0-9-]+):((?:[A-Za-z0-9_.-]|'[^']*')+)\s*=\s*'([^']*)'").unwrap()
    })
}

fn kind_of(obj_type: &str, field: &str) -> IocKind {
    match obj_type {
        "process" => IocKind::ProcessName,
        "file" => {
            if field.starts_with("hashes") {
                IocKind::FileHash
            } else if field == "path" {
                IocKind::FilePath
            } else {
                IocKind::FileName
            }
        }
        "domain-name" => IocKind::Domain,
        "url" => IocKind::Url,
        "email-addr" => IocKind::Email,
        "ipv4-addr" | "ipv6-addr" => IocKind::Ip,
        _ => IocKind::Other,
    }
}

impl IocDb {
    pub fn new() -> Self {
        IocDb::default()
    }

    pub fn total(&self) -> usize {
        self.all.len()
    }

    pub fn applicable_total(&self) -> usize {
        self.sets.iter().map(|s| s.applicable).sum()
    }

    pub fn load_stix(&mut self, set_name: &str, json: &str) -> Result<SetStats, String> {
        let v: serde_json::Value =
            serde_json::from_str(json).map_err(|e| format!("invalid STIX JSON: {e}"))?;
        let objects = v
            .get("objects")
            .and_then(|o| o.as_array())
            .ok_or("STIX bundle has no 'objects' array")?;

        let campaign = objects
            .iter()
            .find(|o| o.get("type").and_then(|t| t.as_str()) == Some("malware"))
            .and_then(|o| o.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or(set_name)
            .to_string();

        let mut stats = SetStats {
            name: set_name.into(),
            campaign: campaign.clone(),
            stix_indicators: 0,
            extracted: 0,
            by_kind: HashMap::new(),
            applicable: 0,
        };

        for obj in objects {
            if obj.get("type").and_then(|t| t.as_str()) != Some("indicator") {
                continue;
            }
            stats.stix_indicators += 1;
            let Some(pattern) = obj.get("pattern").and_then(|p| p.as_str()) else {
                continue;
            };
            // A pattern joining clauses with AND (or sequencing them with
            // FOLLOWEDBY) only matches when every clause holds. Extracting a
            // single clause from one would let a partial condition claim a
            // full indicator match, so such patterns are skipped rather than
            // half-checked. The check is token-based so a multi-line or
            // tab-separated pattern cannot smuggle an AND past it. The
            // bundled Amnesty sets contain none; OR-joined clauses are safe
            // to split and are handled below.
            if pattern.split_whitespace().any(|t| t == "AND") || pattern.contains("FOLLOWEDBY") {
                continue;
            }
            for cap in clause_re().captures_iter(pattern) {
                let kind = kind_of(&cap[1], &cap[2]);
                let value = cap[3].trim().to_lowercase();
                if value.is_empty() {
                    continue;
                }
                stats.extracted += 1;
                *stats
                    .by_kind
                    .entry(kind_label(kind).to_string())
                    .or_default() += 1;

                let idx = self.all.len();
                match kind {
                    IocKind::ProcessName | IocKind::FileName => {
                        self.by_name.entry(value.clone()).or_default().push(idx);
                        stats.applicable += 1;
                    }
                    IocKind::FilePath => {
                        self.by_path.entry(value.clone()).or_default().push(idx);
                        stats.applicable += 1;
                    }
                    _ => {}
                }
                self.all.push(Indicator {
                    kind,
                    value,
                    set: set_name.into(),
                    campaign: campaign.clone(),
                });
            }
        }

        self.sets.push(stats.clone());
        Ok(stats)
    }

    /// Matches a process name or full path against loaded indicators.
    /// Exact, case-insensitive equality on the basename (against process/file
    /// name indicators) and on the full path (against file path indicators) -
    /// deliberately no substring matching, to keep false positives out.
    pub fn match_process(&self, raw: &str) -> Vec<&Indicator> {
        let full = raw.trim().to_lowercase();
        if full.is_empty() {
            return vec![];
        }
        let base = basename(&full);
        let mut idxs: Vec<usize> = Vec::new();
        if let Some(v) = self.by_name.get(base) {
            idxs.extend(v);
        }
        if full != base {
            if let Some(v) = self.by_path.get(&full) {
                idxs.extend(v);
            }
        }
        idxs.sort_unstable();
        idxs.dedup();
        idxs.into_iter().map(|i| &self.all[i]).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINI_STIX: &str = r#"{
      "type": "bundle",
      "objects": [
        {"type": "malware", "name": "Pegasus"},
        {"type": "indicator", "pattern": "[process:name='bh']"},
        {"type": "indicator", "pattern": "[process:name = 'msgacntd']"},
        {"type": "indicator", "pattern": "[file:name='roleaccountd.plist']"},
        {"type": "indicator", "pattern": "[domain-name:value='example-bad.com']"},
        {"type": "indicator", "pattern": "[file:hashes.'SHA-256' = 'abc123']"}
      ]
    }"#;

    #[test]
    fn parses_stix_and_classifies_kinds() {
        let mut db = IocDb::new();
        let stats = db.load_stix("test-set", MINI_STIX).unwrap();
        assert_eq!(stats.campaign, "Pegasus");
        assert_eq!(stats.stix_indicators, 5);
        assert_eq!(stats.extracted, 5);
        assert_eq!(stats.by_kind["process_name"], 2);
        assert_eq!(stats.by_kind["domain"], 1);
        assert_eq!(stats.by_kind["file_hash"], 1);
        assert_eq!(stats.applicable, 3); // 2 process names + 1 file name
    }

    #[test]
    fn and_joined_patterns_are_skipped_not_half_checked() {
        let mut db = IocDb::new();
        let stats = db
            .load_stix(
                "t",
                r#"{"objects":[
                    {"type":"indicator","pattern":"[process:name='safe' AND file:hashes.'SHA-256'='abc']"},
                    {"type":"indicator","pattern":"[process:name='alone']"}
                ]}"#,
            )
            .unwrap();
        assert_eq!(stats.stix_indicators, 2);
        assert_eq!(stats.extracted, 1, "only the single-clause pattern counts");
        // matching one clause of an AND must never claim the full indicator
        assert!(db.match_process("safe").is_empty());
        assert_eq!(db.match_process("alone").len(), 1);
    }

    #[test]
    fn multiline_and_patterns_are_also_skipped() {
        // AND separated by newlines or tabs instead of spaces must be caught
        // by the token-based check, not slip through a literal " AND " match.
        let mut db = IocDb::new();
        let stats = db
            .load_stix(
                "t",
                "{\"objects\":[
                    {\"type\":\"indicator\",\"pattern\":\"[process:name='safe'\\nAND\\nfile:hashes.'SHA-256'='abc']\"},
                    {\"type\":\"indicator\",\"pattern\":\"[process:name='tabbed'\\tAND\\tfile:name='x']\"}
                ]}",
            )
            .unwrap();
        assert_eq!(stats.extracted, 0, "no clause of an AND pattern extracts");
        assert!(db.match_process("safe").is_empty());
        assert!(db.match_process("tabbed").is_empty());
    }

    #[test]
    fn matches_basename_case_insensitively() {
        let mut db = IocDb::new();
        db.load_stix("test-set", MINI_STIX).unwrap();
        assert_eq!(db.match_process("BH").len(), 1);
        assert_eq!(db.match_process("/usr/sbin/bh").len(), 1);
        assert_eq!(
            db.match_process("/private/var/db/com.apple.xpc.roleaccountd.staging/msgacntd")
                .len(),
            1
        );
        // no substring matching: "bh2" must not hit "bh"
        assert!(db.match_process("bh2").is_empty());
        assert!(db.match_process("/usr/libexec/nfcd").is_empty());
    }
}
