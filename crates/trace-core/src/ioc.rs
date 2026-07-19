use serde::Serialize;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};

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
    /// Kept exactly as published. Matching is case-sensitive: Amnesty's
    /// Pegasus set deliberately distinguishes 'Diagnosticd' (implant) from
    /// Apple's legitimate lowercase 'diagnosticd', and MVT compares names
    /// case-sensitively. Case-folding here collapsed exactly that
    /// distinction into a guaranteed false positive.
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
    /// Lexically ordered so report JSON is stable across processes and
    /// producers instead of inheriting `HashMap`'s randomized iteration order.
    pub by_kind: BTreeMap<String, usize>,
    /// Indicators that contribute to negative-result coverage over the
    /// process-bearing artifacts Trace examines: process names plus reviewed
    /// file paths known to name process images. Other safe file indicators
    /// remain indexed for unexpected exact positive matches but cannot make a
    /// no-match result more conclusive.
    pub applicable: usize,
}

#[derive(Default)]
pub struct IocDb {
    all: Vec<Indicator>,
    by_name: HashMap<String, Vec<usize>>,
    by_path: HashMap<String, Vec<usize>>,
    /// file:path indicators published with a trailing slash name a
    /// directory, not a file ('/private/var/tmp/l/'). Exact equality can
    /// never match them against an observed process path, so they match as
    /// path prefixes instead. A handful exist across the bundled sets, so a
    /// linear scan is fine.
    by_dir: Vec<(String, usize)>,
    pub sets: Vec<SetStats>,
}

pub fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// Cursor for the deliberately small STIX pattern subset Trace supports.
/// A regex is not sufficient here: it can extract a convincing-looking
/// clause from a malformed pattern, a comment, or a different pattern
/// language. This parser consumes the entire pattern and accepts exactly one
/// equality comparison whose right-hand side is a STIX string literal.
struct PatternCursor<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> PatternCursor<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn peek(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        Some(c)
    }

    fn take(&mut self, expected: char) -> bool {
        if self.peek() != Some(expected) {
            return false;
        }
        self.bump();
        true
    }

    fn skip_ws(&mut self) {
        while self.peek().is_some_and(char::is_whitespace) {
            self.bump();
        }
    }

    fn identifier(&mut self, allow_hyphen: bool) -> Option<String> {
        let start = self.pos;
        let first = self.peek()?;
        if !(first.is_ascii_alphabetic() || first == '_') {
            return None;
        }
        self.bump();
        while self
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || (allow_hyphen && c == '-'))
        {
            self.bump();
        }
        Some(self.input[start..self.pos].to_string())
    }

    /// Parse and unescape a STIX string literal. STIX permits only escaped
    /// quote and escaped backslash in this literal form; accepting unknown
    /// escapes would silently change the published indicator value.
    fn string_literal(&mut self) -> Option<String> {
        if !self.take('\'') {
            return None;
        }
        let mut value = String::new();
        loop {
            match self.bump()? {
                '\'' => return Some(value),
                '\\' => match self.bump()? {
                    '\'' => value.push('\''),
                    '\\' => value.push('\\'),
                    _ => return None,
                },
                c => value.push(c),
            }
        }
    }

    fn path_component(&mut self) -> Option<String> {
        if self.peek() == Some('\'') {
            self.string_literal()
        } else {
            self.identifier(false)
        }
    }
}

/// Parse one fully anchored STIX equality clause. Boolean/observation
/// operators, comments, qualifiers, unsupported comparison operators, and
/// trailing text all make the pattern inapplicable rather than letting a
/// partial condition become an IOC match.
fn parse_single_equality(pattern: &str) -> Option<(String, Vec<String>, String)> {
    let mut p = PatternCursor::new(pattern);
    p.skip_ws();
    if !p.take('[') {
        return None;
    }
    p.skip_ws();
    let object_type = p.identifier(true)?;
    p.skip_ws();
    if !p.take(':') {
        return None;
    }
    p.skip_ws();
    // The first property is an identifier (`file:hashes`); quoted map keys
    // are valid only after a dot (`file:hashes.'SHA-256'`). Accepting a
    // quoted first property would turn malformed patterns such as
    // `process:'name'` into applicable name indicators.
    let mut field = vec![p.identifier(false)?];
    loop {
        p.skip_ws();
        if !p.take('.') {
            break;
        }
        p.skip_ws();
        field.push(p.path_component()?);
    }
    p.skip_ws();
    if !p.take('=') {
        return None;
    }
    p.skip_ws();
    let value = p.string_literal()?;
    p.skip_ws();
    if !p.take(']') {
        return None;
    }
    p.skip_ws();
    if p.peek().is_some() {
        return None;
    }
    Some((object_type, field, value))
}

fn is_field(field: &[String], expected: &str) -> bool {
    field.len() == 1 && field[0] == expected
}

fn kind_of(object_type: &str, field: &[String]) -> IocKind {
    match object_type {
        "process" if is_field(field, "name") => IocKind::ProcessName,
        "file" if is_field(field, "name") => IocKind::FileName,
        "file" if is_field(field, "path") => IocKind::FilePath,
        "file" if field.len() == 2 && field.first().is_some_and(|v| v == "hashes") => {
            IocKind::FileHash
        }
        "domain-name" if is_field(field, "value") => IocKind::Domain,
        "url" if is_field(field, "value") => IocKind::Url,
        "email-addr" if is_field(field, "value") => IocKind::Email,
        "ipv4-addr" | "ipv6-addr" if is_field(field, "value") => IocKind::Ip,
        _ => IocKind::Other,
    }
}

/// True for an absolute path whose components are all non-empty and free of
/// `.`/`..` segments - the shape safe to compare against path indicators.
/// Shared with the unified-log resolver so the matching-safety predicate has
/// one definition.
pub(crate) fn is_canonical_observed_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() > 1
        && path[1..]
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}

/// Resolve the stable, well-known Darwin compatibility aliases used in
/// diagnostics. IOC values stay exactly as published for evidence and report
/// provenance; only the internal comparison key uses the `/private` spelling.
/// Requiring either equality or a following slash keeps lookalike components
/// such as `/variable`, `/tmp-old`, and `/etcetera` distinct.
fn apple_alias_comparison_path(path: &str) -> Cow<'_, str> {
    for (alias, canonical) in [
        ("/var", "/private/var"),
        ("/tmp", "/private/tmp"),
        ("/etc", "/private/etc"),
    ] {
        if let Some(suffix) = path.strip_prefix(alias) {
            if suffix.is_empty() || suffix.starts_with('/') {
                return Cow::Owned(format!("{canonical}{suffix}"));
            }
        }
    }
    Cow::Borrowed(path)
}

/// STIX `file:name` and `file:path` do not say whether a value names a process
/// main image or an inert file-system artifact. Keep every syntactically safe
/// value available for an exact positive match, but count only file paths
/// explicitly reviewed as observable through Trace's process-bearing surfaces
/// toward negative-result coverage.
fn is_reviewed_process_observable_file(set_name: &str, kind: IocKind, value: &str) -> bool {
    matches!(
        (set_name, kind, value),
        (
            "predator",
            IocKind::FilePath,
            "/private/var/tmp/hooker"
                | "/private/var/tmp/com.apple.WebKit.Networking"
                | "/private/var/tmp/UserEventAgent"
                | "/private/var/tmp/takePhoto"
        ) | (
            "kingspawn",
            IocKind::FilePath,
            "/private/var/db/com.apple.xpc.roleaccountd.staging/subridged"
                | "/private/var/db/com.apple.xpc.roleaccountd.staging/PlugIns/fud.appex/"
        )
    )
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
            by_kind: BTreeMap::new(),
            applicable: 0,
        };
        // A bundle can contain multiple STIX objects that encode the same
        // observable. Count and index the unique published value once per
        // set so duplicate objects cannot pad the reviewed floor or multiply
        // identical findings in a report.
        let mut extracted_in_set: HashSet<(String, Vec<String>, String)> = HashSet::new();

        for obj in objects {
            if obj.get("type").and_then(|t| t.as_str()) != Some("indicator") {
                continue;
            }
            stats.stix_indicators += 1;
            // Missing pattern_type is accepted for older/minimal bundles, but
            // an explicitly different (or malformed) type is another pattern
            // language and must never be interpreted as STIX.
            if obj
                .get("pattern_type")
                .is_some_and(|p| p.as_str() != Some("stix"))
            {
                continue;
            }
            let Some(pattern) = obj.get("pattern").and_then(|p| p.as_str()) else {
                continue;
            };
            let Some((object_type, field, value)) = parse_single_equality(pattern) else {
                continue;
            };
            if value.trim().is_empty() {
                continue;
            }
            if !extracted_in_set.insert((object_type.clone(), field.clone(), value.clone())) {
                continue;
            }
            let kind = kind_of(&object_type, &field);
            stats.extracted += 1;
            *stats
                .by_kind
                .entry(kind_label(kind).to_string())
                .or_default() += 1;

            let idx = self.all.len();
            match kind {
                IocKind::ProcessName if !value.contains('/') => {
                    self.by_name.entry(value.clone()).or_default().push(idx);
                    stats.applicable += 1;
                }
                IocKind::FileName if !value.contains('/') => {
                    self.by_name.entry(value.clone()).or_default().push(idx);
                    if is_reviewed_process_observable_file(set_name, kind, &value) {
                        stats.applicable += 1;
                    }
                }
                // Slash-bearing values claim path structure, but name
                // indicators can only be checked against an observed basename.
                // Keep them in extraction accounting without overstating the
                // number of indicators this scanner can actually evaluate.
                IocKind::ProcessName | IocKind::FileName => {}
                // A trailing slash names a directory: match as a path
                // prefix. A relative or dot-segment path cannot be checked
                // safely against the absolute process paths Trace observes,
                // so it is recorded but not applicable.
                IocKind::FilePath
                    if value
                        .strip_suffix('/')
                        .is_some_and(is_canonical_observed_path) =>
                {
                    self.by_dir
                        .push((apple_alias_comparison_path(&value).into_owned(), idx));
                    if is_reviewed_process_observable_file(set_name, kind, &value) {
                        stats.applicable += 1;
                    }
                }
                IocKind::FilePath if is_canonical_observed_path(&value) => {
                    self.by_path
                        .entry(apple_alias_comparison_path(&value).into_owned())
                        .or_default()
                        .push(idx);
                    if is_reviewed_process_observable_file(set_name, kind, &value) {
                        stats.applicable += 1;
                    }
                }
                IocKind::FilePath => {}
                _ => {}
            }
            self.all.push(Indicator {
                kind,
                value,
                set: set_name.into(),
                campaign: campaign.clone(),
            });
        }

        self.sets.push(stats.clone());
        Ok(stats)
    }

    fn path_indices(&self, full: &str) -> Vec<usize> {
        let mut idxs: Vec<usize> = Vec::new();
        if !is_canonical_observed_path(full) {
            return idxs;
        }
        let comparison_path = apple_alias_comparison_path(full);
        if let Some(v) = self.by_path.get(comparison_path.as_ref()) {
            idxs.extend(v);
        }
        for (dir, idx) in &self.by_dir {
            if comparison_path.len() > dir.len() && comparison_path.starts_with(dir.as_str()) {
                idxs.push(*idx);
            }
        }
        idxs.sort_unstable();
        idxs.dedup();
        idxs
    }

    fn indicators(&self, mut idxs: Vec<usize>) -> Vec<&Indicator> {
        idxs.sort_unstable();
        idxs.dedup();
        idxs.into_iter().map(|i| &self.all[i]).collect()
    }

    /// Matches only full file paths, resolving the well-known Apple
    /// `/var`/`/tmp`/`/etc` aliases for comparison. This intentionally does
    /// not consult process/file-name indicators, so a caller handling an
    /// ambiguous full command line cannot turn the basename of a path
    /// argument into an IOC match. Dot-segment paths are rejected rather than
    /// lexically matching a directory prefix they ultimately escape.
    pub fn match_path(&self, raw: &str) -> Vec<&Indicator> {
        if raw.is_empty() {
            return vec![];
        }
        self.indicators(self.path_indices(raw))
    }

    /// Matches a process name or full path against loaded indicators.
    /// Exact, case-sensitive equality on the basename (against process/file
    /// name indicators) and on the alias-resolved full path (against file path
    /// indicators), plus prefix matching for directory-valued path indicators
    /// - deliberately no substring matching, to keep false positives out.
    ///
    /// Case-sensitivity mirrors MVT: published sets use capitalization to
    /// tell an implant apart from the legitimate daemon it masquerades as.
    pub fn match_process(&self, raw: &str) -> Vec<&Indicator> {
        let full = raw;
        if full.is_empty() {
            return vec![];
        }
        // A slash-bearing identity is claiming to be a process path. Reject
        // relative, empty-component, and dot-segment spellings before using
        // its basename; otherwise `/safe/../bh` could match a name IOC even
        // though the path's actual target was never established.
        if full.contains('/') && !is_canonical_observed_path(full) {
            return vec![];
        }
        let base = basename(full);
        let mut idxs = self.path_indices(full);
        if let Some(v) = self.by_name.get(base) {
            idxs.extend(v);
        }
        self.indicators(idxs)
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

    fn db_with_path_indicator(path: &str) -> IocDb {
        let bundle = serde_json::json!({
            "objects": [{
                "type": "indicator",
                "pattern": format!("[file:path='{path}']")
            }]
        })
        .to_string();
        let mut db = IocDb::new();
        db.load_stix("alias-test", &bundle).unwrap();
        db
    }

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
        assert_eq!(stats.applicable, 2); // process-observable names accepted for negative coverage
    }

    #[test]
    fn kind_counts_serialize_deterministically() {
        let mut db = IocDb::new();
        let stats = db.load_stix("test-set", MINI_STIX).unwrap();
        assert_eq!(
            serde_json::to_string(&stats.by_kind).unwrap(),
            r#"{"domain":1,"file_hash":1,"file_name":1,"process_name":2}"#
        );
    }

    #[test]
    fn duplicate_stix_values_are_counted_and_matched_once_per_set() {
        let mut db = IocDb::new();
        let stats = db
            .load_stix(
                "t",
                r#"{"objects":[
                    {"type":"indicator","id":"indicator--one","pattern":"[process:name='bh']"},
                    {"type":"indicator","id":"indicator--two","pattern":"[process:name='bh']"}
                ]}"#,
            )
            .unwrap();

        assert_eq!(stats.stix_indicators, 2, "raw STIX records stay auditable");
        assert_eq!(stats.extracted, 1);
        assert_eq!(stats.applicable, 1);
        assert_eq!(db.total(), 1);
        assert_eq!(db.match_process("bh").len(), 1);
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
    fn matches_basename_case_sensitively() {
        let mut db = IocDb::new();
        db.load_stix("test-set", MINI_STIX).unwrap();
        assert_eq!(db.match_process("bh").len(), 1);
        assert_eq!(db.match_process("/usr/sbin/bh").len(), 1);
        assert_eq!(
            db.match_process("/private/var/db/com.apple.xpc.roleaccountd.staging/msgacntd")
                .len(),
            1
        );
        // no substring matching: "bh2" must not hit "bh"
        assert!(db.match_process("bh2").is_empty());
        assert!(db.match_process("/usr/libexec/nfcd").is_empty());
        // case-sensitive, like MVT: a different capitalization is a
        // different name, not a match
        assert!(db.match_process("BH").is_empty());
        assert!(db.match_process("Bh").is_empty());
        assert!(
            db.match_process(" bh ").is_empty(),
            "observed identity whitespace must not be normalized into an IOC"
        );
        for ambiguous in [
            "/safe/../bh",
            "/safe/./bh",
            "/safe//bh",
            "/safe/bh/",
            "relative/bh",
        ] {
            assert!(
                db.match_process(ambiguous).is_empty(),
                "ambiguous observed path matched: {ambiguous}"
            );
        }
    }

    #[test]
    fn capitalized_indicator_does_not_match_legitimate_lowercase_daemon() {
        // Amnesty's Pegasus set lists 'Diagnosticd' (capital D) precisely
        // because the implant is spelled differently from Apple's
        // /usr/libexec/diagnosticd. The legitimate daemon must never match.
        let mut db = IocDb::new();
        db.load_stix(
            "t",
            r#"{"objects":[{"type":"malware","name":"Pegasus"},{"type":"indicator","pattern":"[process:name='Diagnosticd']"}]}"#,
        )
        .unwrap();
        assert!(db.match_process("/usr/libexec/diagnosticd").is_empty());
        assert!(db.match_process("diagnosticd").is_empty());
        assert_eq!(db.match_process("Diagnosticd").len(), 1);
    }

    #[test]
    fn directory_indicator_matches_paths_under_it() {
        // Predator publishes '/private/var/tmp/l/' - a directory. A payload
        // running from inside it must match; equality alone never could.
        let mut db = IocDb::new();
        let stats = db
            .load_stix(
                "t",
                r#"{"objects":[{"type":"malware","name":"Predator"},{"type":"indicator","pattern":"[file:path='/private/var/tmp/l/']"}]}"#,
            )
            .unwrap();
        assert_eq!(stats.applicable, 0);
        assert_eq!(db.match_process("/private/var/tmp/l/loader").len(), 1);
        assert_eq!(db.match_process("/private/var/tmp/l/a/b").len(), 1);
        assert_eq!(db.match_path("/private/var/tmp/l/loader").len(), 1);
        // the directory itself, a sibling, and a prefix-lookalike do not match
        assert!(db.match_process("/private/var/tmp/l/").is_empty());
        assert!(db.match_process("/private/var/tmp/lx/loader").is_empty());
        assert!(db.match_process("/private/var/tmp/l").is_empty());
    }

    #[test]
    fn apple_path_aliases_match_exact_indicators_bidirectionally() {
        for (short, private) in [
            ("/var/tmp/trace-alias", "/private/var/tmp/trace-alias"),
            ("/tmp/trace-alias", "/private/tmp/trace-alias"),
            ("/etc/trace-alias.conf", "/private/etc/trace-alias.conf"),
        ] {
            let short_db = db_with_path_indicator(short);
            let matched = short_db.match_path(private);
            assert_eq!(matched.len(), 1, "published {short}, observed {private}");
            assert_eq!(matched[0].value, short, "published value must stay raw");

            let private_db = db_with_path_indicator(private);
            let matched = private_db.match_process(short);
            assert_eq!(matched.len(), 1, "published {private}, observed {short}");
            assert_eq!(matched[0].value, private, "published value must stay raw");
        }
    }

    #[test]
    fn apple_path_aliases_match_directory_indicators_bidirectionally() {
        for (short, private) in [
            ("/var/tmp/trace-dir/", "/private/var/tmp/trace-dir/"),
            ("/tmp/trace-dir/", "/private/tmp/trace-dir/"),
            ("/etc/trace-dir/", "/private/etc/trace-dir/"),
        ] {
            let private_child = format!("{private}payload");
            let short_db = db_with_path_indicator(short);
            let matched = short_db.match_path(&private_child);
            assert_eq!(
                matched.len(),
                1,
                "published {short}, observed {private_child}"
            );
            assert_eq!(matched[0].value, short, "published value must stay raw");

            let short_child = format!("{short}payload");
            let private_db = db_with_path_indicator(private);
            let matched = private_db.match_process(&short_child);
            assert_eq!(
                matched.len(),
                1,
                "published {private}, observed {short_child}"
            );
            assert_eq!(matched[0].value, private, "published value must stay raw");
        }
    }

    #[test]
    fn apple_path_aliases_require_component_boundaries() {
        for (published, observed) in [
            ("/private/variable/payload", "/variable/payload"),
            ("/private/tmp-old/payload", "/tmp-old/payload"),
            ("/private/etcetera/payload", "/etcetera/payload"),
        ] {
            assert!(
                db_with_path_indicator(published)
                    .match_path(observed)
                    .is_empty(),
                "lookalike alias component matched: {observed}"
            );
        }

        let directory_db = db_with_path_indicator("/private/var/tmp/trace-dir/");
        assert!(directory_db
            .match_path("/var/tmp/trace-directory/payload")
            .is_empty());
        assert!(directory_db.match_path("/var/tmp/trace-dir").is_empty());
    }

    #[test]
    fn relative_path_indicator_is_recorded_but_not_applicable() {
        // A backup-artifact relative path can never equal an observed
        // process path or basename; counting it as checkable would
        // overstate what this scan examined.
        let mut db = IocDb::new();
        let stats = db
            .load_stix(
                "t",
                r#"{"objects":[{"type":"indicator","pattern":"[file:path='Library/Preferences/com.apple.photolibraryd.plist']"}]}"#,
            )
            .unwrap();
        assert_eq!(stats.extracted, 1);
        assert_eq!(stats.applicable, 0);
    }

    #[test]
    fn noncanonical_absolute_path_indicators_are_not_applicable() {
        let mut db = IocDb::new();
        let stats = db
            .load_stix(
                "t",
                r#"{"objects":[
                    {"type":"indicator","pattern":"[file:path='/tmp//payload']"},
                    {"type":"indicator","pattern":"[file:path='/tmp//']"},
                    {"type":"indicator","pattern":"[file:path='/tmp/./payload']"}
                ]}"#,
            )
            .unwrap();
        assert_eq!(stats.extracted, 3);
        assert_eq!(stats.applicable, 0);
        assert!(db.match_path("/tmp//payload").is_empty());
        assert!(db.match_path("/tmp/./payload").is_empty());
    }

    #[test]
    fn slash_bearing_name_indicators_are_not_applicable() {
        let mut db = IocDb::new();
        let stats = db
            .load_stix(
                "t",
                r#"{"objects":[
                    {"type":"indicator","pattern":"[process:name='foo/bar']"},
                    {"type":"indicator","pattern":"[file:name='/tmp/payload']"}
                ]}"#,
            )
            .unwrap();
        assert_eq!(stats.extracted, 2);
        assert_eq!(stats.applicable, 0);
        assert_eq!(db.total(), 2);
        assert!(db.match_process("/foo/bar").is_empty());
        assert!(db.match_process("/tmp/payload").is_empty());
    }

    #[test]
    fn only_supported_object_fields_are_classified_as_names() {
        let mut db = IocDb::new();
        let stats = db
            .load_stix(
                "t",
                r#"{"objects":[
                    {"type":"indicator","pattern":"[process:command_line='launchd']"},
                    {"type":"indicator","pattern":"[file:mime_type='launchd']"},
                    {"type":"indicator","pattern":"[file:hashes_extra='launchd']"},
                    {"type":"indicator","pattern":"[file:hashes='launchd']"},
                    {"type":"indicator","pattern":"[file:hashes.'SHA-256'.extra='launchd']"}
                ]}"#,
            )
            .unwrap();
        assert_eq!(stats.extracted, 5);
        assert_eq!(stats.by_kind["other"], 5);
        assert_eq!(stats.applicable, 0);
        assert!(db.match_process("/sbin/launchd").is_empty());
    }

    #[test]
    fn malformed_non_stix_compound_and_qualified_patterns_are_rejected() {
        let mut db = IocDb::new();
        let stats = db
            .load_stix(
                "t",
                r#"{"objects":[
                    {"type":"indicator","pattern":"garbage process:name='bad'"},
                    {"type":"indicator","pattern":"[process:name='bad'"},
                    {"type":"indicator","pattern":"[process:name='bad'] trailing junk"},
                    {"type":"indicator","pattern":"[process:name='bad'] /* comment */"},
                    {"type":"indicator","pattern":"[domain-name:value='evil'] /* process:name='bad' */"},
                    {"type":"indicator","pattern":"[process:name='bad'] REPEATS 2 TIMES"},
                    {"type":"indicator","pattern":"[process:name='bad'] START t'2020-01-01T00:00:00Z' STOP t'2020-01-02T00:00:00Z'"},
                    {"type":"indicator","pattern":"[process:name='bad' OR process:name='other']"},
                    {"type":"indicator","pattern":"[process:name='bad'AND file:name='x']"},
                    {"type":"indicator","pattern":"[process:name NOT = 'bad']"},
                    {"type":"indicator","pattern":"[process:name != 'bad']"},
                    {"type":"indicator","pattern":"[process:name NOT != 'bad']"},
                    {"type":"indicator","pattern":"[process:name LIKE 'bad']"},
                    {"type":"indicator","pattern":"[process:'name'='bad']"},
                    {"type":"indicator","pattern_type":"yara","pattern":"[process:name='bad']"},
                    {"type":"indicator","pattern_type":7,"pattern":"[process:name='bad']"},
                    {"type":"indicator","pattern_type":"stix","pattern":" [ process : name = 'good' ] "}
                ]}"#,
            )
            .unwrap();
        assert_eq!(stats.stix_indicators, 17);
        assert_eq!(stats.extracted, 1);
        assert_eq!(stats.applicable, 1);
        assert!(db.match_process("bad").is_empty());
        assert!(db.match_process("other").is_empty());
        assert_eq!(db.match_process("good").len(), 1);
    }

    #[test]
    fn stix_string_escapes_are_exact_and_nonstandard_equals_is_rejected() {
        let mut db = IocDb::new();
        let stats = db
            .load_stix(
                "t",
                r#"{"objects":[
                    {"type":"indicator","pattern":"[process:name = 'foo\\'bar\\\\baz']"},
                    {"type":"indicator","pattern":"[process:name=' launchd ']"},
                    {"type":"indicator","pattern":"[process:name == 'not-stix']"},
                    {"type":"indicator","pattern":"[process:name='   ']"}
                ]}"#,
            )
            .unwrap();
        assert_eq!(stats.extracted, 2);
        assert_eq!(stats.applicable, 2);
        assert_eq!(db.all[0].value, r"foo'bar\baz");
        assert_eq!(db.all[1].value, " launchd ");
        assert_eq!(db.match_process(r"foo'bar\baz").len(), 1);
        // Literal whitespace is data, not parser padding; it must not be
        // trimmed into a match for the ordinary daemon name.
        assert!(db.match_process("launchd").is_empty());
        assert!(db.match_process("not-stix").is_empty());
    }

    #[test]
    fn unknown_stix_string_escapes_are_rejected() {
        let mut db = IocDb::new();
        let stats = db
            .load_stix(
                "t",
                r#"{"objects":[
                    {"type":"indicator","pattern":"[process:name='bad\\q']"},
                    {"type":"indicator","pattern":"[process:name='good']"}
                ]}"#,
            )
            .unwrap();
        assert_eq!(stats.extracted, 1);
        assert!(db.match_process("bad\\q").is_empty());
        assert_eq!(db.match_process("good").len(), 1);
    }

    #[test]
    fn path_only_matching_excludes_names_and_dot_segments() {
        let mut db = IocDb::new();
        let stats = db
            .load_stix(
                "t",
                r#"{"objects":[
                    {"type":"indicator","pattern":"[process:name='named']"},
                    {"type":"indicator","pattern":"[file:name='named-file']"},
                    {"type":"indicator","pattern":"[file:path='/private/var/tmp/exact']"},
                    {"type":"indicator","pattern":"[file:path='/private/var/tmp/l/']"},
                    {"type":"indicator","pattern":"[file:path='/private/var/tmp/l/../outside']"}
                ]}"#,
            )
            .unwrap();
        assert_eq!(stats.extracted, 5);
        assert_eq!(stats.applicable, 1);
        assert!(db.match_path("/usr/bin/named").is_empty());
        assert!(db.match_path("/usr/bin/named-file").is_empty());
        assert_eq!(db.match_process("/usr/bin/named").len(), 1);
        assert_eq!(db.match_process("/usr/bin/named-file").len(), 1);
        assert_eq!(db.match_path("/private/var/tmp/exact").len(), 1);
        assert!(db.match_path(" /private/var/tmp/exact").is_empty());
        assert!(db.match_path("/private/var/tmp/exact ").is_empty());
        assert_eq!(db.match_path("/private/var/tmp/l/loader").len(), 1);
        assert!(db.match_path("/private/var/tmp/l/../outside").is_empty());
        assert!(db.match_process("/private/var/tmp/l/../outside").is_empty());
    }

    #[test]
    fn file_indicators_match_exactly_without_padding_negative_coverage() {
        let mut db = IocDb::new();
        let stats = db
            .load_stix(
                "custom",
                r#"{"objects":[
                    {"type":"indicator","pattern":"[file:name='unexpected-payload']"},
                    {"type":"indicator","pattern":"[file:path='/private/var/tmp/unexpected-payload']"}
                ]}"#,
            )
            .unwrap();

        assert_eq!(stats.extracted, 2);
        assert_eq!(stats.applicable, 0);
        assert_eq!(db.match_process("unexpected-payload").len(), 1);
        assert_eq!(
            db.match_path("/private/var/tmp/unexpected-payload").len(),
            1
        );
    }

    #[test]
    fn only_policy_accepted_process_image_paths_count_toward_negative_coverage() {
        let cases = [
            ("predator", "/private/var/tmp/hooker"),
            ("predator", "/private/var/tmp/com.apple.WebKit.Networking"),
            ("predator", "/private/var/tmp/UserEventAgent"),
            ("predator", "/private/var/tmp/takePhoto"),
            (
                "kingspawn",
                "/private/var/db/com.apple.xpc.roleaccountd.staging/subridged",
            ),
            (
                "kingspawn",
                "/private/var/db/com.apple.xpc.roleaccountd.staging/PlugIns/fud.appex/",
            ),
        ];

        for (set_name, path) in cases {
            let mut db = IocDb::new();
            let bundle = serde_json::json!({
                "objects": [{
                    "type": "indicator",
                    "pattern": format!("[file:path='{path}']")
                }]
            })
            .to_string();
            let stats = db.load_stix(set_name, &bundle).unwrap();
            assert_eq!(stats.applicable, 1, "{set_name}: {path}");
        }

        let mut db = IocDb::new();
        let stats = db
            .load_stix(
                "predator",
                r#"{"objects":[{"type":"indicator","pattern":"[file:path='/private/var/tmp/not-reviewed']"}]}"#,
            )
            .unwrap();
        assert_eq!(stats.applicable, 0);
    }

    #[test]
    fn quote_adjacent_and_is_still_a_compound_pattern() {
        // The STIX grammar does not require whitespace after a closing
        // quote: [x='a'AND y='b'] is legal and joins two clauses. Extracting
        // either clause would let a partial condition claim a full match.
        let mut db = IocDb::new();
        let stats = db
            .load_stix(
                "t",
                r#"{"objects":[
                    {"type":"indicator","pattern":"[process:name='chrome'AND file:hashes.'SHA-256'='abc']"},
                    {"type":"indicator","pattern":"[process:name='a'FOLLOWEDBY[process:name='b']]"},
                    {"type":"indicator","pattern":"[process:name='operandi']"},
                    {"type":"indicator","pattern":"[process:name='has AND inside']"}
                ]}"#,
            )
            .unwrap();
        assert_eq!(
            stats.extracted, 2,
            "only the two non-compound patterns extract"
        );
        assert!(db.match_process("chrome").is_empty());
        assert!(db.match_process("a").is_empty());
        // AND inside a quoted value is data, not an operator
        assert_eq!(db.match_process("operandi").len(), 1);
        assert_eq!(db.match_process("has AND inside").len(), 1);
    }
}
