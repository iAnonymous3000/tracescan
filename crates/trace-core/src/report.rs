use crate::ioc::{kind_label, Indicator};
use serde::Serialize;

/// Severity is epistemically descriptive, not a fear scale:
/// - `Match`: a deterministic match against a published indicator: exact for
///   process names, file names, and file paths; canonical descendant matching
///   for directory-valued file-path indicators that end in `/`.
/// - `Suspicious`: an anomaly documented in public research as associated
///   with spyware infections, but not an IOC match by itself.
/// - `Note`: unusual but frequently benign; context for an expert reviewer.
#[derive(Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Note,
    Suspicious,
    Match,
}

#[derive(Serialize, Clone, PartialEq, Eq, Hash)]
pub struct IndicatorRef {
    pub value: String,
    pub kind: String,
    pub set: String,
    pub campaign: String,
}

#[derive(Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub kind: String,
    pub artifact: String,
    pub summary: String,
    pub evidence: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indicator: Option<IndicatorRef>,
}

/// Hard cap on accumulated findings. Real scans produce well under a
/// hundred; only a crafted archive (e.g. a ps.txt whose every line raises a
/// heuristic) approaches this. Findings are retained in WASM memory and
/// serialized into the canonical JSON report (the browser separately caps
/// visible cards), so unbounded growth is a memory exhaustion vector.
pub const MAX_FINDINGS: usize = 5_000;

/// Findings accumulator enforcing [`MAX_FINDINGS`]. Retention is
/// severity-aware: at the cap, a Match evicts a Note (then a Suspicious),
/// and a Suspicious evicts a Note - a flood of informational findings from
/// a crafted archive must never crowd out an actual indicator match, which
/// has to survive and control the verdict. Hitting the cap in any way sets
/// `capped`; the engine surfaces that as a scan limit, so a capped scan can
/// never read as clear.
#[derive(Default)]
pub struct Findings {
    matches: Vec<Finding>,
    suspicious: Vec<Finding>,
    notes: Vec<Finding>,
    pub capped: bool,
}

impl Findings {
    pub fn new() -> Self {
        Findings::default()
    }

    pub fn len(&self) -> usize {
        self.matches.len() + self.suspicious.len() + self.notes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = &Finding> {
        self.matches
            .iter()
            .chain(self.suspicious.iter())
            .chain(self.notes.iter())
    }

    pub fn push(&mut self, f: Finding) {
        if self.len() >= MAX_FINDINGS {
            self.capped = true;
            let evicted = match f.severity {
                Severity::Match => {
                    self.notes.pop().or_else(|| self.suspicious.pop()).is_some()
                        || self.make_room_for_distinct_match(&f)
                }
                Severity::Suspicious => self.notes.pop().is_some(),
                Severity::Note => false,
            };
            if !evicted {
                return;
            }
        }
        match f.severity {
            Severity::Match => self.matches.push(f),
            Severity::Suspicious => self.suspicious.push(f),
            Severity::Note => self.notes.push(f),
        }
    }

    /// Once the cap is occupied entirely by matches, preserve indicator
    /// diversity: a crafted archive can repeat one published indicator
    /// thousands of times, but those duplicates must not crowd out the first
    /// observation of a different indicator encountered later in the scan.
    fn make_room_for_distinct_match(&mut self, incoming: &Finding) -> bool {
        let Some(incoming_indicator) = incoming.indicator.as_ref() else {
            return false;
        };
        if self
            .matches
            .iter()
            .any(|finding| finding.indicator.as_ref() == Some(incoming_indicator))
        {
            return false;
        }

        let mut seen = std::collections::HashSet::with_capacity(self.matches.len());
        let mut duplicate_index = None;
        for (index, finding) in self.matches.iter().enumerate() {
            if let Some(indicator) = finding.indicator.as_ref() {
                if !seen.insert(indicator) {
                    duplicate_index = Some(index);
                }
            }
        }
        if let Some(index) = duplicate_index {
            self.matches.remove(index);
            true
        } else {
            false
        }
    }

    pub fn into_vec(self) -> Vec<Finding> {
        let mut v = self.matches;
        v.extend(self.suspicious);
        v.extend(self.notes);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn match_finding(value: &str, artifact: &str) -> Finding {
        Finding {
            severity: Severity::Match,
            kind: "ioc_match".into(),
            artifact: artifact.into(),
            summary: format!("matched {value}"),
            evidence: serde_json::json!({ "process": value }),
            indicator: Some(IndicatorRef {
                value: value.into(),
                kind: "process_name".into(),
                set: "test-set".into(),
                campaign: "Test Campaign".into(),
            }),
        }
    }

    #[test]
    fn distinct_match_survives_a_cap_filled_with_duplicate_matches() {
        let mut findings = Findings::new();
        for n in 0..MAX_FINDINGS {
            findings.push(match_finding("duplicate", &format!("artifact-{n}")));
        }
        assert_eq!(findings.len(), MAX_FINDINGS);
        assert!(!findings.capped);

        findings.push(match_finding("later-distinct", "last-artifact"));

        assert!(findings.capped);
        assert_eq!(findings.len(), MAX_FINDINGS);
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding
                    .indicator
                    .as_ref()
                    .is_some_and(|indicator| { indicator.value == "duplicate" }))
                .count(),
            MAX_FINDINGS - 1
        );
        assert!(findings.iter().any(|finding| {
            finding
                .indicator
                .as_ref()
                .is_some_and(|indicator| indicator.value == "later-distinct")
        }));
    }
}

impl Finding {
    pub fn ioc_match(
        artifact: &str,
        summary: String,
        evidence: serde_json::Value,
        ind: &Indicator,
    ) -> Finding {
        Finding {
            severity: Severity::Match,
            kind: "ioc_match".into(),
            artifact: artifact.into(),
            summary,
            evidence,
            indicator: Some(IndicatorRef {
                value: ind.value.clone(),
                kind: kind_label(ind.kind).into(),
                set: ind.set.clone(),
                campaign: ind.campaign.clone(),
            }),
        }
    }

    pub fn heuristic(
        severity: Severity,
        artifact: &str,
        summary: String,
        evidence: serde_json::Value,
    ) -> Finding {
        Finding {
            severity,
            kind: "heuristic".into(),
            artifact: artifact.into(),
            summary,
            evidence,
            indicator: None,
        }
    }
}

#[derive(Serialize)]
pub struct ArtifactSummary {
    pub path: String,
    pub kind: String,
    pub status: String,
    pub details: serde_json::Value,
}

impl ArtifactSummary {
    pub fn parsed(path: &str, kind: &str, details: serde_json::Value) -> Self {
        ArtifactSummary {
            path: path.into(),
            kind: kind.into(),
            status: "parsed".into(),
            details,
        }
    }

    pub fn problem(path: &str, kind: &str, status: &str, details: serde_json::Value) -> Self {
        ArtifactSummary {
            path: path.into(),
            kind: kind.into(),
            status: status.into(),
            details,
        }
    }
}

#[derive(Serialize)]
pub struct DeviceInfo {
    pub os_version: String,
    pub source: String,
    /// Timestamp of the .ips report the OS version came from. A report can
    /// predate an OS upgrade, so the engine prefers the newest one; keeping
    /// the timestamp in the report makes that provenance checkable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

#[derive(Serialize)]
pub struct ToolInfo {
    pub name: &'static str,
    pub version: &'static str,
    /// Exact commit the running scanner was built from, injected at build
    /// time via TRACE_BUILD_COMMIT. An untagged commit can reach production
    /// while `version` stays the same, so version alone does not identify
    /// the build. Null when built outside the release paths (local dev).
    pub build_commit: Option<&'static str>,
}

/// What was scanned: the producer supplies only the display name, while the
/// engine measures both byte count and SHA-256 from every byte actually
/// pushed. The hash lets a responder confirm which exact archive a report
/// describes.
#[derive(Serialize)]
pub struct SourceFile {
    pub name: Option<String>,
    pub size: Option<u64>,
    pub sha256: String,
}

/// Provenance of one loaded indicator set: which reviewed snapshot, hashed
/// by the engine from the exact text it extracted indicators from. The
/// producer supplies catalog metadata (date, url, source); the hash is
/// never producer-claimed.
#[derive(Serialize)]
pub struct SetProvenance {
    pub name: String,
    pub campaign: String,
    pub sha256: String,
    pub loaded_from: String,
    pub date: Option<String>,
    pub url: Option<String>,
    pub source: Option<String>,
    /// Load-time upstream check result ('current' | 'update-available' |
    /// 'unknown'); informational only - scans always use the reviewed text
    /// hashed above.
    pub upstream: Option<String>,
}

/// Per-surface completeness, machine-readable. `complete` means every
/// artifact of that kind parsed fully; any parser degradation makes it
/// `partial` (the human-readable reason is in scan_limits). Global limits
/// (entry caps, decompression budget) live in `Assurance::complete`, not
/// per surface.
#[derive(Serialize)]
pub struct SurfaceState {
    pub kind: &'static str,
    pub state: &'static str,
}

/// Machine-readable completeness summary for comparison tooling and
/// responder triage. Everything here is derived from the same inputs as
/// the verdict; it adds no new semantics, only structure.
#[derive(Serialize)]
pub struct Assurance {
    /// Processing completeness, not surface coverage: true when the input
    /// was recognizably a sysdiagnose, no verdict-relevant safety limit was
    /// hit, and every parser succeeded fully. Bounded evidence sampling may
    /// still be disclosed. A scan can be complete with absent surfaces - those
    /// are in `surfaces` and `missing_artifacts`.
    pub complete: bool,
    pub surfaces: Vec<SurfaceState>,
    pub surfaces_examined: usize,
    pub surfaces_total: usize,
}

#[derive(Serialize)]
pub struct ScanStats {
    pub bytes_read: u64,
    pub archive_entries: u64,
    pub artifacts_found: usize,
    pub total_indicators: usize,
    pub applicable_indicators: usize,
}

/// An artifact kind the scanner knows how to read but did not find in the
/// archive. Surfacing these is part of honest results: a verdict computed
/// from two of three detection surfaces must say so.
#[derive(Serialize)]
pub struct MissingArtifact {
    pub kind: String,
    pub note: String,
}

#[derive(Serialize)]
pub struct Coverage {
    /// Surfaces actually present and analyzed in this archive - built per
    /// scan, so a missing surface can never be listed as examined.
    pub examined: Vec<&'static str>,
    pub not_examined: Vec<&'static str>,
    pub note: &'static str,
}

/// The scan outcome, owned by the Rust engine. Rendering code must display
/// this verdict, never re-derive its own from other report fields: every
/// safety consideration (parser health, scan limits, artifact presence)
/// funnels into this one value.
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// At least one deterministic match against a published indicator under
    /// the matching rules documented on [`Severity::Match`].
    Match,
    /// No indicator match, but research-documented anomalies present.
    Suspicious,
    /// Every present surface parsed fully and nothing matched.
    Clear,
    /// Part of the archive was not (or could not be) analyzed; absence of
    /// findings is not meaningful. Never rendered as "no traces found".
    Inconclusive,
    /// Nothing recognizable as a sysdiagnose was found in the input.
    Invalid,
}

/// Field policy: producer-supplied metadata (`generated_at`, `scanned_via`,
/// `duration_ms`, `source_file.name`, provenance details) is always
/// serialized, null when unknown, so every producer emits the identical
/// field set for identical input - the producer-parity golden test depends
/// on this. `source_file.size` and SHA-256 are engine-derived. Other
/// content-derived fields (`device`, a finding's `indicator`) may be omitted,
/// because their presence depends only on the archive.
#[derive(Serialize)]
pub struct Report {
    /// Bumped when the report shape changes incompatibly. Consumers
    /// (helplines, future comparison tooling) can key on it.
    /// v3: Rust owns the whole envelope (no fields appended by the UI),
    /// adds source_file with archive SHA-256, build identity,
    /// generated_at/duration, indicator_provenance, and assurance.
    pub schema_version: u32,
    pub tool: ToolInfo,
    pub verdict: Verdict,
    /// RFC 3339 timestamp from the host's calendar clock, stamped by the
    /// wrapper when finalization begins.
    pub generated_at: Option<String>,
    /// Milliseconds measured by the engine through its host-injected
    /// clock, from the first byte received to the end of report assembly
    /// (parsing, matching, and the verdict all happen inside finish).
    /// Null when the host injected no clock.
    pub duration_ms: Option<u64>,
    /// 'worker' | 'inline' | 'native'.
    pub scanned_via: Option<String>,
    pub source_file: SourceFile,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<DeviceInfo>,
    pub indicator_sets: Vec<crate::ioc::SetStats>,
    pub indicator_provenance: Vec<SetProvenance>,
    pub artifacts: Vec<ArtifactSummary>,
    pub missing_artifacts: Vec<MissingArtifact>,
    pub findings: Vec<Finding>,
    pub stats: ScanStats,
    /// Non-empty when the scan hit a verdict-relevant safety limit or a parser
    /// failed on part of the input, so not everything was analyzed. Any entry
    /// here forces the verdict away from `Clear`; evidence-only sampling limits
    /// are disclosed in artifact details instead.
    pub scan_limits: Vec<String>,
    pub assurance: Assurance,
    pub coverage: Coverage,
}
