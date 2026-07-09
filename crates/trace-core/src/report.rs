use crate::ioc::{kind_label, Indicator};
use serde::Serialize;

/// Severity is epistemically descriptive, not a fear scale:
/// - `Match`: an exact match against a published indicator of compromise.
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

#[derive(Serialize, Clone)]
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
/// heuristic) approaches this. Each finding is duplicated into report JSON
/// and a DOM card, so unbounded growth is a memory exhaustion vector.
pub const MAX_FINDINGS: usize = 5_000;

/// Findings accumulator enforcing [`MAX_FINDINGS`]. Once the cap is hit,
/// further findings are dropped and `capped` is set; the engine surfaces
/// that as a scan limit, so the verdict can never read as clear.
#[derive(Default)]
pub struct Findings {
    items: Vec<Finding>,
    pub capped: bool,
}

impl Findings {
    pub fn new() -> Self {
        Findings::default()
    }

    pub fn push(&mut self, f: Finding) {
        if self.items.len() < MAX_FINDINGS {
            self.items.push(f);
        } else {
            self.capped = true;
        }
    }

    pub fn into_vec(self) -> Vec<Finding> {
        self.items
    }
}

impl std::ops::Deref for Findings {
    type Target = [Finding];
    fn deref(&self) -> &[Finding] {
        &self.items
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
    /// Timestamp of the crash log the OS version came from. A crash can
    /// predate an OS upgrade, so the engine prefers the newest one; keeping
    /// the timestamp in the report makes that provenance checkable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

#[derive(Serialize)]
pub struct ToolInfo {
    pub name: &'static str,
    pub version: &'static str,
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
    /// At least one exact match against a published indicator.
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

#[derive(Serialize)]
pub struct Report {
    /// Bumped when the report shape changes incompatibly. Consumers
    /// (helplines, future comparison tooling) can key on it.
    pub schema_version: u32,
    pub tool: ToolInfo,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<DeviceInfo>,
    pub indicator_sets: Vec<crate::ioc::SetStats>,
    pub artifacts: Vec<ArtifactSummary>,
    pub missing_artifacts: Vec<MissingArtifact>,
    pub findings: Vec<Finding>,
    pub stats: ScanStats,
    /// Non-empty when the scan hit a safety limit or a parser failed on
    /// part of the input, so not everything was analyzed. Any entry here
    /// forces the verdict away from `Clear`.
    pub scan_limits: Vec<String>,
    pub coverage: Coverage,
}
