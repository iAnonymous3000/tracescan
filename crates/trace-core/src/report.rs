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
    pub examined: Vec<&'static str>,
    pub not_examined: Vec<&'static str>,
    pub note: &'static str,
}

#[derive(Serialize)]
pub struct Report {
    pub tool: ToolInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<DeviceInfo>,
    pub indicator_sets: Vec<crate::ioc::SetStats>,
    pub artifacts: Vec<ArtifactSummary>,
    pub missing_artifacts: Vec<MissingArtifact>,
    pub findings: Vec<Finding>,
    pub stats: ScanStats,
    /// Non-empty when the scan hit a safety limit (oversized or too many
    /// files, too many archive entries) and therefore did not analyze
    /// everything. Consumers must not present such a scan as a clean result;
    /// the UI renders it as inconclusive.
    pub scan_limits: Vec<String>,
    pub coverage: Coverage,
}
