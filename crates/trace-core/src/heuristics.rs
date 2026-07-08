//! Path-based heuristic classification shared by all three artifact parsers,
//! so the definition of "suspicious location" - and the finding text it
//! produces - cannot drift between surfaces.

use crate::report::{Finding, Severity};

/// How a process path should be flagged, if at all.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PathFlag {
    /// The roleaccountd.staging directory is strongly associated with
    /// Pegasus infections in published research (Kaspersky iShutdown 2024,
    /// Amnesty/MVT case work).
    Staging,
    /// Writable system locations that legitimate iOS software rarely runs
    /// from; frequently benign, so this only ever produces a Note.
    UnusualLocation,
}

pub fn path_flag(path: &str) -> Option<PathFlag> {
    if path.contains("/com.apple.xpc.roleaccountd.staging/") {
        return Some(PathFlag::Staging);
    }
    if path.starts_with("/private/var/db/")
        || path.starts_with("/private/var/tmp/")
        || path.starts_with("/private/var/root/")
    {
        return Some(PathFlag::UnusualLocation);
    }
    None
}

/// Builds the standard finding for a flagged path. `subject` opens the
/// sentence and names the surface, e.g. "A process ran from".
pub fn path_flag_finding(
    artifact: &str,
    proc_path: &str,
    subject: &str,
    evidence: &serde_json::Value,
) -> Option<Finding> {
    let finding = match path_flag(proc_path)? {
        PathFlag::Staging => Finding::heuristic(
            Severity::Suspicious,
            artifact,
            format!(
                "{subject} {proc_path} - this staging directory is strongly associated with Pegasus infections in published research (Kaspersky iShutdown, 2024)"
            ),
            evidence.clone(),
        ),
        PathFlag::UnusualLocation => Finding::heuristic(
            Severity::Note,
            artifact,
            format!(
                "{subject} an unusual location ({proc_path}) - often benign, but worth review alongside other findings"
            ),
            evidence.clone(),
        ),
    };
    Some(finding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_paths() {
        assert_eq!(
            path_flag("/private/var/db/com.apple.xpc.roleaccountd.staging/bh"),
            Some(PathFlag::Staging)
        );
        assert_eq!(
            path_flag("/private/var/tmp/agent"),
            Some(PathFlag::UnusualLocation)
        );
        assert_eq!(path_flag("/usr/libexec/nfcd"), None);
        // app containers are normal ground and must not be flagged
        assert_eq!(
            path_flag("/private/var/containers/Bundle/Application/X/App.app/App"),
            None
        );
    }
}
