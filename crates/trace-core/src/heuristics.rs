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
    const ROLEACCOUNT_STAGING: &str = "/private/var/db/com.apple.xpc.roleaccountd.staging/";
    if let Some(relative) = path.strip_prefix(ROLEACCOUNT_STAGING) {
        let relative = relative.trim_end_matches('/');
        // Published Pegasus/KingSpawn examples execute as a direct child of
        // roleaccountd.staging (for example `rolexd`, `bh`, `subridged`).
        // iOS itself legitimately uses the specifically observed
        // exec/<id>.xpc/... workspace shape here. Keep every other descendant
        // suspicious; exempting arbitrary nested paths would create a bypass.
        let is_apple_exec_workspace = relative
            .strip_prefix("exec/")
            .and_then(|rest| rest.split_once('/'))
            .is_some_and(|(workspace, executable)| {
                workspace
                    .strip_suffix(".xpc")
                    .is_some_and(|id| !id.is_empty())
                    && !executable.is_empty()
            });
        if !relative.is_empty() && !is_apple_exec_workspace {
            return Some(PathFlag::Staging);
        }
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
            path_flag(
                "/private/var/db/com.apple.xpc.roleaccountd.staging/exec/16777224.1.xpc/com.apple.NRD.UpdateBrainService"
            ),
            Some(PathFlag::UnusualLocation),
            "Apple's nested role-account execution workspace is not the published direct-child Pegasus shape"
        );
        assert_eq!(
            path_flag("/private/var/db/com.apple.xpc.roleaccountd.staging/drop/bh"),
            Some(PathFlag::Staging),
            "arbitrary nested staging paths must remain suspicious"
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
