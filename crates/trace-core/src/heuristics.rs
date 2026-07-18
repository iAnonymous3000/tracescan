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
    // Process paths reported by these artifacts should already be canonical.
    // Classifying a lexical path that contains `.` or `..` can accuse the
    // wrong location (for example staging/../usr/bin/legit). Leave ambiguous
    // paths unclassified rather than applying a prefix heuristic to them.
    if path
        .split('/')
        .any(|component| matches!(component, "." | ".."))
    {
        return None;
    }
    // On Apple platforms `/var` is a symlink to `/private/var`. Diagnostic
    // artifacts can retain either spelling, so compare the path relative to
    // that shared location instead of assuming the canonical prefix.
    let var_relative = path
        .strip_prefix("/private/var/")
        .or_else(|| path.strip_prefix("/var/"));
    const ROLEACCOUNT_STAGING: &str = "db/com.apple.xpc.roleaccountd.staging/";
    if let Some(relative) = var_relative.and_then(|path| path.strip_prefix(ROLEACCOUNT_STAGING)) {
        // Published Pegasus/KingSpawn examples execute as a direct child of
        // roleaccountd.staging (for example `rolexd`, `bh`, `subridged`).
        // iOS itself legitimately uses the observed
        // exec/<numeric>.<numeric>.xpc/<executable> workspace shape here.
        // Require that exact component shape: accepting an arbitrary `.xpc`
        // directory or additional descendants would let a suspicious path
        // hide behind the false-positive exception.
        let mut components = relative.split('/');
        let is_apple_exec_workspace = match (
            components.next(),
            components.next(),
            components.next(),
            components.next(),
        ) {
            (Some("exec"), Some(workspace), Some(executable), None) => {
                workspace
                    .strip_suffix(".xpc")
                    .and_then(|id| id.split_once('.'))
                    .is_some_and(|(account, instance)| {
                        !account.is_empty()
                            && account.bytes().all(|byte| byte.is_ascii_digit())
                            && !instance.is_empty()
                            && instance.bytes().all(|byte| byte.is_ascii_digit())
                    })
                    && !executable.is_empty()
            }
            _ => false,
        };
        if !relative.is_empty() && !is_apple_exec_workspace {
            return Some(PathFlag::Staging);
        }
    }
    if var_relative.is_some_and(|path| {
        path.starts_with("db/") || path.starts_with("tmp/") || path.starts_with("root/")
    }) {
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
            path_flag(
                "/private/var/db/com.apple.xpc.roleaccountd.staging/exec/16777224.1.xpc/drop/bh"
            ),
            Some(PathFlag::Staging),
            "the legitimate workspace exception must cover exactly one executable component"
        );
        assert_eq!(
            path_flag("/private/var/db/com.apple.xpc.roleaccountd.staging/exec/evil.xpc/drop/bh"),
            Some(PathFlag::Staging),
            "an arbitrary .xpc directory must not suppress the staging heuristic"
        );
        assert_eq!(
            path_flag(
                "/private/var/db/com.apple.xpc.roleaccountd.staging/exec/evil.xpc/com.apple.NRD.UpdateBrainService"
            ),
            Some(PathFlag::Staging),
            "the workspace identifier must retain the observed numeric shape"
        );
        assert_eq!(
            path_flag("/private/var/tmp/agent"),
            Some(PathFlag::UnusualLocation)
        );
        assert_eq!(
            path_flag("/private/var/db/com.apple.xpc.roleaccountd.staging/../usr/bin/legit"),
            None,
            "dot segments must not inherit the raw staging prefix"
        );
        assert_eq!(
            path_flag("/private/var/tmp/./usr/bin/legit"),
            None,
            "dot segments make an unusual-location prefix ambiguous"
        );
        assert_eq!(path_flag("/usr/libexec/nfcd"), None);
        // app containers are normal ground and must not be flagged
        assert_eq!(
            path_flag("/private/var/containers/Bundle/Application/X/App.app/App"),
            None
        );
    }

    #[test]
    fn classifies_var_symlink_spelling_like_private_var() {
        for (alias, canonical, expected) in [
            (
                "/var/db/com.apple.xpc.roleaccountd.staging/bh",
                "/private/var/db/com.apple.xpc.roleaccountd.staging/bh",
                Some(PathFlag::Staging),
            ),
            (
                "/var/db/com.apple.xpc.roleaccountd.staging/exec/16777224.1.xpc/com.apple.NRD.UpdateBrainService",
                "/private/var/db/com.apple.xpc.roleaccountd.staging/exec/16777224.1.xpc/com.apple.NRD.UpdateBrainService",
                Some(PathFlag::UnusualLocation),
            ),
            (
                "/var/db/agent",
                "/private/var/db/agent",
                Some(PathFlag::UnusualLocation),
            ),
            (
                "/var/tmp/agent",
                "/private/var/tmp/agent",
                Some(PathFlag::UnusualLocation),
            ),
            (
                "/var/root/agent",
                "/private/var/root/agent",
                Some(PathFlag::UnusualLocation),
            ),
            (
                "/var/containers/Bundle/Application/X/App.app/App",
                "/private/var/containers/Bundle/Application/X/App.app/App",
                None,
            ),
        ] {
            assert_eq!(path_flag(canonical), expected, "canonical control: {canonical}");
            assert_eq!(path_flag(alias), expected, "symlink spelling: {alias}");
        }

        // /tmp and /etc point to /private/tmp and /private/etc, respectively,
        // but neither canonical location is part of this heuristic's narrow
        // /private/var/{db,tmp,root} unusual-location set.
        for (alias, canonical) in [
            ("/tmp/agent", "/private/tmp/agent"),
            ("/etc/agent", "/private/etc/agent"),
        ] {
            assert_eq!(path_flag(canonical), None, "canonical control: {canonical}");
            assert_eq!(path_flag(alias), None, "symlink spelling: {alias}");
        }

        assert_eq!(path_flag("/variable/tmp/agent"), None);
    }
}
