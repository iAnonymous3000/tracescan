//! Path-based heuristic classification shared by all three artifact parsers,
//! so the definition of "suspicious location" cannot drift between surfaces.

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
