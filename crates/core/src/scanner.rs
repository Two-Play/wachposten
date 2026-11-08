//! Hook for malware scanners (YARA-X, hash lists), implemented outside the core.

use std::path::Path;

use crate::model::Finding;

/// Rule id of findings from a malware scanner.
pub const MALWARE_RULE: &str = "malware";

/// Checks one file for known malware.
pub trait FileScanner: Send + Sync {
    /// Findings with rule [`MALWARE_RULE`]; the line names the signature and the file.
    fn scan(&self, path: &Path) -> Vec<Finding>;
}
