use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use silver_common::Enr;

/// Snapshots fit 149,753 validators attesting every epoch, with one block per
/// slot. Retained records for inactive validators reduce this capacity.
/// Oversized snapshots stop cluster participation and local submissions.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClusterConfig {
    /// All cluster nodes, including the local node, keyed by cluster node id.
    #[serde(default)]
    pub nodes: HashMap<u64, Enr>,
    /// Create a new journal exclusively. Disable on restart; recovery never
    /// recreates missing journals. Never use this to replace a lost voter
    /// journal. The journal lives at
    /// `data_storage_dir/attestation-cluster.wal`; its parent directory must
    /// exist.
    #[serde(default)]
    pub bootstrap: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_creation_requires_explicit_bootstrap() {
        let config: ClusterConfig = serde_yml::from_str("nodes: {}").unwrap();
        assert!(!config.bootstrap);
        let config: ClusterConfig = serde_yml::from_str("nodes: {}\nbootstrap: true").unwrap();
        assert!(config.bootstrap);
    }
}
