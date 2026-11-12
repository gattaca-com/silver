use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use silver_common::Enr;

/// Snapshots fit 149,753 validators attesting every epoch, with one block per
/// slot. Retained records for inactive validators reduce this capacity. Past
/// the limit, compaction is skipped and the journal grows. At most 7 nodes.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClusterConfig {
    /// All cluster nodes, including the local node, keyed by cluster node id.
    #[serde(default, deserialize_with = "node_ids::deserialize")]
    pub nodes: HashMap<u64, Enr>,
    /// Create a new journal exclusively. Disable on restart; recovery never
    /// recreates missing journals. Never use this to replace a lost voter
    /// journal. The journal lives at
    /// `data_storage_dir/attestation-cluster.wal`; its parent directory must
    /// exist.
    #[serde(default)]
    pub bootstrap: bool,
}

/// TOML keys are always strings.
mod node_ids {
    use std::collections::HashMap;

    use serde::{Deserialize, Deserializer, de::Error};
    use silver_common::Enr;

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<HashMap<u64, Enr>, D::Error> {
        HashMap::<String, Enr>::deserialize(deserializer)?
            .into_iter()
            .map(|(id, enr)| match id.parse() {
                Ok(id) => Ok((id, enr)),
                Err(_) => Err(D::Error::custom(format!("cluster node id {id} is not a u64"))),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENR_1: &str = "enr:-Iu4QLm7bZGdAt9NSeJG0cEnJohWcQTQaI9wFLu3Q7eHIDfrI4cwtzvEW3F3VbG9XdFXlrHyFGeXPn9snTCQJ9bnMRABgmlkgnY0gmlwhAOTJQCJc2VjcDI1NmsxoQIZdZD6tDYpkpEfVo5bgiU8MGRjhcOmHGD2nErK0UKRrIN0Y3CCIyiDdWRwgiMo";
    const ENR_2: &str = "enr:-Iu4QEDJ4Wa_UQNbK8Ay1hFEkXvd8psolVK6OhfTL9irqz3nbXxxWyKwEplPfkju4zduVQj6mMhUCm9R2Lc4YM5jPcIBgmlkgnY0gmlwhANrfESJc2VjcDI1NmsxoQJCYz2-nsqFpeEj6eov9HSi9QssIVIVNr0I89J1vXM9foN0Y3CCIyiDdWRwgiMo";

    #[test]
    fn journal_creation_requires_explicit_bootstrap() {
        let config: ClusterConfig = serde_yml::from_str("nodes: {}").unwrap();
        assert!(!config.bootstrap);
        let config: ClusterConfig = serde_yml::from_str("nodes: {}\nbootstrap: true").unwrap();
        assert!(config.bootstrap);
    }

    #[test]
    fn toml_nodes_are_keyed_by_numeric_strings() {
        let config: ClusterConfig =
            toml::from_str(&format!("[nodes]\n1 = \"{ENR_1}\"\n2 = \"{ENR_2}\"\n")).unwrap();
        assert_eq!(config.nodes[&1].to_base64(), ENR_1);
        assert_eq!(config.nodes[&2].to_base64(), ENR_2);

        let err =
            toml::from_str::<ClusterConfig>(&format!("[nodes]\na = \"{ENR_1}\"\n")).unwrap_err();
        assert!(err.to_string().contains("cluster node id a is not a u64"), "{err}");
    }
}
