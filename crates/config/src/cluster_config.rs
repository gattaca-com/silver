use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use silver_common::Enr;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClusterConfig {
    /// All cluster nodes, including the local node, keyed by cluster node id.
    #[serde(default)]
    pub nodes: HashMap<u64, Enr>,
}
