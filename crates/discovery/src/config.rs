use std::time::Duration;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryConfig {
    pub find_nodes_peer_count: usize,
    pub ping_frequency_s: u64,
    pub query_parallelism: usize,
    pub query_peer_timeout_ms: u64,
}

impl DiscoveryConfig {
    pub fn ping_frequency(&self) -> Duration {
        Duration::from_secs(self.ping_frequency_s)
    }

    pub fn query_peer_timeout(&self) -> Duration {
        Duration::from_millis(self.query_peer_timeout_ms)
    }
}
