use std::time::Duration;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryConfig {
    pub lookup_interval_ms: u64,
    pub lookup_distances: usize,
    pub target_sessions: usize,
    pub ping_frequency_s: u64,
}

impl DiscoveryConfig {
    pub fn lookup_interval(&self) -> Duration {
        Duration::from_millis(self.lookup_interval_ms)
    }

    pub fn ping_frequency(&self) -> Duration {
        Duration::from_secs(self.ping_frequency_s)
    }
}
