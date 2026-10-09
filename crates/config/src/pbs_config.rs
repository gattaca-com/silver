use std::time::Duration;

use serde::Deserialize;

fn default_get_header_timeout_ms() -> u64 {
    1200
}

fn default_submit_blinded_block_timeout_ms() -> u64 {
    5000
}

#[derive(Debug, Clone, Deserialize)]
pub struct PbsConfig {
    pub endpoint: String,
    /// Commit-Boost answers within its `timeout_get_header_ms`, 950 by
    /// default; the rest covers the round trip.
    #[serde(default = "default_get_header_timeout_ms")]
    pub get_header_timeout_ms: u64,
    /// Commit-Boost waits up to its `timeout_get_payload_ms`, 4000 by default,
    /// for a relay to reveal; the rest covers the round trip.
    #[serde(default = "default_submit_blinded_block_timeout_ms")]
    pub submit_blinded_block_timeout_ms: u64,
}

impl PbsConfig {
    pub fn new(endpoint: String) -> Self {
        Self {
            endpoint,
            get_header_timeout_ms: default_get_header_timeout_ms(),
            submit_blinded_block_timeout_ms: default_submit_blinded_block_timeout_ms(),
        }
    }

    pub fn get_header_timeout(&self) -> Duration {
        Duration::from_millis(self.get_header_timeout_ms)
    }

    pub fn submit_blinded_block_timeout(&self) -> Duration {
        Duration::from_millis(self.submit_blinded_block_timeout_ms)
    }
}
