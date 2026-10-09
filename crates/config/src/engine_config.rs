use std::time::Duration;

use serde::{Deserialize, Serialize};

fn default_tcache_size() -> usize {
    2 << 24
}

fn default_max_connections() -> usize {
    32
}

// The deadline breaks wedged connections; it is not a latency target.
fn default_request_timeout_secs() -> u64 {
    12
}

fn default_get_payload_timeout_ms() -> u64 {
    2000
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EngineConfig {
    pub execution_endpoint: String,
    /// Path to the EL's hex-encoded JWT secret file.
    pub jwt_secret: String,
    #[serde(default = "default_tcache_size")]
    pub incoming_engine_resp_tcache_size: usize,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Measured from enqueue, so it also covers a connect that never completes.
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    /// How long block production waits for the EL's payload after a block is
    /// requested, before building on the sidecar's bid alone or failing.
    #[serde(default = "default_get_payload_timeout_ms")]
    pub get_payload_timeout_ms: u64,
    /// Unsafe testing mode: do not connect to the EL. The engine tile answers
    /// every spine request with a synthetic VALID response. Lets the CL run
    /// without an execution client. Never enable in production.
    #[serde(default)]
    pub unsafe_no_el: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            execution_endpoint: "http://localhost:8551".into(),
            jwt_secret: "0".into(),
            incoming_engine_resp_tcache_size: 2 << 24,
            max_connections: 32,
            request_timeout_secs: default_request_timeout_secs(),
            get_payload_timeout_ms: default_get_payload_timeout_ms(),
            unsafe_no_el: false,
        }
    }
}

impl EngineConfig {
    pub fn get_payload_timeout(&self) -> Duration {
        Duration::from_millis(self.get_payload_timeout_ms)
    }
}
