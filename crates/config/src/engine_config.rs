use serde::{Deserialize, Serialize};

fn default_tcache_size() -> usize {
    2 << 24
}

fn default_max_connections() -> usize {
    32
}

// Clears every engine-api per-method minimum-wait floor (the highest is
// getPayloadBodiesBy* at 10 s) with margin: this deadline breaks wedged
// connections, it is not a latency target.
fn default_request_timeout_secs() -> u64 {
    12
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
            unsafe_no_el: false,
        }
    }
}
