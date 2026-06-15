use serde::{Deserialize, Serialize};

fn default_tcache_size() -> usize {
    2 << 24
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EngineConfig {
    pub execution_endpoint: String,
    /// Path to the EL's hex-encoded JWT secret file.
    pub jwt_secret: String,
    #[serde(default = "default_tcache_size")]
    pub incoming_engine_resp_tcache_size: usize,
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
            unsafe_no_el: false,
        }
    }
}
