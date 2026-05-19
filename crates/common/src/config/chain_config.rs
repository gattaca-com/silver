use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::default_u64;
use crate::{Enr, config::SpecConfig};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChainConfig {
    #[serde(default = "default_u64::<1438269973>")]
    pub genesis_unix_secs: u64,
    #[serde(default = "default_u64::<4000>")]
    pub prepare_payload_lookahead_millis: u64,
    #[serde(default)]
    pub checkpoint_file: Option<String>,
    #[serde(default)]
    pub bootstrap_enrs: Vec<Enr>,
    #[serde(default)]
    pub spec: SpecConfig,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            genesis_unix_secs: 1438269973,
            prepare_payload_lookahead_millis: 4000,
            checkpoint_file: None,
            bootstrap_enrs: vec![],
            spec: SpecConfig::mainnet(),
        }
    }
}

impl ChainConfig {
    /// Single source of truth: `spec.seconds_per_slot` × 1s.
    pub fn slot_duration(&self) -> Duration {
        Duration::from_secs(self.spec.seconds_per_slot)
    }

    pub fn playload_lookahead(&self) -> Duration {
        Duration::from_millis(self.prepare_payload_lookahead_millis)
    }
}
