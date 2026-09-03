use std::time::Duration;

use serde::{Deserialize, Serialize};
use silver_chain_spec::SpecConfig;
use silver_common::Enr;

use super::default_u64;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChainConfig {
    #[serde(default = "default_u64::<1606824023>")]
    pub genesis_unix_secs: u64,
    #[serde(default = "default_u64::<4000>")]
    pub prepare_payload_lookahead_millis: u64,
    #[serde(default)]
    pub checkpoint_file: Option<String>,
    #[serde(default)]
    pub checkpoint_pubkeys_file: Option<String>,
    #[serde(default)]
    pub spec_file: Option<String>,
    #[serde(default)]
    pub bootstrap_enrs: Vec<Enr>,
    #[serde(default)]
    pub spec: SpecConfig,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            genesis_unix_secs: 1606824023,
            prepare_payload_lookahead_millis: 4000,
            checkpoint_file: None,
            checkpoint_pubkeys_file: None,
            spec_file: None,
            bootstrap_enrs: vec![],
            spec: SpecConfig::mainnet(),
        }
    }
}

impl ChainConfig {
    pub fn slot_duration(&self) -> Duration {
        Duration::from_millis(self.spec.slot_duration_ms())
    }

    pub fn playload_lookahead(&self) -> Duration {
        Duration::from_millis(self.prepare_payload_lookahead_millis)
    }
}
