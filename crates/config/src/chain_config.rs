use std::time::Duration;

use serde::{Deserialize, Serialize};
use silver_chain_spec::SpecConfig;
use silver_common::Enr;

/// Independent operators, so agreement between them means something.
const MAINNET_CHECKPOINT_SYNC_URLS: [&str; 5] = [
    "https://mainnet.checkpoint.sigp.io",
    "https://beaconstate-mainnet.chainsafe.io",
    "https://sync-mainnet.beaconcha.in",
    "https://mainnet-checkpoint-sync.attestant.io",
    "https://beaconstate.ethstaker.cc",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct ChainConfig {
    pub genesis_unix_secs: u64,
    pub prepare_payload_lookahead_millis: u64,
    pub checkpoint_file: Option<String>,
    pub checkpoint_pubkeys_file: Option<String>,
    /// Beacon API bases serving finalized states, e.g. checkpointz instances.
    /// Mainnet's only with the whole mainnet preset. A `[chain_config]` table
    /// omitting it gets none, so a devnet never falls back to mainnet's.
    #[serde(default)]
    pub checkpoint_sync_urls: Vec<String>,
    pub spec_file: Option<String>,
    pub bootstrap_enrs: Vec<Enr>,
    pub spec: SpecConfig,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            genesis_unix_secs: 1606824023,
            prepare_payload_lookahead_millis: 4000,
            checkpoint_file: None,
            checkpoint_pubkeys_file: None,
            checkpoint_sync_urls: MAINNET_CHECKPOINT_SYNC_URLS.map(str::to_owned).to_vec(),
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
