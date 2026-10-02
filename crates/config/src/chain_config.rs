use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use silver_chain_spec::{ForkName, SpecConfig};
use silver_common::{Enr, Error, NodeChain, SLOTS_PER_EPOCH};

use crate::{Genesis, Network};

/// The `[chain_config]` keys a config file may set. Unset ones take the
/// network's.
#[derive(Debug, Default, Deserialize)]
pub struct ChainOverrides {
    prepare_payload_lookahead_millis: Option<u64>,
    checkpoint_file: Option<String>,
    checkpoint_pubkeys_file: Option<String>,
    checkpoint_sync_urls: Option<Vec<String>>,
    bootstrap_enrs: Option<Vec<Enr>>,
}

#[derive(Clone, Debug)]
pub struct ChainConfig {
    pub prepare_payload_lookahead_millis: u64,
    pub checkpoint_file: Option<String>,
    pub checkpoint_pubkeys_file: Option<String>,
    /// Beacon API bases serving finalized states, e.g. checkpointz instances.
    pub checkpoint_sync_urls: Vec<String>,
    pub bootstrap_enrs: Vec<Enr>,
    pub spec: SpecConfig,
    pub data_dir: String,
}

impl ChainConfig {
    /// An unset `data_dir` defaults to one per network.
    pub fn new(
        network: &Network,
        overrides: &ChainOverrides,
        data_dir: Option<&str>,
    ) -> Result<Self, Error> {
        let bootstrap_enrs = match &overrides.bootstrap_enrs {
            Some(enrs) => enrs.clone(),
            None => network.bootnodes()?,
        };
        let spec = network.spec()?;
        let data_dir =
            data_dir.map_or_else(|| default_data_dir(&spec.network_name()), str::to_owned);
        Ok(Self {
            prepare_payload_lookahead_millis: overrides
                .prepare_payload_lookahead_millis
                .unwrap_or(4000),
            checkpoint_file: overrides.checkpoint_file.clone(),
            checkpoint_pubkeys_file: overrides.checkpoint_pubkeys_file.clone(),
            checkpoint_sync_urls: (overrides.checkpoint_sync_urls.clone())
                .unwrap_or_else(|| network.checkpoint_sync_urls()),
            bootstrap_enrs,
            spec,
            data_dir,
        })
    }

    /// Zero before genesis.
    pub fn wall_epoch(&self, genesis: &Genesis) -> u64 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let since_genesis = now.as_millis().saturating_sub(genesis.unix_secs as u128 * 1000);
        (since_genesis / self.slot_duration().as_millis()) as u64 / SLOTS_PER_EPOCH
    }

    /// Refuses a spec that puts `epoch` earlier than Fulu.
    pub fn checked_fork_digest(&self, epoch: u64, genesis: &Genesis) -> Result<[u8; 4], Error> {
        let fork = self.spec.fork_at(epoch);
        if fork < ForkName::Fulu {
            return Err(Error::ConfigError(format!(
                "chain_config.spec puts epoch {epoch} in {}; silver runs Fulu and Gloas only \
                 (check FULU_FORK_EPOCH)",
                fork.name()
            )));
        }
        Ok(self.spec.fork_digest_at(epoch, &genesis.validators_root))
    }

    pub fn node_chain(&self, genesis: &Genesis) -> NodeChain {
        NodeChain {
            genesis_unix_secs: genesis.unix_secs,
            slot_ms: self.spec.slot_duration_ms(),
            network: self.spec.network_name(),
        }
    }

    pub fn slot_duration(&self) -> Duration {
        Duration::from_millis(self.spec.slot_duration_ms())
    }

    pub fn playload_lookahead(&self) -> Duration {
        Duration::from_millis(self.prepare_payload_lookahead_millis)
    }
}

/// `~/.local/silver` for mainnet, a subdirectory of it for every other chain.
fn default_data_dir(network_name: &str) -> String {
    let base = std::env::home_dir()
        .map(|home| home.join(".local").join("silver"))
        .unwrap_or_else(|| "/tmp/silver".into());
    let dir = if network_name == "mainnet" { base } else { base.join(network_name) };
    dir.to_string_lossy().into_owned()
}
