use std::{
    io,
    path::{Path, PathBuf},
};

use silver_beacon_state_data::{B256, CheckpointState, SLOTS_PER_EPOCH, SpecConfig};
use silver_config::{BootSource, ChainConfig, Genesis};
use silver_storage::latest_local_checkpoint;

use self::checkpoint_providers::CheckpointProviders;

mod checkpoint_providers;

/// Untuned guess: catching up 32 epochs from disk beats a ~340 MB download.
const MAX_LOCAL_LAG_EPOCHS: u64 = 32;

pub struct BootCheckpoint {
    ssz: Vec<u8>,
    pubkeys: Vec<u8>,
    /// Set for a download: the agreed block root the state must anchor to.
    expected_root: Option<B256>,
}

impl BootCheckpoint {
    pub fn load(chain_config: &ChainConfig) -> io::Result<Self> {
        let checkpoint = Self::load_unchecked(chain_config)?;
        checkpoint.check_chain(chain_config)?;
        Ok(checkpoint)
    }

    fn load_unchecked(chain_config: &ChainConfig) -> io::Result<Self> {
        let data_dir = &chain_config.data_dir;
        match &chain_config.boot {
            BootSource::File { ssz, pubkeys } => Self::from_file(ssz, pubkeys.as_deref()),
            BootSource::Providers(urls) => {
                let local = latest_local_checkpoint(data_dir);
                let local_head =
                    local.as_ref().map(|(slot, ssz, _)| (slot / SLOTS_PER_EPOCH, ssz.as_path()));
                match Self::download_if_behind(chain_config, urls, local_head)? {
                    Some(downloaded) => Ok(downloaded),
                    None => Self::persisted(local, data_dir),
                }
            }
        }
    }

    fn check_chain(&self, chain_config: &ChainConfig) -> io::Result<()> {
        let expected = chain_config.genesis_validators_root;
        let genesis = Genesis::from_state(&self.ssz).map_err(io::Error::other)?;
        if genesis.validators_root != expected {
            return Err(io::Error::other(format!(
                "boot state has genesis_validators_root 0x{}, but {}'s is 0x{}: it is from \
                 another chain",
                hex::encode(genesis.validators_root),
                chain_config.spec.network_name(),
                hex::encode(expected)
            )));
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.ssz.is_empty()
    }

    pub fn ssz(&self) -> &[u8] {
        &self.ssz
    }

    /// Consumes the SSZ, so a download is freed before the node runs.
    pub fn decompose(self, spec: &SpecConfig) -> CheckpointState {
        match self.expected_root {
            Some(block_root) => CheckpointState::downloaded(&self.ssz, spec, block_root),
            None => CheckpointState::trusted(&self.ssz, spec, &self.pubkeys),
        }
    }

    fn from_file(file: &Path, pubkeys_file: Option<&Path>) -> io::Result<Self> {
        silver_log::info!("using the config checkpoint at {}", file.display());
        let ssz = std::fs::read(file)?;
        let pubkeys = match pubkeys_file {
            Some(file) if !ssz.is_empty() => std::fs::read(file)?,
            _ => vec![],
        };
        Ok(Self { ssz, pubkeys, expected_root: None })
    }

    /// `None` keeps the persisted checkpoint: it is recent by the wall clock
    /// (no network call), no providers are configured, they are unusable while
    /// one exists, or it is close to their finalized epoch.
    fn download_if_behind(
        chain_config: &ChainConfig,
        urls: &[String],
        local: Option<(u64, &Path)>,
    ) -> io::Result<Option<Self>> {
        let local_epoch = local.map(|(epoch, _)| epoch);
        if let Some((epoch, ssz)) = local {
            let genesis = Genesis::from_state_file(ssz).map_err(io::Error::other)?;
            let lag = chain_config.wall_epoch(&genesis).saturating_sub(epoch);
            if lag <= MAX_LOCAL_LAG_EPOCHS {
                return Ok(None);
            }
        }

        let mut providers = CheckpointProviders::new(urls);
        if providers.is_empty() {
            return Ok(None);
        }

        let finalized = match providers.agreed_finalized() {
            Ok(finalized) => finalized,
            Err(e) if local_epoch.is_some() => {
                silver_log::warn!(%e, "checkpoint providers unusable; using the persisted one");
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        if let Some(epoch) = local_epoch {
            let lag = finalized.epoch.saturating_sub(epoch);
            silver_log::info!(lag, "persisted checkpoint lag behind the providers");
            if lag <= MAX_LOCAL_LAG_EPOCHS {
                return Ok(None);
            }
        }

        let ssz = providers.download(finalized)?;
        Ok(Some(Self { ssz, pubkeys: vec![], expected_root: Some(finalized.root) }))
    }

    fn persisted(
        local: Option<(u64, PathBuf, Option<PathBuf>)>,
        data_dir: &str,
    ) -> io::Result<Self> {
        let Some((slot, ssz_path, pubkeys_path)) = local else {
            return Err(io::Error::other(format!(
                "no checkpoint_file, no checkpoint_sync_urls answer, and none persisted under \
                 {data_dir}"
            )));
        };
        silver_log::info!(
            slot,
            "checkpoint not set in the config, booting from the latest persisted one."
        );
        let pubkeys = pubkeys_path.map(std::fs::read).transpose()?.unwrap_or_default();
        Ok(Self { ssz: std::fs::read(ssz_path)?, pubkeys, expected_root: None })
    }
}

#[cfg(test)]
mod tests {
    use silver_config::{Config, Network, Overrides};
    use tempfile::TempDir;

    use super::*;

    fn mainnet_boot_from(dir: &Path, validators_root: [u8; 32]) -> io::Result<BootCheckpoint> {
        let ssz = dir.join("state.ssz");
        let mut head = 1_606_824_023u64.to_le_bytes().to_vec();
        head.extend_from_slice(&validators_root);
        std::fs::write(&ssz, head).unwrap();
        let toml = dir.join("silver.toml");
        let data_dir = dir.join("data");
        std::fs::write(
            &toml,
            format!(
                "data_storage_dir = \"{}\"\n[chain_config]\ncheckpoint_file = \"{}\"\n",
                data_dir.display(),
                ssz.display()
            ),
        )
        .unwrap();
        let chain_config =
            Config::load(toml.to_str(), Overrides::default()).unwrap().chain().unwrap();
        BootCheckpoint::load(&chain_config)
    }

    #[test]
    fn boot_state_from_another_chain_refused() {
        let dir = TempDir::new().unwrap();
        let mainnet = Network::Mainnet.genesis_validators_root().unwrap();
        assert!(mainnet_boot_from(dir.path(), mainnet).is_ok());

        let hoodi = Network::Hoodi.genesis_validators_root().unwrap();
        let err = mainnet_boot_from(dir.path(), hoodi).err().unwrap();
        assert!(err.to_string().contains("another chain"), "{err}");
    }
}
