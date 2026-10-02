use std::{
    io,
    path::{Path, PathBuf},
};

use silver_beacon_state_data::{B256, CheckpointState, SLOTS_PER_EPOCH, SpecConfig};
use silver_config::{ChainConfig, Genesis};
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
    /// The configured `checkpoint_file`, else a provider download when the
    /// persisted checkpoint is missing or behind, else the persisted one.
    pub fn load(chain_config: &ChainConfig) -> io::Result<Self> {
        if let Some(file) = &chain_config.checkpoint_file {
            return Self::from_file(file, chain_config.checkpoint_pubkeys_file.as_deref());
        }

        let local = latest_local_checkpoint(&chain_config.data_dir);
        let local_head =
            local.as_ref().map(|(slot, ssz, _)| (slot / SLOTS_PER_EPOCH, ssz.as_path()));
        match Self::download_if_behind(chain_config, local_head)? {
            Some(downloaded) => Ok(downloaded),
            None => Self::persisted(local, &chain_config.data_dir),
        }
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

    fn from_file(file: &str, pubkeys_file: Option<&str>) -> io::Result<Self> {
        silver_log::info!("using the config checkpoint at {}", file);
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

        let mut providers = CheckpointProviders::new(&chain_config.checkpoint_sync_urls);
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
