use std::{
    error::Error,
    fs::{File, OpenOptions},
    io,
    path::Path,
};

use silver_common::Enr;
use silver_config::ClusterConfig;
use silver_control::cluster::{AttestationClusterConfig, ClusterStorageConfig};

pub struct ClusterStartup {
    pub config: AttestationClusterConfig,
    _journal_lock: File,
}

impl ClusterStartup {
    pub fn new(
        config: &ClusterConfig,
        local: &Enr,
        directory: &Path,
    ) -> Result<Self, Box<dyn Error>> {
        let node_id = config
            .nodes
            .iter()
            .find(|(_, enr)| enr.node_id() == local.node_id())
            .map(|(id, _)| *id)
            .ok_or("no local node configured in cluster config")?;
        let journal_lock = Self::lock(directory)?;
        let path = directory.join("attestation-cluster.wal");
        let storage = if config.bootstrap {
            ClusterStorageConfig::Create(path)
        } else {
            ClusterStorageConfig::Open(path)
        };
        Ok(Self {
            config: AttestationClusterConfig::new(
                node_id,
                config.nodes.keys().copied().collect(),
                storage,
            ),
            _journal_lock: journal_lock,
        })
    }

    fn lock(directory: &Path) -> io::Result<File> {
        // Retain the lock file: removing it could let processes lock different inodes.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join("attestation-cluster.lock"))?;
        file.try_lock().map_err(|error| {
            io::Error::other(format!("cannot lock attestation cluster journal: {error}"))
        })?;
        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_lock_is_exclusive_until_the_process_guard_is_dropped() {
        let directory = tempfile::tempdir().unwrap();
        let first = ClusterStartup::lock(directory.path()).unwrap();
        assert!(ClusterStartup::lock(directory.path()).is_err());
        drop(first);
        let _second = ClusterStartup::lock(directory.path()).unwrap();
    }
}
