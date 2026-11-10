use std::{
    error::Error,
    fs::{File, OpenOptions},
    io,
    path::{Path, PathBuf},
};

use silver_common::Enr;
use silver_config::ClusterConfig;
use silver_control::cluster::{
    ClusterStorageConfig, MemberAddress, SlashingProtectionConfig, StorageIdentity,
};

const JOURNAL_FILE: &str = "attestation-cluster.wal";

pub struct ClusterStartup {
    pub config: SlashingProtectionConfig,
    _journal_lock: File,
}

impl ClusterStartup {
    pub fn new(
        config: &ClusterConfig,
        local: &Enr,
        directory: &Path,
    ) -> Result<Self, Box<dyn Error>> {
        let (node_id, advertised) = Self::local_member(config, local)?;
        let voters = || config.nodes.keys().copied();
        let identity = StorageIdentity::new(node_id, voters())?;
        let journal_lock = Self::lock(directory)?;
        let storage = Self::journal(config.bootstrap, directory.join(JOURNAL_FILE))?;
        Self::check_identity(&storage, &identity)?;
        Ok(Self {
            config: SlashingProtectionConfig::new(node_id, voters(), advertised, storage)?,
            _journal_lock: journal_lock,
        })
    }

    /// Standalone locks live in memory only. A journal left by a clustered
    /// run holds lock history this node no longer checks against.
    pub fn warn_unused_journal(directory: &Path) {
        let journal = directory.join(JOURNAL_FILE);
        if journal.exists() {
            silver_log::warn!(
                journal = %journal.display(),
                "clustering is off, but a cluster journal exists: slashing protection now keeps \
                 locks in memory only and ignores the cluster's lock history"
            );
        }
    }

    /// The local entry is the ENR the other members dial, so its address is
    /// the one announced to them.
    fn local_member(
        config: &ClusterConfig,
        local: &Enr,
    ) -> Result<(u64, MemberAddress), Box<dyn Error>> {
        let local = local.node_id();
        let (&id, enr) = config
            .nodes
            .iter()
            .find(|(_, enr)| enr.node_id() == local)
            .ok_or("no local node configured in cluster config")?;
        let addr = enr
            .quic4_socket()
            .or_else(|| enr.quic6_socket())
            .ok_or_else(|| format!("cluster config ENR of node {id} has no QUIC address"))?;
        Ok((id, MemberAddress { public_key: enr.public_key().serialize(), addr }))
    }

    /// A journal that contradicts `bootstrap` would only fail later, inside
    /// Control, and leave the node running with the cluster refusing every
    /// duty.
    fn journal(bootstrap: bool, path: PathBuf) -> Result<ClusterStorageConfig, Box<dyn Error>> {
        match (bootstrap, path.try_exists()?) {
            (true, false) => Ok(ClusterStorageConfig::Create(path)),
            (false, true) => Ok(ClusterStorageConfig::Open(path)),
            (true, true) => Err(format!(
                "cluster bootstrap = true, but {} already exists: set bootstrap = false",
                path.display()
            )
            .into()),
            (false, false) => Err(format!(
                "cluster journal {} is missing: restore it, never bootstrap a single node over it",
                path.display()
            )
            .into()),
        }
    }

    /// An existing journal written for another node would likewise fail only
    /// inside Control.
    fn check_identity(
        storage: &ClusterStorageConfig,
        identity: &StorageIdentity,
    ) -> Result<(), Box<dyn Error>> {
        let ClusterStorageConfig::Open(path) = storage else {
            return Ok(());
        };
        identity
            .check_journal(path)
            .map_err(|error| format!("cluster journal {}: {error}", path.display()).into())
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

    #[test]
    fn journal_must_agree_with_bootstrap() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("attestation-cluster.wal");

        assert!(matches!(
            ClusterStartup::journal(true, path.clone()),
            Ok(ClusterStorageConfig::Create(_))
        ));
        assert!(ClusterStartup::journal(false, path.clone()).is_err(), "missing journal");

        File::create(&path).unwrap();
        assert!(matches!(
            ClusterStartup::journal(false, path.clone()),
            Ok(ClusterStorageConfig::Open(_))
        ));
        assert!(ClusterStartup::journal(true, path).is_err(), "bootstrap over a journal");
    }
}
