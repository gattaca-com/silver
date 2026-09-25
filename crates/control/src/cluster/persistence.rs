use std::{io, path::PathBuf};

use raft::{
    Ready,
    eraftpb::{Entry, HardState, Message},
};

use super::node::AttestationClusterConfig;
#[cfg(target_os = "linux")]
use super::storage::{ClusterStorage, ClusterStorageEvent, StorageIdentity};

#[derive(Debug, Clone)]
pub enum ClusterStorageConfig {
    Create(PathBuf),
    Open(PathBuf),
}

#[derive(Debug, Default)]
pub struct RecoveredStorage {
    pub hard_state: HardState,
    /// Includes the uncommitted suffix; replay only entries through
    /// `hard_state.commit` into the state machine.
    pub entries: Vec<Entry>,
}

pub(super) struct PersistedReady {
    pub number: u64,
    pub messages: Vec<Message>,
    pub committed_entries: Vec<Entry>,
    wait_for_disk: bool,
}

pub(super) enum PersistenceEvent {
    #[cfg(target_os = "linux")]
    Recovered(RecoveredStorage),
    Persisted(PersistedReady),
}

pub(super) struct Persistence {
    #[cfg(target_os = "linux")]
    disk: Option<ClusterStorage>,
    pending: Option<PersistedReady>,
    #[cfg(test)]
    pub paused: bool,
    #[cfg(test)]
    pub fail: bool,
}

impl Persistence {
    pub fn new(config: &AttestationClusterConfig) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let identity = StorageIdentity::new(config.node_id, config.voters.clone())?;
            let disk = match &config.storage {
                ClusterStorageConfig::Create(path) => ClusterStorage::create(path, identity)?,
                ClusterStorageConfig::Open(path) => ClusterStorage::open(path, identity)?,
            };
            Ok(Self {
                disk: Some(disk),
                pending: None,
                #[cfg(test)]
                paused: false,
                #[cfg(test)]
                fail: false,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = config;
            Err(io::Error::new(io::ErrorKind::Unsupported, "Raft persistence requires Linux"))
        }
    }

    #[cfg(test)]
    pub fn memory() -> Self {
        Self {
            #[cfg(target_os = "linux")]
            disk: None,
            pending: None,
            paused: false,
            fail: false,
        }
    }

    pub fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    pub fn submit(&mut self, ready: &mut Ready) -> io::Result<()> {
        if self.pending.is_some() {
            return Err(io::Error::other("Raft persistence already has a pending Ready"));
        }
        let wait_for_disk = !ready.entries().is_empty() || ready.hs().is_some();
        #[cfg(target_os = "linux")]
        if wait_for_disk && let Some(disk) = &mut self.disk {
            disk.persist(ready.number(), ready.entries(), ready.hs())?;
        }
        self.pending = Some(PersistedReady {
            number: ready.number(),
            messages: ready.take_persisted_messages(),
            committed_entries: ready.take_committed_entries(),
            wait_for_disk,
        });
        Ok(())
    }

    pub fn poll(&mut self) -> io::Result<Option<PersistenceEvent>> {
        #[cfg(test)]
        {
            if self.fail {
                return Err(io::Error::other("injected Raft persistence failure"));
            }
            if self.paused {
                return Ok(None);
            }
        }

        if self.pending.as_ref().is_some_and(|pending| !pending.wait_for_disk) {
            return Ok(self.pending.take().map(PersistenceEvent::Persisted));
        }
        #[cfg(target_os = "linux")]
        if let Some(disk) = &mut self.disk {
            return match disk.poll()? {
                Some(ClusterStorageEvent::Recovered(recovered)) if self.pending.is_none() => {
                    Ok(Some(PersistenceEvent::Recovered(recovered)))
                }
                Some(ClusterStorageEvent::Persisted { ready_number }) => {
                    let pending = self
                        .pending
                        .take()
                        .filter(|pending| pending.number == ready_number)
                        .ok_or_else(|| {
                            io::Error::other("unexpected Raft persistence completion")
                        })?;
                    Ok(Some(PersistenceEvent::Persisted(pending)))
                }
                Some(_) => Err(io::Error::other("unexpected Raft recovery completion")),
                None => Ok(None),
            };
        }
        Ok(self.pending.take().map(PersistenceEvent::Persisted))
    }
}
