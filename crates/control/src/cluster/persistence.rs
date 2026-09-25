use std::{io, path::PathBuf};

use raft::{
    Ready,
    eraftpb::{Entry, HardState, Message, Snapshot},
};

#[cfg(target_os = "linux")]
use super::storage::{ClusterStorage, ClusterStorageEvent, StorageIdentity};
use super::{node::AttestationClusterConfig, raft_storage::RestoredSnapshot};

#[derive(Debug, Clone)]
pub enum ClusterStorageConfig {
    Create(PathBuf),
    Open(PathBuf),
}

#[derive(Debug, Default)]
pub struct RecoveredStorage {
    pub hard_state: HardState,
    pub snapshot: Snapshot,
    /// Includes the uncommitted suffix; replay only entries through
    /// `hard_state.commit` into the state machine.
    pub entries: Vec<Entry>,
}

pub(super) struct PersistedReady {
    pub number: u64,
    pub messages: Vec<Message>,
    pub committed_entries: Vec<Entry>,
    pub snapshot: Option<RestoredSnapshot>,
    wait_for_disk: bool,
}

pub(super) enum PersistenceEvent {
    #[cfg(target_os = "linux")]
    Recovered(RecoveredStorage),
    Persisted(PersistedReady),
    Compacted(Snapshot),
}

enum Pending {
    Ready(PersistedReady),
    Compact(Snapshot),
}

impl Pending {
    fn into_event(self) -> PersistenceEvent {
        match self {
            Self::Ready(ready) => PersistenceEvent::Persisted(ready),
            Self::Compact(snapshot) => PersistenceEvent::Compacted(snapshot),
        }
    }
}

pub(super) struct Persistence {
    #[cfg(target_os = "linux")]
    disk: Option<ClusterStorage>,
    pending: Option<Pending>,
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

    pub fn compaction_due(&self) -> bool {
        #[cfg(target_os = "linux")]
        if let Some(disk) = &self.disk {
            return disk.appended_bytes() >= 16 * 1024 * 1024;
        }
        false
    }

    pub fn compact(
        &mut self,
        snapshot: Snapshot,
        entries: &[Entry],
        hard_state: &HardState,
    ) -> io::Result<()> {
        if self.is_pending() {
            return Err(io::Error::other("Raft persistence already has pending work"));
        }
        #[cfg(target_os = "linux")]
        if let Some(disk) = &mut self.disk {
            disk.checkpoint(None, &snapshot, entries, hard_state)?;
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (entries, hard_state);
        self.pending = Some(Pending::Compact(snapshot));
        Ok(())
    }

    pub fn submit(
        &mut self,
        ready: &mut Ready,
        snapshot: Option<RestoredSnapshot>,
    ) -> io::Result<()> {
        if self.pending.is_some() {
            return Err(io::Error::other("Raft persistence already has a pending Ready"));
        }
        let wait_for_disk =
            !ready.entries().is_empty() || ready.hs().is_some() || snapshot.is_some();
        #[cfg(target_os = "linux")]
        if wait_for_disk && let Some(disk) = &mut self.disk {
            if snapshot.is_some() {
                disk.checkpoint(
                    Some(ready.number()),
                    ready.snapshot(),
                    ready.entries(),
                    ready
                        .hs()
                        .ok_or_else(|| io::Error::other("Raft snapshot Ready has no hard state"))?,
                )?;
            } else {
                disk.persist(ready.number(), ready.entries(), ready.hs())?;
            }
        }
        self.pending = Some(Pending::Ready(PersistedReady {
            number: ready.number(),
            messages: ready.take_persisted_messages(),
            committed_entries: ready.take_committed_entries(),
            snapshot,
            wait_for_disk,
        }));
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

        if matches!(&self.pending, Some(Pending::Ready(ready)) if !ready.wait_for_disk) {
            return Ok(self.pending.take().map(Pending::into_event));
        }
        #[cfg(target_os = "linux")]
        if let Some(disk) = &mut self.disk {
            return match disk.poll()? {
                Some(ClusterStorageEvent::Recovered(recovered)) if self.pending.is_none() => {
                    Ok(Some(PersistenceEvent::Recovered(recovered)))
                }
                Some(ClusterStorageEvent::Persisted { ready_number }) => {
                    match self.pending.take() {
                        Some(Pending::Ready(ready)) if ready.number == ready_number => {
                            Ok(Some(PersistenceEvent::Persisted(ready)))
                        }
                        _ => Err(io::Error::other("unexpected Raft persistence completion")),
                    }
                }
                Some(ClusterStorageEvent::Compacted { index }) => match self.pending.take() {
                    Some(Pending::Compact(snapshot)) if snapshot.get_metadata().index == index => {
                        Ok(Some(PersistenceEvent::Compacted(snapshot)))
                    }
                    _ => Err(io::Error::other("unexpected Raft compaction completion")),
                },
                Some(_) => Err(io::Error::other("unexpected Raft recovery completion")),
                None => Ok(None),
            };
        }
        Ok(self.pending.take().map(Pending::into_event))
    }
}
