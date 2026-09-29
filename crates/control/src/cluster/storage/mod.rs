mod journal;
mod replacement;

use std::{
    io, mem,
    path::{Path, PathBuf},
};

use flux_disk::{DiskConfig, DiskEvent, DiskIo, FileToken, OpenOptions, OperationId};
pub use journal::StorageIdentity;
use journal::{JournalReplay, LogState, READ_CHUNK_BYTES, Record};
use raft::eraftpb::{Entry, HardState, Snapshot};
use replacement::Replacement;

use super::persistence::RecoveredStorage;

#[derive(Debug)]
pub enum ClusterStorageEvent {
    Recovered(RecoveredStorage),
    Persisted { ready_number: u64 },
    Compacted { index: u64 },
}

/// Keeps one persistence batch in flight. Completion always means durable, not
/// merely written. The caller must exclusively own the journal path for this
/// instance's lifetime.
pub struct ClusterStorage {
    disk: DiskIo,
    state: StorageState,
}

impl ClusterStorage {
    pub fn create(path: &Path, identity: StorageIdentity) -> io::Result<Self> {
        Self::start(path, identity, true)
    }

    /// Missing journals are errors; recovery must never silently bootstrap a
    /// fresh voter.
    pub fn open(path: &Path, identity: StorageIdentity) -> io::Result<Self> {
        Self::start(path, identity, false)
    }

    fn start(path: &Path, identity: StorageIdentity, create: bool) -> io::Result<Self> {
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut disk = DiskIo::new(DiskConfig::default())?;
        let directory = disk.open_directory(parent)?;
        let file = disk.open(path, OpenOptions::new().read(true).write(true).create_new(create))?;
        let (phase, replay) = if create {
            (Phase::Creating(identity.clone()), None)
        } else {
            (Phase::ReadNext { offset: 0 }, Some(JournalReplay::new(identity.clone())))
        };
        let mut state = StorageState {
            file,
            directory,
            path: path.to_path_buf(),
            identity,
            retired_file: None,
            appended_bytes: 0,
            phase,
            replay,
            recovered: None,
            log: LogState::default(),
            last_ready_number: 0,
        };
        state.advance(&mut disk)?;
        Ok(Self { disk, state })
    }

    pub fn is_ready(&self) -> bool {
        matches!(self.state.phase, Phase::Ready)
    }

    pub fn appended_bytes(&self) -> u64 {
        self.state.appended_bytes
    }

    pub fn checkpoint(
        &mut self,
        ready_number: Option<u64>,
        snapshot: &Snapshot,
        entries: &[Entry],
        hard_state: &HardState,
    ) -> io::Result<()> {
        if !self.is_ready() {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "Raft storage is busy"));
        }
        if ready_number.is_some_and(|number| number <= self.state.last_ready_number) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Raft Ready numbers must increase",
            ));
        }
        let previous = &self.state.log.hard_state;
        if hard_state.term < previous.term ||
            hard_state.commit < previous.commit ||
            (hard_state.term == previous.term &&
                previous.vote != 0 &&
                hard_state.vote != previous.vote)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "checkpoint hard state regressed",
            ));
        }
        let next =
            LogState::from_snapshot(snapshot, hard_state)?.next(entries, Some(hard_state))?;
        if ready_number.is_none() &&
            (snapshot.get_metadata().index > previous.commit || next != self.state.log)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "local checkpoint must preserve the durable log suffix and hard state",
            ));
        }
        if ready_number.is_some() && snapshot.get_metadata().index < previous.commit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "incoming snapshot precedes durable commit",
            ));
        }
        let replacement = Replacement::new(
            &mut self.disk,
            &self.state.path,
            &self.state.identity,
            snapshot,
            entries,
            hard_state,
            ready_number,
        );
        match replacement {
            Ok(replacement) => self.state.phase = Phase::Replacing(replacement),
            Err(error) => {
                self.state.phase = Phase::Failed;
                return Err(error);
            }
        }
        Ok(())
    }

    /// Entries are a contiguous append or an uncommitted suffix replacement, as
    /// supplied by Raft's `Ready`. Even commit-only batches are synced in
    /// this initial implementation.
    pub fn persist(
        &mut self,
        ready_number: u64,
        entries: &[Entry],
        hard_state: Option<&HardState>,
    ) -> io::Result<()> {
        match self.state.phase {
            Phase::Ready => {}
            Phase::Failed => return Err(failed()),
            _ => return Err(io::Error::new(io::ErrorKind::WouldBlock, "Raft storage is busy")),
        }
        if ready_number <= self.state.last_ready_number {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Raft Ready numbers must increase",
            ));
        }
        let next = self.state.log.next(entries, hard_state)?;
        let record = Record::new(entries, hard_state)?;
        self.state.appended_bytes = self.state.appended_bytes.saturating_add(record.len());
        if !self.disk.write_with(self.state.file, |output| record.write(output)) {
            self.state.phase = Phase::Failed;
            return Err(failed());
        }
        let Some(sync) = self.disk.sync_data(self.state.file) else {
            self.state.phase = Phase::Failed;
            return Err(failed());
        };
        self.state.phase = Phase::SyncingBatch { sync, ready_number, next };
        Ok(())
    }

    pub fn poll(&mut self) -> io::Result<Option<ClusterStorageEvent>> {
        let mut result = Ok(None);
        self.disk.poll_with(|event| {
            if result.is_err() {
                return;
            }
            match self.state.on_event(event) {
                Ok(Some(event)) => result = Ok(Some(event)),
                Ok(None) => {}
                Err(error) => result = Err(error),
            }
        });
        if result.is_ok() {
            if let Err(error) = self.state.advance(&mut self.disk) {
                result = Err(error);
            }
        }
        if result.is_err() {
            self.state.phase = Phase::Failed;
        }
        result
    }
}

enum Phase {
    Creating(StorageIdentity),
    ReadNext { offset: u64 },
    Reading { offset: u64 },
    Repair { truncate: bool, valid_len: u64 },
    SyncingLog { sync: OperationId },
    SyncDirectory,
    SyncingDirectory { sync: OperationId },
    Ready,
    SyncingBatch { sync: OperationId, ready_number: u64, next: LogState },
    Replacing(Replacement),
    Failed,
}

struct StorageState {
    file: FileToken,
    directory: FileToken,
    path: PathBuf,
    identity: StorageIdentity,
    retired_file: Option<FileToken>,
    appended_bytes: u64,
    phase: Phase,
    replay: Option<JournalReplay>,
    recovered: Option<RecoveredStorage>,
    log: LogState,
    last_ready_number: u64,
}

impl StorageState {
    fn advance(&mut self, disk: &mut DiskIo) -> io::Result<()> {
        if let Some(file) = self.retired_file.take() &&
            !disk.close(file)
        {
            return Err(failed());
        }
        match &mut self.phase {
            Phase::Replacing(replacement) => {
                replacement.advance(disk, &self.path, self.directory)?
            }
            Phase::Creating(identity) => {
                if !disk.write_with(self.file, |output| identity.write(output)) {
                    return Err(failed());
                }
                self.recovered = Some(RecoveredStorage::default());
                let sync = disk.sync_all(self.file).ok_or_else(failed)?;
                self.phase = Phase::SyncingLog { sync };
            }
            Phase::ReadNext { offset } => {
                if !disk.read_at(self.file, *offset, READ_CHUNK_BYTES) {
                    return Err(failed());
                }
                self.phase = Phase::Reading { offset: *offset };
            }
            Phase::Repair { truncate, valid_len } => {
                if *truncate {
                    disk.truncate(self.file, *valid_len).ok_or_else(failed)?;
                }
                if !disk.set_write_cursor(self.file, *valid_len) {
                    return Err(failed());
                }
                let sync = disk.sync_all(self.file).ok_or_else(failed)?;
                self.phase = Phase::SyncingLog { sync };
            }
            Phase::SyncDirectory => {
                // File tokens have independent queues; sync the directory only after the file
                // sync completes.
                let sync = disk.sync_all(self.directory).ok_or_else(failed)?;
                self.phase = Phase::SyncingDirectory { sync };
            }
            Phase::Failed => return Err(failed()),
            _ => {}
        }
        Ok(())
    }

    fn on_event(&mut self, event: DiskEvent<'_>) -> io::Result<Option<ClusterStorageEvent>> {
        if matches!(self.phase, Phase::Failed) {
            return Ok(None);
        }
        if let DiskEvent::Failed { op, error, .. } = event {
            self.phase = Phase::Failed;
            return Err(io::Error::new(error.kind(), format!("Raft journal {op:?}: {error}")));
        }
        if let Phase::Replacing(replacement) = &mut self.phase {
            if !replacement.on_event(event, self.directory)? {
                return Ok(None);
            }
            let Phase::Replacing(replacement) = mem::replace(&mut self.phase, Phase::Ready) else {
                return Err(failed());
            };
            self.retired_file = Some(mem::replace(&mut self.file, replacement.file));
            self.log = replacement.log;
            self.appended_bytes = 0;
            return Ok(Some(match replacement.ready_number {
                Some(ready_number) => {
                    self.last_ready_number = ready_number;
                    ClusterStorageEvent::Persisted { ready_number }
                }
                None => ClusterStorageEvent::Compacted { index: replacement.index },
            }));
        }
        match event {
            DiskEvent::Read { file, offset, payload, eof } => {
                if file != self.file ||
                    !matches!(self.phase, Phase::Reading { offset: expected } if expected == offset)
                {
                    return Err(io::Error::other("unexpected Raft journal read completion"));
                }
                let replay = self.replay.as_mut().ok_or_else(failed)?;
                replay.feed(payload)?;
                if eof {
                    let truncate = replay.finish()?;
                    let replay = self.replay.take().ok_or_else(failed)?;
                    self.log = replay.log;
                    self.appended_bytes = replay.appended_bytes;
                    self.recovered = Some(replay.recovered);
                    self.phase = Phase::Repair { truncate, valid_len: replay.valid_len };
                } else {
                    let offset = offset
                        .checked_add(payload.len() as u64)
                        .ok_or_else(|| io::Error::other("Raft journal offset overflow"))?;
                    self.phase = Phase::ReadNext { offset };
                }
            }
            DiskEvent::Synced { file, operation_id } => match &self.phase {
                Phase::SyncingLog { sync } if file == self.file && *sync == operation_id => {
                    self.phase = Phase::SyncDirectory;
                }
                Phase::SyncingDirectory { sync }
                    if file == self.directory && *sync == operation_id =>
                {
                    let recovered = self.recovered.take().ok_or_else(failed)?;
                    self.phase = Phase::Ready;
                    return Ok(Some(ClusterStorageEvent::Recovered(recovered)));
                }
                Phase::SyncingBatch { sync, ready_number, next }
                    if file == self.file && *sync == operation_id =>
                {
                    let ready_number = *ready_number;
                    self.log = next.clone();
                    self.last_ready_number = ready_number;
                    self.phase = Phase::Ready;
                    return Ok(Some(ClusterStorageEvent::Persisted { ready_number }));
                }
                _ => return Err(io::Error::other("unexpected Raft journal sync completion")),
            },
            _ => {}
        }
        Ok(None)
    }
}

fn failed() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "Raft storage is failed; restart and recover before proceeding",
    )
}

#[cfg(test)]
mod compaction_tests;
#[cfg(test)]
mod tests;
