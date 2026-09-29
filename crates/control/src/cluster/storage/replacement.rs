use std::{io, path::Path};

use flux_disk::{DiskEvent, DiskIo, FileToken, OpenOptions, OperationId};
use raft::eraftpb::{Entry, HardState, Snapshot};

use super::{
    failed,
    journal::{LogState, Record, StorageIdentity},
};

pub(super) struct Replacement {
    pub file: FileToken,
    pub log: LogState,
    pub ready_number: Option<u64>,
    pub index: u64,
    phase: Phase,
}

enum Phase {
    SyncFile(OperationId),
    Rename,
    Renaming(OperationId),
    SyncDirectory,
    SyncingDirectory(OperationId),
}

impl Replacement {
    pub fn new(
        disk: &mut DiskIo,
        path: &Path,
        identity: &StorageIdentity,
        snapshot: &Snapshot,
        entries: &[Entry],
        hard_state: &HardState,
        ready_number: Option<u64>,
    ) -> io::Result<Self> {
        identity.validate_snapshot(snapshot)?;
        let log = LogState::from_snapshot(snapshot, hard_state)?.next(entries, Some(hard_state))?;
        let record = Record::checkpoint(snapshot, entries, hard_state)?;
        let mut staging = path.as_os_str().to_os_string();
        staging.push(".next");
        // Only the canonical path is authoritative. An interrupted replacement is
        // disposable.
        let file = disk.open(
            Path::new(&staging),
            OpenOptions::new().read(true).write(true).create(true).truncate(true),
        )?;
        if !disk.write_with(file, |output| {
            identity.write_checkpoint(output);
            record.write(output);
        }) {
            return Err(failed());
        }
        let sync = disk.sync_all(file).ok_or_else(failed)?;
        Ok(Self {
            file,
            log,
            ready_number,
            index: snapshot.get_metadata().index,
            phase: Phase::SyncFile(sync),
        })
    }

    pub fn advance(
        &mut self,
        disk: &mut DiskIo,
        path: &Path,
        directory: FileToken,
    ) -> io::Result<()> {
        match self.phase {
            Phase::Rename => {
                self.phase = Phase::Renaming(disk.rename(self.file, path)?.ok_or_else(failed)?);
            }
            Phase::SyncDirectory => {
                self.phase = Phase::SyncingDirectory(disk.sync_all(directory).ok_or_else(failed)?);
            }
            _ => {}
        }
        Ok(())
    }

    pub fn on_event(&mut self, event: DiskEvent<'_>, directory: FileToken) -> io::Result<bool> {
        match event {
            DiskEvent::Synced { file, operation_id } => match self.phase {
                Phase::SyncFile(expected) if file == self.file && operation_id == expected => {
                    self.phase = Phase::Rename;
                }
                Phase::SyncingDirectory(expected)
                    if file == directory && operation_id == expected =>
                {
                    return Ok(true)
                }
                _ => return Err(io::Error::other("unexpected checkpoint sync completion")),
            },
            DiskEvent::Renamed { file, operation_id } => match self.phase {
                Phase::Renaming(expected) if file == self.file && operation_id == expected => {
                    self.phase = Phase::SyncDirectory;
                }
                _ => return Err(io::Error::other("unexpected checkpoint rename completion")),
            },
            _ => {}
        }
        Ok(false)
    }
}
