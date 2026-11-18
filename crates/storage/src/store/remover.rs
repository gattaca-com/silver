use std::{
    collections::VecDeque,
    fs::ReadDir,
    io::{Error, ErrorKind},
    os::fd::{AsRawFd, RawFd},
    path::PathBuf,
};

use flux_disk::{DiskEvent, DiskIo, FailedOp};

use super::file_writer::DirectoryTokens;

/// Bounds the unlinks in flight and the entries listed per turn: a 16k-file
/// column group neither stalls a turn nor grows the queue.
const MAX_QUEUED: usize = 256;
const MAX_LISTED_PER_TURN: usize = 32;

/// Removes directories with the files in them, a bounded batch per turn. One
/// directory is listed at a time, and its `remove_dir` waits for every unlink
/// in flight.
pub(super) struct DirectoryRemover {
    disk: DiskIo,
    directory: DirectoryTokens,
    directories: VecDeque<PathBuf>,
    listing: Option<(PathBuf, ReadDir)>,
    queued: usize,
}

impl DirectoryRemover {
    pub(super) fn new(store_dir: &str) -> Result<Self, Error> {
        let mut disk = super::disk_ring()?;
        Ok(Self {
            directory: DirectoryTokens::open(&mut disk, store_dir)?,
            disk,
            directories: VecDeque::new(),
            listing: None,
            queued: 0,
        })
    }

    pub(super) fn remove(&mut self, directory: PathBuf) {
        self.directories.push_back(directory);
    }

    pub(super) fn ring_fd(&mut self) -> RawFd {
        self.disk.submit();
        self.disk.as_raw_fd()
    }

    pub(super) fn step(&mut self) -> bool {
        self.reap();
        self.queue_removals()
    }

    fn reap(&mut self) {
        let queued = &mut self.queued;
        self.disk.poll_with(|event| match event {
            DiskEvent::Unlinked { .. } => *queued -= 1,
            DiskEvent::Failed { op: FailedOp::Unlink, error, .. } => {
                *queued -= 1;
                if error.kind() != ErrorKind::NotFound {
                    silver_log::warn!(?error, "directory removal op failed");
                }
            }
            DiskEvent::Failed { op, error, .. } => {
                silver_log::warn!(?op, ?error, "directory removal op failed");
            }
            _ => {}
        });
    }

    fn queue_removals(&mut self) -> bool {
        for turn in 0..MAX_LISTED_PER_TURN {
            if self.queued == MAX_QUEUED {
                return turn > 0;
            }
            let Some((directory, listing)) = self.listing.as_mut() else {
                let Some(directory) = self.directories.pop_front() else { return turn > 0 };
                match std::fs::read_dir(&directory) {
                    Ok(listing) => self.listing = Some((directory, listing)),
                    Err(error) if error.kind() == ErrorKind::NotFound => {}
                    Err(error) => silver_log::warn!(?error, ?directory, "directory listing failed"),
                }
                continue;
            };
            let queued = match listing.next() {
                Some(Ok(entry)) => self.disk.unlink(self.directory.next(), entry.path()),
                Some(Err(error)) => {
                    silver_log::warn!(?error, ?directory, "directory listing failed");
                    self.listing = None;
                    continue;
                }
                None if self.queued > 0 => return turn > 0,
                None => {
                    let (directory, _) = self.listing.take().expect("listing present");
                    self.disk.remove_dir(self.directory.next(), directory)
                }
            };
            if let Ok(Some(_)) = queued {
                self.queued += 1;
            }
        }
        true
    }

    #[cfg(test)]
    pub(super) fn is_idle(&self) -> bool {
        self.directories.is_empty() && self.listing.is_none() && self.queued == 0
    }
}
