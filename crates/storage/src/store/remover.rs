use std::{
    collections::VecDeque,
    fs::ReadDir,
    io::{Error, ErrorKind},
    path::PathBuf,
};

use flux_disk::{DiskEvent, DiskIo, FileToken};

/// Bounds the unlinks queued at once, and so the entries listed per turn: a
/// 16k-file column group neither stalls a turn nor grows the queue.
const MAX_QUEUED: usize = 256;

/// Removes directories with the files in them, a bounded batch per turn. Every
/// unlink and the closing `remove_dir` are ordered on one directory token, so
/// a directory goes only after its files.
pub(super) struct DirectoryRemover {
    disk: DiskIo,
    order: FileToken,
    directories: VecDeque<PathBuf>,
    listing: Option<(PathBuf, ReadDir)>,
    queued: usize,
}

impl DirectoryRemover {
    pub(super) fn new(store_dir: &str) -> Result<Self, Error> {
        let mut disk = super::disk_ring()?;
        Ok(Self {
            order: disk.open_directory(store_dir)?,
            disk,
            directories: VecDeque::new(),
            listing: None,
            queued: 0,
        })
    }

    pub(super) fn remove(&mut self, directory: PathBuf) {
        self.directories.push_back(directory);
    }

    pub(super) fn step(&mut self) {
        let queued = &mut self.queued;
        self.disk.poll_with(|event| match event {
            DiskEvent::Unlinked { .. } => *queued -= 1,
            DiskEvent::Failed { op, error, .. } => {
                *queued -= 1;
                if error.kind() != ErrorKind::NotFound {
                    silver_log::warn!(?op, ?error, "directory removal op failed");
                }
            }
            _ => {}
        });

        while self.queued < MAX_QUEUED {
            let Some((directory, listing)) = self.listing.as_mut() else {
                let Some(directory) = self.directories.pop_front() else { return };
                match std::fs::read_dir(&directory) {
                    Ok(listing) => self.listing = Some((directory, listing)),
                    Err(error) if error.kind() == ErrorKind::NotFound => {}
                    Err(error) => silver_log::warn!(?error, ?directory, "directory listing failed"),
                }
                continue;
            };
            let queued = match listing.next() {
                Some(Ok(entry)) => self.disk.unlink(self.order, entry.path()),
                Some(Err(error)) => {
                    silver_log::warn!(?error, ?directory, "directory listing failed");
                    self.listing = None;
                    continue;
                }
                None => {
                    let (directory, _) = self.listing.take().expect("listing present");
                    self.disk.remove_dir(self.order, directory)
                }
            };
            if let Ok(Some(_)) = queued {
                self.queued += 1;
            }
        }
    }

    pub(super) fn is_idle(&self) -> bool {
        self.directories.is_empty() && self.listing.is_none() && self.queued == 0
    }
}
