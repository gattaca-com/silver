use std::{
    collections::VecDeque,
    fs::ReadDir,
    io::{Error, ErrorKind},
    os::fd::{AsRawFd, RawFd},
    path::PathBuf,
};

use flux_disk::{DiskEvent, DiskIo, FailedOp, OperationId};

use super::file_writer::{DIRECTORY_TOKENS, DirectoryTokens};

/// Bounds the unlinks in flight and the entries listed per turn: a 16k-file
/// column group neither stalls a turn nor grows the queue. Unlinks on one
/// directory token run one at a time, so two per token keep them all busy.
const MAX_QUEUED: usize = 2 * DIRECTORY_TOKENS;
const MAX_LISTED_PER_TURN: usize = 32;
/// A file created after the listing leaves the directory non-empty; past
/// this many listings something keeps filling it.
const MAX_ATTEMPTS: u32 = 3;

struct Removal {
    directory: PathBuf,
    attempts: u32,
}

/// Removes directories with the files in them, a bounded batch per turn. One
/// directory is listed at a time, and its `remove_dir` waits for every unlink
/// in flight.
pub(super) struct DirectoryRemover {
    disk: DiskIo,
    directory: DirectoryTokens,
    removals: VecDeque<Removal>,
    listing: Option<(Removal, ReadDir)>,
    // Runs only once every unlink before it completed, so one at a time.
    removing: Option<(OperationId, Removal)>,
    queued: usize,
}

impl DirectoryRemover {
    pub(super) fn new(store_dir: &str) -> Result<Self, Error> {
        let mut disk = super::disk_ring()?;
        Ok(Self {
            directory: DirectoryTokens::open(&mut disk, store_dir)?,
            disk,
            removals: VecDeque::new(),
            listing: None,
            removing: None,
            queued: 0,
        })
    }

    pub(super) fn remove(&mut self, directory: PathBuf) {
        self.removals.push_back(Removal { directory, attempts: 0 });
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
        let (queued, removing, removals) =
            (&mut self.queued, &mut self.removing, &mut self.removals);
        self.disk.poll_with(|event| match event {
            DiskEvent::Unlinked { operation_id, .. } => {
                *queued -= 1;
                removing.take_if(|(id, _)| *id == operation_id);
            }
            DiskEvent::Failed { op: FailedOp::Unlink, operation_id, error, .. } => {
                *queued -= 1;
                let removal = removing.take_if(|(id, _)| Some(*id) == operation_id);
                match removal {
                    Some((_, mut removal))
                        if error.kind() == ErrorKind::DirectoryNotEmpty &&
                            removal.attempts < MAX_ATTEMPTS =>
                    {
                        removal.attempts += 1;
                        removals.push_back(removal);
                    }
                    _ if error.kind() == ErrorKind::NotFound => {}
                    _ => silver_log::warn!(?error, "directory removal op failed"),
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
            let Some((removal, listing)) = self.listing.as_mut() else {
                let Some(removal) = self.removals.pop_front() else { return turn > 0 };
                match std::fs::read_dir(&removal.directory) {
                    Ok(listing) => self.listing = Some((removal, listing)),
                    Err(error) if error.kind() == ErrorKind::NotFound => {}
                    Err(error) => {
                        let directory = &removal.directory;
                        silver_log::warn!(?error, ?directory, "directory listing failed");
                    }
                }
                continue;
            };
            let queued = match listing.next() {
                Some(Ok(entry)) => self.disk.unlink(self.directory.next(), entry.path()),
                Some(Err(error)) => {
                    let directory = &removal.directory;
                    silver_log::warn!(?error, ?directory, "directory listing failed");
                    self.listing = None;
                    continue;
                }
                None if self.queued > 0 => return turn > 0,
                None => {
                    let (removal, _) = self.listing.take().expect("listing present");
                    let queued = self.disk.remove_dir(self.directory.next(), &removal.directory);
                    if let Ok(Some(id)) = queued {
                        self.removing = Some((id, removal));
                    }
                    queued
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
        self.removals.is_empty() && self.listing.is_none() && self.queued == 0
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use tempfile::TempDir;

    use super::{DirectoryRemover, MAX_ATTEMPTS};

    fn step_until(remover: &mut DirectoryRemover, done: impl Fn(&DirectoryRemover) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !done(remover) {
            assert!(Instant::now() < deadline, "the remover did not get there");
            remover.step();
        }
    }

    fn relisting(remover: &DirectoryRemover, attempts: u32) -> bool {
        remover.listing.as_ref().is_some_and(|(removal, _)| removal.attempts == attempts)
    }

    /// A subdirectory cannot be unlinked as a file, so it keeps the group
    /// non-empty, as a file created after the listing would.
    fn blocked_group(root: &TempDir) -> std::path::PathBuf {
        let group = root.path().join("128");
        std::fs::create_dir_all(group.join("blocking")).unwrap();
        std::fs::write(group.join("40.ssz"), b"x").unwrap();
        group
    }

    #[test]
    fn non_empty_directory_is_listed_again() {
        let root = TempDir::new().unwrap();
        let group = blocked_group(&root);
        let mut remover = DirectoryRemover::new(root.path().to_str().unwrap()).unwrap();
        remover.remove(group.clone());

        step_until(&mut remover, |remover| relisting(remover, 1));
        assert!(!group.join("40.ssz").exists(), "the first listing removed the file");
        std::fs::remove_dir(group.join("blocking")).unwrap();
        step_until(&mut remover, DirectoryRemover::is_idle);
        assert!(!group.exists(), "the second listing removed the directory");
    }

    #[test]
    fn directory_that_stays_non_empty_is_given_up() {
        let root = TempDir::new().unwrap();
        let group = blocked_group(&root);
        let mut remover = DirectoryRemover::new(root.path().to_str().unwrap()).unwrap();
        remover.remove(group.clone());

        step_until(&mut remover, |remover| relisting(remover, MAX_ATTEMPTS));
        step_until(&mut remover, DirectoryRemover::is_idle);
        assert!(group.join("blocking").exists(), "left in place after the last attempt");
    }
}
