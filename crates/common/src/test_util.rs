use std::{io, path::Path};

use flux::communication::cleanup_shmem;
use tempfile::TempDir;

/// Removing a Flux link file alone leaves its POSIX shared-memory object
/// behind.
pub struct ShmemDir(TempDir);

impl ShmemDir {
    pub fn new() -> io::Result<Self> {
        TempDir::new().map(Self)
    }

    pub fn path(&self) -> &Path {
        self.0.path()
    }
}

impl Drop for ShmemDir {
    fn drop(&mut self) {
        cleanup_shmem(self.path());
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use flux::communication::queue::{Queue, QueueType};
    use shared_memory::ShmemConf;

    use super::*;

    #[test]
    fn shared_memory_is_removed_on_return_and_unwind() {
        for unwind in [false, true] {
            let mut resource = None;
            let result = catch_unwind(AssertUnwindSafe(|| {
                let dir = ShmemDir::new().unwrap();
                let link = dir.path().join("queue");
                let _queue: Queue<u64> = Queue::create_or_open_shared(&link, 8, QueueType::SPMC);
                let mapping = ShmemConf::new().flink(&link).open().unwrap();
                resource = Some((dir.path().to_owned(), mapping.get_os_id().to_owned()));
                if unwind {
                    panic!("exercise fixture unwinding");
                }
            }));
            assert_eq!(result.is_err(), unwind);
            let (path, id) = resource.unwrap();
            assert!(!path.exists(), "fixture directory survives teardown");
            assert!(
                ShmemConf::new().os_id(id).open().is_err(),
                "shared-memory object survives teardown"
            );
        }
    }
}
