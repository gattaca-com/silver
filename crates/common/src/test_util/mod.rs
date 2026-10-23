mod synth_block;

use std::{io, path::Path};

use flux::communication::cleanup_shmem;
pub use synth_block::{SynthBid, SynthBlock};
use tempfile::TempDir;

use crate::{ssz_hash_gloas::EMPTY_EXECUTION_REQUESTS, ssz_view::EXECUTION_PAYLOAD_FIXED_GLOAS};

pub fn empty_signed_envelope(slot: u64, block_root: [u8; 32]) -> Vec<u8> {
    let mut signed = vec![0; 100 + 80 + EXECUTION_PAYLOAD_FIXED_GLOAS];
    signed[..4].copy_from_slice(&100u32.to_le_bytes());
    let envelope = &mut signed[100..];
    envelope[..4].copy_from_slice(&80u32.to_le_bytes());
    envelope[4..8].copy_from_slice(&((80 + EXECUTION_PAYLOAD_FIXED_GLOAS) as u32).to_le_bytes());
    envelope[16..48].copy_from_slice(&block_root);
    let payload = &mut envelope[80..];
    for at in [436, 504, 508, 528] {
        payload[at..at + 4].copy_from_slice(&(EXECUTION_PAYLOAD_FIXED_GLOAS as u32).to_le_bytes());
    }
    payload[532..540].copy_from_slice(&slot.to_le_bytes());
    signed.extend_from_slice(&EMPTY_EXECUTION_REQUESTS);
    signed
}

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

/// Lets a reader follow its producer's published floor: the first drained
/// pass clears the mark left by consumed reads, the second takes the
/// snapshot, the third applies it and publishes the tail.
pub fn follow_producer_floor(reader: &mut crate::TCacheReader) {
    for _ in 0..3 {
        reader.free();
    }
}
