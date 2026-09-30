use std::{fs, io, path::Path, slice, sync::atomic::AtomicU64};

use silver_beacon_state::BeaconStateCounters;
use silver_columns::DataColumnCounters;
use silver_common::{TCacheCounters, metrics::mmap_readonly};
use silver_control::ControlCounters;
use silver_network::NetworkCounters;
use silver_peer::PeerCounters;
use silver_storage::StorageCounters;

/// Variant names of a `counters-{group}` file, keyed by its `{group}` suffix.
pub fn counter_names(group: &str) -> Option<&'static [&'static str]> {
    match group {
        "beacon_state" => Some(BeaconStateCounters::NAMES),
        "control" => Some(ControlCounters::NAMES),
        "storage" => Some(StorageCounters::NAMES),
        "columns" => Some(DataColumnCounters::NAMES),
        "network" => Some(NetworkCounters::NAMES),
        "peer" => Some(PeerCounters::NAMES),
        "tcache" => Some(TCacheCounters::NAMES),
        _ => None,
    }
}

/// A read-only mapping of a `counters-{group}` file.
pub struct CounterValues {
    base: *const AtomicU64,
    len: usize,
}

unsafe impl Send for CounterValues {}
unsafe impl Sync for CounterValues {}

impl CounterValues {
    pub fn open(path: &Path) -> io::Result<Self> {
        let len = fs::metadata(path)?.len() as usize / size_of::<AtomicU64>();
        if len == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "empty counter file"));
        }
        let ptr = mmap_readonly(path, len * size_of::<AtomicU64>())?;
        Ok(Self { base: ptr.cast(), len })
    }

    pub fn values(&self) -> &[AtomicU64] {
        unsafe { slice::from_raw_parts(self.base, self.len) }
    }
}

impl Drop for CounterValues {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.base.cast_mut().cast(), self.len * size_of::<AtomicU64>()) };
    }
}
