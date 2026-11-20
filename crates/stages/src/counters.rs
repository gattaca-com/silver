use std::{fs, io, path::Path, slice, sync::atomic::AtomicU64};

use silver_beacon_state::BeaconStateCounters;
use silver_columns::DataColumnCounters;
use silver_common::{TCacheCounters, metrics::mmap_readonly};
use silver_control::{ClusterCounters, ControlCounters};
use silver_network::NetworkCounters;
use silver_peer::PeerCounters;
use silver_storage::StorageCounters;

/// Variant names of a `counters-{group}` file, keyed by its `{group}` suffix.
pub fn counter_names(group: &str) -> Option<&'static [&'static str]> {
    counter_schema(group).map(|(names, _)| names)
}

pub fn counter_schema(group: &str) -> Option<(&'static [&'static str], &'static [bool])> {
    match group {
        "beacon_state" => Some((BeaconStateCounters::NAMES, BeaconStateCounters::GAUGES)),
        "cluster" => Some((ClusterCounters::NAMES, ClusterCounters::GAUGES)),
        "control" => Some((ControlCounters::NAMES, ControlCounters::GAUGES)),
        "storage" => Some((StorageCounters::NAMES, StorageCounters::GAUGES)),
        "columns" => Some((DataColumnCounters::NAMES, DataColumnCounters::GAUGES)),
        "network" => Some((NetworkCounters::NAMES, NetworkCounters::GAUGES)),
        "peer" => Some((PeerCounters::NAMES, PeerCounters::GAUGES)),
        "tcache" => Some((TCacheCounters::NAMES, TCacheCounters::GAUGES)),
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
