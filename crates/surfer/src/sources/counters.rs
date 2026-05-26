//! Read-only mmap onto a `counters-{name}` file produced by
//! `silver_common::declare_counters!`. Slots are `[u64; N]` accessed
//! via `read_volatile`-equivalent atomic loads; the producer side does
//! `fetch_add(Relaxed)`.
//!
//! Holds (current, previous_sample) snapshots so the UI can render
//! deltas without recomputing on every frame. Historical bucketing
//! (12s deltas, 240-deep ring) is a follow-up.

use std::{
    collections::VecDeque,
    fs::OpenOptions,
    io,
    os::fd::AsRawFd,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::discovery::CounterFile;

/// Bucket-roll cadence, in seconds. 1 s gives sub-slot resolution on
/// counter rates; trade-off is shorter retention at fixed depth.
pub const BUCKET_SECS: u64 = 1;
/// 1 s bucket × 240 = 4 minutes of history.
pub const BUCKET_HISTORY_LEN: usize = 240;

pub struct CounterSet {
    pub name: String,
    pub slot_names: Vec<String>,
    /// Whether `slot_names` come from a registered schema (`true`) or
    /// are positional fallbacks because no schema was wired up
    /// (`false`).
    pub schema_registered: bool,
    base: *const AtomicU64,
    slot_count: usize,
    map_bytes: usize,
    /// Last sampled values, one per slot.
    pub current: Vec<u64>,
    /// Previous sample — for delta-vs-tick rendering.
    pub previous: Vec<u64>,
    /// Values at the start of the current bucket.
    bucket_start: Vec<u64>,
    /// Per-slot ring of completed-bucket deltas (newest at back).
    pub history: Vec<VecDeque<u64>>,
}

// SAFETY: `base` points at an mmap'd shmem file; the underlying memory
// is shared with producer processes that mutate via atomic ops. We only
// read, so cross-thread/cross-process sharing of the pointer is sound.
unsafe impl Send for CounterSet {}
unsafe impl Sync for CounterSet {}

impl CounterSet {
    pub fn open(file: &CounterFile) -> io::Result<Self> {
        let slot_count = (file.size_bytes / 8) as usize;
        if slot_count == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "empty counter file"));
        }
        let map_bytes = slot_count * 8;
        let base = mmap_readonly(&file.path, map_bytes)?;
        let (slot_names, schema_registered) = crate::schema::names_for(&file.name, slot_count);
        Ok(Self {
            name: file.name.clone(),
            slot_names,
            schema_registered,
            base,
            slot_count,
            map_bytes,
            current: vec![0; slot_count],
            previous: vec![0; slot_count],
            bucket_start: vec![0; slot_count],
            history: (0..slot_count).map(|_| VecDeque::with_capacity(BUCKET_HISTORY_LEN)).collect(),
        })
    }

    /// Read all slots into `current`, after copying the previous tick's
    /// values into `previous`. O(slot_count) atomic loads.
    pub fn sample(&mut self) {
        self.previous.copy_from_slice(&self.current);
        // SAFETY: `base` is valid for `slot_count` AtomicU64s for the
        // life of `self`; mmap region was sized accordingly.
        for i in 0..self.slot_count {
            self.current[i] = unsafe { (*self.base.add(i)).load(Ordering::Relaxed) };
        }
    }

    pub fn slot_count(&self) -> usize {
        self.slot_count
    }

    /// Close the current 12 s bucket: for each slot, compute
    /// `current - bucket_start` and push to the per-slot history ring
    /// (drop oldest when full). Then snapshot `current` into
    /// `bucket_start` so the next bucket starts accumulating from now.
    pub fn roll_bucket(&mut self) {
        for i in 0..self.slot_count {
            let delta = self.current[i].wrapping_sub(self.bucket_start[i]);
            let h = &mut self.history[i];
            if h.len() == BUCKET_HISTORY_LEN {
                h.pop_front();
            }
            h.push_back(delta);
            self.bucket_start[i] = self.current[i];
        }
    }

    /// Most recent completed bucket delta for slot `i`, or 0 if no
    /// bucket has rolled yet.
    pub fn last_bucket_delta(&self, i: usize) -> u64 {
        self.history.get(i).and_then(|h| h.back().copied()).unwrap_or(0)
    }
}

impl Drop for CounterSet {
    fn drop(&mut self) {
        // SAFETY: `base` was returned by mmap with `map_bytes`; nothing
        // else holds a reference into it (we hand out only borrowed
        // slices via accessors that don't outlive `&self`).
        unsafe {
            libc::munmap(self.base as *mut libc::c_void, self.map_bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use silver_common::declare_counters;

    declare_counters! {
        SurferTestCounters => "surfer_smoke" {
            Alpha,
            Beta,
            Gamma,
        }
    }

    #[test]
    fn discover_open_sample() {
        let tmp = std::env::temp_dir().join(format!("surfer_smoke_{}", std::process::id()));
        SurferTestCounters::init_with_base(&tmp, "surfer_test").unwrap();

        SurferTestCounters::Alpha.set(0);
        SurferTestCounters::Beta.set(0);
        SurferTestCounters::Gamma.set(0);
        SurferTestCounters::Alpha.add(11);
        SurferTestCounters::Beta.set(42);

        let sources = crate::discovery::discover(&tmp, "surfer_test").unwrap();
        let file = sources.counters.iter().find(|f| f.name == "surfer_smoke").unwrap();

        let mut set = super::CounterSet::open(file).unwrap();
        set.sample();

        // After init() the slot count == _Count discriminant.
        assert_eq!(set.slot_count(), 3);
        assert_eq!(set.current[0], 11);
        assert_eq!(set.current[1], 42);
        assert_eq!(set.current[2], 0);

        // Mutate, re-sample, check delta.
        SurferTestCounters::Alpha.add(5);
        set.sample();
        assert_eq!(set.current[0], 16);
        assert_eq!(set.previous[0], 11);

        std::fs::remove_dir_all(&tmp).ok();
    }
}

fn mmap_readonly(path: &Path, bytes: usize) -> io::Result<*const AtomicU64> {
    let file = OpenOptions::new().read(true).open(path)?;
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            bytes,
            libc::PROT_READ,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    Ok(ptr.cast::<AtomicU64>())
}
