//! Per-TCache shmem-backed counter set.
//!
//! Layout in `counters-tcache-{name}` (each slot is a `u64`):
//!   0: capacity (bytes) — set once at construction.
//!   1: head_seq — updated by `Producer::publish_head`.
//!   2..2+N: tail_seq[i] — updated by consumer `i`'s `free`.
//!
//! Surfer renders the file as a ring-buffer occupancy bar
//! (head − min_tail / capacity) plus current length, decoded
//! dynamically from the file's slot count.

use std::{
    io,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::metrics::mmap_counters_file;

/// Number of fixed (non-tail) slots in the layout.
const FIXED_SLOTS: usize = 2;
/// Index of the capacity slot.
const CAPACITY_IDX: usize = 0;
/// Index of the head_seq slot.
const HEAD_IDX: usize = 1;

pub struct TCacheMetrics {
    base: *mut AtomicU64,
    n_consumers: usize,
    map_bytes: usize,
}

// SAFETY: `base` points at an `mmap(MAP_SHARED)` region; every access
// goes through atomic ops. The mmap is alive for the lifetime of the
// `TCacheMetrics` value (Drop calls munmap).
unsafe impl Send for TCacheMetrics {}
unsafe impl Sync for TCacheMetrics {}

impl TCacheMetrics {
    /// mmap the `counters-tcache-{name}` file under
    /// `flux::utils::directories::local_share_dir() / "silver" / shmem /
    /// queues`, pre-populate the capacity slot.
    pub fn new(name: &str, n_consumers: usize, capacity: u64) -> io::Result<Self> {
        let slots = FIXED_SLOTS + n_consumers;
        let map_bytes = slots * std::mem::size_of::<AtomicU64>();
        let file_name = format!("tcache-{name}");
        let base_dir = flux::utils::directories::local_share_dir();
        let base = mmap_counters_file(&base_dir, "silver", &file_name, map_bytes)?;
        // SAFETY: ptr is valid for `slots` AtomicU64s.
        unsafe {
            (*base.add(CAPACITY_IDX)).store(capacity, Ordering::Relaxed);
            // Tails start at u64::MAX sentinel — matches the TCache's
            // own `head.tails` initialisation. Surfer treats this as
            // "tail == head" (no consumer for this slot).
            for i in 0..n_consumers {
                (*base.add(FIXED_SLOTS + i)).store(u64::MAX, Ordering::Relaxed);
            }
        }
        Ok(Self { base, n_consumers, map_bytes })
    }

    #[inline]
    pub fn set_head_seq(&self, v: u64) {
        // SAFETY: HEAD_IDX is < slot count by construction.
        unsafe { (*self.base.add(HEAD_IDX)).store(v, Ordering::Relaxed) };
    }

    #[inline]
    pub fn set_tail_seq(&self, consumer_idx: usize, v: u64) {
        debug_assert!(consumer_idx < self.n_consumers);
        // SAFETY: consumer_idx bounded by `n_consumers` (debug-asserted).
        unsafe {
            (*self.base.add(FIXED_SLOTS + consumer_idx)).store(v, Ordering::Relaxed);
        }
    }
}

impl Drop for TCacheMetrics {
    fn drop(&mut self) {
        // SAFETY: `base` was returned by mmap with `map_bytes`; no other
        // references into this region outlive `self`.
        unsafe { libc::munmap(self.base.cast::<libc::c_void>(), self.map_bytes) };
    }
}
