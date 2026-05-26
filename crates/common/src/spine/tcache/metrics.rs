//! Per-TCache shmem-backed counter set.
//!
//! Layout in `counters-tcache-{name}` (each slot is a `u64`):
//!   0: capacity (bytes) — set once at construction.
//!   1: head_seq — updated by `Producer::publish_head`.
//!   2..2+N: tail_seq[i] — updated by consumer `i`'s `free`.
//!
//! Companion file `tcache-names-{name}` stores per-consumer names
//! as fixed-width zero-padded UTF-8 buffers (`MAX_CONSUMERS × NAME_LEN`
//! bytes). Each consumer writes its name at registration time so
//! surfer can label rows by consumer identity instead of positional
//! `tail_{i}`.

use std::{
    fs::OpenOptions,
    io,
    os::fd::AsRawFd,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::metrics::mmap_counters_file;

/// Number of fixed (non-tail) slots in the layout.
const FIXED_SLOTS: usize = 2;
/// Index of the capacity slot.
const CAPACITY_IDX: usize = 0;
/// Index of the head_seq slot.
const HEAD_IDX: usize = 1;
/// Bytes per consumer-name slot. UTF-8 zero-padded; tail bytes zero.
/// 32 fits typical labels like `data_columns_gossip` with headroom.
pub const NAME_LEN: usize = 32;

pub struct TCacheMetrics {
    base: *mut AtomicU64,
    n_consumers: usize,
    map_bytes: usize,
    /// Companion mmap for consumer names. `n_consumers * NAME_LEN`
    /// bytes. `None` if the names file couldn't be opened (e.g.
    /// permissions); name writes become no-ops.
    names_base: *mut u8,
    names_bytes: usize,
}

// SAFETY: `base` points at an `mmap(MAP_SHARED)` region; every access
// goes through atomic ops. The mmap is alive for the lifetime of the
// `TCacheMetrics` value (Drop calls munmap).
unsafe impl Send for TCacheMetrics {}
unsafe impl Sync for TCacheMetrics {}

impl TCacheMetrics {
    /// mmap the `counters-tcache-{name}` file and companion
    /// `tcache-names-{name}` file under
    /// `flux::utils::directories::local_share_dir() / "silver" / shmem /
    /// queues`. Pre-populates the capacity slot, fills tail slots with the
    /// `u64::MAX` sentinel, and zeroes the names buffer.
    pub fn new(name: &str, n_consumers: usize, capacity: u64) -> io::Result<Self> {
        let slots = FIXED_SLOTS + n_consumers;
        let map_bytes = slots * std::mem::size_of::<AtomicU64>();
        let counters_file = format!("tcache-{name}");
        let base_dir = flux::utils::directories::local_share_dir();
        let base = mmap_counters_file(&base_dir, "silver", &counters_file, map_bytes)?;
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

        let names_bytes = n_consumers * NAME_LEN;
        let names_file = format!("tcache-names-{name}");
        let names_base = mmap_bytes_file(&base_dir, "silver", &names_file, names_bytes)?;
        // SAFETY: pointer is valid for `names_bytes`. Zero on init so
        // unset slots have empty names.
        unsafe { std::ptr::write_bytes(names_base, 0, names_bytes) };

        Ok(Self { base, n_consumers, map_bytes, names_base, names_bytes })
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

    /// Write a consumer's name into its slot. Truncated to `NAME_LEN`
    /// bytes. Trailing bytes are zero-padded so readers can find the
    /// terminator.
    pub fn set_consumer_name(&self, idx: usize, name: &str) {
        debug_assert!(idx < self.n_consumers);
        if idx >= self.n_consumers {
            return;
        }
        let bytes = name.as_bytes();
        let len = bytes.len().min(NAME_LEN);
        // SAFETY: idx bounded by `n_consumers`; `idx * NAME_LEN + NAME_LEN`
        // is within `names_bytes`.
        unsafe {
            let dst = self.names_base.add(idx * NAME_LEN);
            std::ptr::write_bytes(dst, 0, NAME_LEN);
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, len);
        }
    }
}

impl Drop for TCacheMetrics {
    fn drop(&mut self) {
        // SAFETY: both pointers came from `mmap` with the recorded sizes;
        // no other references into either region outlive `self`.
        unsafe {
            libc::munmap(self.base.cast::<libc::c_void>(), self.map_bytes);
            libc::munmap(self.names_base.cast::<libc::c_void>(), self.names_bytes);
        }
    }
}

/// Open/create + mmap a raw bytes shmem file under flux's
/// `shmem/queues` directory. Layered alongside `mmap_counters_file`
/// for non-u64 layouts.
fn mmap_bytes_file(
    base_dir: &std::path::Path,
    app_name: &str,
    file_name: &str,
    bytes: usize,
) -> io::Result<*mut u8> {
    let dir = flux::utils::directories::shmem_dir_queues_with_base(base_dir, app_name);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(file_name);
    let file =
        OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&path)?;
    file.set_len(bytes as u64)?;
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            bytes,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    Ok(ptr.cast::<u8>())
}
