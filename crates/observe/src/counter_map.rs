//! A `counters-{name}` file produced by `silver_common::declare_counters!`,
//! plus the companion consumer-names file of a tcache.

use std::{io, sync::atomic::Ordering};

use silver_metrics::mmap_readonly;
use silver_stages::CounterValues;

use crate::discovery::CounterFile;

/// Matches `silver_common::spine::tcache::metrics::NAME_LEN`.
const CONSUMER_NAME_LEN: usize = 32;

pub struct CounterMap {
    values: CounterValues,
    /// Companion mmap of `tcache-names-{name}`: `n_consumers × 32` bytes of
    /// zero-padded UTF-8. Null for non-tcache counters and for tcaches whose
    /// names file couldn't be opened.
    consumer_names_base: *const u8,
    consumer_names_bytes: usize,
}

// SAFETY: `consumer_names_base` is a read-only mmap of shmem.
unsafe impl Send for CounterMap {}
unsafe impl Sync for CounterMap {}

impl CounterMap {
    pub fn open(file: &CounterFile) -> io::Result<Self> {
        let values = CounterValues::open(&file.path)?;
        let slot_count = values.values().len();

        // Failure is non-fatal: consumers render with positional labels.
        let (consumer_names_base, consumer_names_bytes) =
            if let Some(tc_name) = file.name.strip_prefix("tcache-") {
                let names_bytes = slot_count.saturating_sub(2) * CONSUMER_NAME_LEN;
                let names_path = file
                    .path
                    .parent()
                    .map(|d| d.join(format!("tcache-names-{tc_name}")))
                    .unwrap_or_default();
                match mmap_readonly(&names_path, names_bytes) {
                    Ok(p) => (p, names_bytes),
                    Err(_) => (std::ptr::null(), 0),
                }
            } else {
                (std::ptr::null(), 0)
            };

        Ok(Self { values, consumer_names_base, consumer_names_bytes })
    }

    pub fn slot_count(&self) -> usize {
        self.values.values().len()
    }

    /// O(slot_count) relaxed loads.
    pub fn read_into(&self, out: &mut [u64]) {
        let values = self.values.values();
        assert_eq!(out.len(), values.len());
        for (o, v) in out.iter_mut().zip(values) {
            *o = v.load(Ordering::Relaxed);
        }
    }

    /// Name of tcache tail slot `consumer_idx` (slot index minus 2). Empty
    /// when the names file isn't open or the slot is uninitialised.
    pub fn consumer_name(&self, consumer_idx: usize) -> &str {
        if self.consumer_names_base.is_null() {
            return "";
        }
        let off = consumer_idx * CONSUMER_NAME_LEN;
        if off + CONSUMER_NAME_LEN > self.consumer_names_bytes {
            return "";
        }
        // SAFETY: bounds checked above; bytes are written by the producer side
        // under a zero-padded UTF-8 convention.
        let bytes = unsafe {
            std::slice::from_raw_parts(self.consumer_names_base.add(off), CONSUMER_NAME_LEN)
        };
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(CONSUMER_NAME_LEN);
        std::str::from_utf8(&bytes[..end]).unwrap_or("")
    }
}

impl Drop for CounterMap {
    fn drop(&mut self) {
        if !self.consumer_names_base.is_null() {
            // SAFETY: the pointer came from `mmap` with the recorded size;
            // borrows handed out by `consumer_name` do not outlive `&self`.
            unsafe {
                libc::munmap(
                    self.consumer_names_base as *mut libc::c_void,
                    self.consumer_names_bytes,
                )
            };
        }
    }
}
