use std::path::PathBuf;

use flux::{
    communication::{
        cleanup::cleanup_flink,
        queue::{Queue, QueueType},
    },
    utils::directories::{local_share_dir, shmem_dir_queues_with_base},
};

/// Per-thread ring capacity. A background reader continuously drains each ring
/// into a heap `Vec`, so the ring only has to absorb the marks produced between
/// reader polls, not the whole run — hence a small `1 << 14`. Each slot is a
/// 64-aligned `Seqlock<T>` (timer ring 1 MiB, perf ring 2 MiB per thread).
const RING_CAPACITY: usize = 1 << 14;

/// The shmem directory holding this run's per-thread timing rings, named
/// `events-<token>` (and `perf-events-<token>` with the `perf` feature).
/// Producers and the background reader meet here.
pub(super) struct QueueDir(PathBuf);

impl QueueDir {
    pub(super) fn open() -> Self {
        let dir = shmem_dir_queues_with_base(local_share_dir(), crate::TIMING.app());
        let _ = std::fs::create_dir_all(&dir);
        Self(dir)
    }

    pub(super) fn path(&self, prefix: &str, token: &str) -> PathBuf {
        self.0.join(format!("{prefix}-{token}"))
    }

    /// Unlink rings left by a prior run before producers create theirs, so the
    /// reader only sees this run's threads — a stale `events-<token>` whose
    /// thread is now absent would otherwise be folded as bogus data.
    pub(super) fn clear_stale(&self) {
        let Ok(entries) = std::fs::read_dir(&self.0) else { return };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("events-") || name.starts_with("perf-events-") {
                let _ = cleanup_flink(&entry.path());
            }
        }
    }

    pub(super) fn ring<T: Copy>(&self, prefix: &str, token: &str) -> Queue<T> {
        let path = self.path(prefix, token);
        // Stable name, fresh ring: unlink any pre-existing backing so a stale
        // file (crashed run) or a foreign producer (concurrent `silver`-app
        // process: a restart overlap, the unit tests alongside `perf-local`,
        // nextest's per-test processes) is never reused. Two producers on one
        // ring desync the marks/perf streams and corrupt headers.
        let _ = cleanup_flink(&path);
        Queue::create_or_open_shared(path, RING_CAPACITY, QueueType::SPMC)
    }

    /// The `<token>` of every `events-<token>` ring currently in the dir.
    /// `perf-events-*` is excluded (it doesn't start with `events-`).
    pub(super) fn event_tokens(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(&self.0) else { return Vec::new() };
        entries
            .flatten()
            .filter_map(|e| {
                e.file_name().to_string_lossy().strip_prefix("events-").map(str::to_owned)
            })
            .collect()
    }
}
