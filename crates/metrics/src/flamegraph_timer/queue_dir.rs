use std::path::PathBuf;

use flux::{
    communication::{
        cleanup::cleanup_flink,
        queue::{Queue, QueueType},
    },
    utils::directories::{local_share_dir, shmem_dir_queues_with_base},
};

#[cfg(feature = "perf")]
use crate::perf::{MAX_EVENTS, PerfSample};
use crate::{
    Schema,
    flamegraph_timer::mark::{Frame, Mark},
};

/// Each ring element type carries its own ring name and empty value, so the
/// two can't be mismatched at a call site.
pub(super) trait RingEntry: Copy {
    const PREFIX: &'static str;
    const EMPTY: Self;
}

impl RingEntry for Mark {
    const PREFIX: &'static str = "events";
    const EMPTY: Self = Mark { frame: Frame::Close { id: 0 }, ts: 0 };
}

#[cfg(feature = "perf")]
impl RingEntry for PerfSample {
    const PREFIX: &'static str = "perf-events";
    const EMPTY: Self = PerfSample { vals: [0; MAX_EVENTS] };
}

/// A background reader drains each ring continuously, so a ring only buffers
/// the marks produced between polls, not the whole run — hence small.
const RING_CAPACITY: usize = 1 << 14;

/// The shmem dir holding this run's per-thread timing rings.
pub(super) struct QueueDir(PathBuf);

impl QueueDir {
    pub(super) fn open() -> Self {
        Self::open_app(crate::TIMING.app())
    }

    pub(super) fn open_app(app: &str) -> Self {
        let dir = shmem_dir_queues_with_base(local_share_dir(), app);
        let _ = std::fs::create_dir_all(&dir);
        Self(dir)
    }

    /// Publish our pid so a surfer can attach to this run.
    pub(super) fn write_pid(&self) {
        let _ = std::fs::write(self.0.join("pid"), std::process::id().to_string());
    }

    /// Publish the perf event names this run measures so a surfer labels its
    /// positional samples by our vocabulary, not its own `SILVER_PERF_EVENTS`.
    /// Removed when the run has no perf, so a surfer can't fold a prior perf
    /// run's stale names against samples that no longer exist.
    pub(super) fn publish_perf_schema(&self) {
        let path = self.0.join("perf_schema");
        #[cfg(feature = "perf")]
        {
            let names: Vec<&str> = Schema::local().iter().map(|e| e.label.as_str()).collect();
            let _ = std::fs::write(path, names.join(","));
        }
        #[cfg(not(feature = "perf"))]
        let _ = std::fs::remove_file(path);
    }

    /// The vocabulary this run published, if it enabled perf.
    pub(super) fn perf_schema(&self) -> Option<Schema> {
        std::fs::read_to_string(self.0.join("perf_schema")).ok().map(|s| Schema::parse(&s))
    }

    /// The published pid, but only if its process is still alive: the pid file
    /// and stale `events-*` rings outlive a dead run, so a consumer must not
    /// fold them as live data.
    pub(super) fn live_pid(&self) -> Option<u32> {
        let pid: u32 = std::fs::read_to_string(self.0.join("pid")).ok()?.trim().parse().ok()?;
        // `/proc/<pid>` exists only while the process is alive.
        std::path::Path::new(&format!("/proc/{pid}")).exists().then_some(pid)
    }

    pub(super) fn path<T: RingEntry>(&self, token: &str) -> PathBuf {
        self.0.join(format!("{}-{token}", T::PREFIX))
    }

    fn entries(&self) -> impl Iterator<Item = std::fs::DirEntry> {
        std::fs::read_dir(&self.0).into_iter().flatten().flatten()
    }

    /// Unlink a prior run's rings before producers create theirs, so the reader
    /// doesn't fold a vanished thread's stale ring as live data.
    pub(super) fn clear_stale(&self) {
        for entry in self.entries() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let is_ring = name.starts_with(Mark::PREFIX);
            #[cfg(feature = "perf")]
            let is_ring = is_ring || name.starts_with(PerfSample::PREFIX);
            if is_ring {
                let _ = cleanup_flink(&entry.path());
            }
        }
    }

    pub(super) fn ring<T: RingEntry>(&self, token: &str) -> Queue<T> {
        let path = self.path::<T>(token);
        // Discard any leftover backing under this stable name first: a crashed
        // run's ring or another `silver` process must never be shared, or two
        // producers would write the same ring and corrupt each other.
        let _ = cleanup_flink(&path);
        Queue::create_or_open_shared(path, RING_CAPACITY, QueueType::SPMC)
    }

    /// The `<token>` of every marks ring in the dir; perf rings are excluded.
    pub(super) fn event_threads(&self) -> Vec<String> {
        self.entries()
            .filter_map(|e| {
                e.file_name()
                    .to_string_lossy()
                    .strip_prefix(Mark::PREFIX)
                    .and_then(|rest| rest.strip_prefix('-'))
                    .map(str::to_owned)
            })
            .collect()
    }
}

/// Enable `#[timed]` production and publish this run so a surfer can attach.
/// Call once at startup.
pub fn enable_surfer() {
    crate::TIMING.set_enabled();
    let dir = QueueDir::open();
    dir.clear_stale();
    dir.publish_perf_schema();
    dir.write_pid();
}
