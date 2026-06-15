//! `#[perf]` runtime: per-function instructions-retired + CPU-cycle
//! measurement via rdpmc, emitted per call onto a `perf-{fn}` MPMC shmem
//! queue (mirroring `#[timed]`'s `timing-{fn}` queues).
//!
//! Counters are perf self-monitoring events bound to the opening thread,
//! so each thread lazily opens its own set (instructions, cycles, branch
//! misses, LLC misses). Collection is gated behind the `perf` feature;
//! without it (or when `perf_event_paranoid` blocks the events at
//! runtime) the guard is inert.

/// One decorated-function call: counter deltas between entry and every
/// exit path. Kernel-mode work is included when perf permits
/// (`perf_event_paranoid` <= 1), else userspace only — see `hw_counter`.
///
/// `branch_misses` / `cache_misses` sit in general-purpose PMU counters
/// and read zero if those couldn't be opened (counter budget exhausted).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PerfSample {
    pub instr: u64,
    pub cycles: u64,
    pub branch_misses: u64,
    pub cache_misses: u64,
}

impl PerfSample {
    #[inline]
    pub fn ipc(&self) -> f64 {
        if self.cycles == 0 { 0.0 } else { self.instr as f64 / self.cycles as f64 }
    }
}

/// Drop-based scope used by the `#[perf]` macro expansion. Records on
/// every exit path — normal return, `?`, early `return`, panic-unwind.
#[doc(hidden)]
pub struct PerfGuard {
    #[cfg(feature = "perf")]
    name: &'static str,
    #[cfg(feature = "perf")]
    start: PerfSample,
}

#[cfg(feature = "perf")]
mod imp {
    use std::{cell::RefCell, collections::HashMap};

    use flux::{
        communication::queue::{Producer, Queue, QueueType},
        utils::directories::{local_share_dir, shmem_dir_queues_with_base},
    };

    use super::{PerfGuard, PerfSample};
    use crate::hw_counter::HwCounter;

    const QUEUE_SIZE: usize = 2usize.pow(13);

    /// Per-thread counter set. Instructions/cycles use fixed PMU counters
    /// and are required; branch/cache misses use general-purpose counters
    /// and degrade individually to zero readings when unavailable.
    struct Counters {
        instr: HwCounter,
        cycles: HwCounter,
        branch_misses: Option<HwCounter>,
        cache_misses: Option<HwCounter>,
    }

    impl Counters {
        fn open() -> Option<Self> {
            Some(Self {
                instr: HwCounter::instructions()?,
                cycles: HwCounter::cycles()?,
                branch_misses: HwCounter::branch_misses(),
                cache_misses: HwCounter::cache_misses(),
            })
        }

        #[inline]
        fn read(&self) -> PerfSample {
            PerfSample {
                instr: self.instr.read(),
                cycles: self.cycles.read(),
                branch_misses: self.branch_misses.as_ref().map_or(0, HwCounter::read),
                cache_misses: self.cache_misses.as_ref().map_or(0, HwCounter::read),
            }
        }
    }

    ::std::thread_local! {
        /// Perf pid=0 events bind to the opening thread. None when
        /// perf_event_open is unavailable.
        static COUNTERS: Option<Counters> = Counters::open();
        static PRODUCERS: RefCell<HashMap<&'static str, Producer<PerfSample>>> =
            RefCell::new(HashMap::new());
    }

    fn new_producer(name: &str) -> Producer<PerfSample> {
        let app = crate::APP_NAME.get().map(String::as_str).unwrap_or("silver");
        let dir = shmem_dir_queues_with_base(local_share_dir(), app);
        let _ = std::fs::create_dir_all(&dir);
        let queue: Queue<PerfSample> = Queue::create_or_open_shared(
            dir.join(format!("perf-{name}")),
            QUEUE_SIZE,
            QueueType::MPMC,
        );
        Producer::from(queue)
    }

    impl PerfGuard {
        #[inline]
        pub fn new(name: &'static str) -> Self {
            let start = COUNTERS.with(|c| c.as_ref().map(Counters::read).unwrap_or_default());
            Self { name, start }
        }
    }

    impl Drop for PerfGuard {
        fn drop(&mut self) {
            let Some(end) = COUNTERS.with(|c| c.as_ref().map(Counters::read)) else {
                return;
            };
            let sample = PerfSample {
                instr: end.instr.saturating_sub(self.start.instr),
                cycles: end.cycles.saturating_sub(self.start.cycles),
                branch_misses: end.branch_misses.saturating_sub(self.start.branch_misses),
                cache_misses: end.cache_misses.saturating_sub(self.start.cache_misses),
            };
            PRODUCERS.with(|cell| {
                let mut map = cell.borrow_mut();
                let producer = map.entry(self.name).or_insert_with(|| new_producer(self.name));
                producer.produce(&sample);
            });
        }
    }
}

#[cfg(not(feature = "perf"))]
impl PerfGuard {
    #[inline]
    pub fn new(_name: &'static str) -> Self {
        Self {}
    }
}
