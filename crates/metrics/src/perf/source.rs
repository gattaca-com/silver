//! Live counter source: open the [`schema`](super::schema)'s events per thread
//! via rdpmc, then [`read`] a snapshot or [`emit`] one onto the `perf-{name}`
//! queue for surfer. Feature-gated — without `perf`, `read` is `None` and
//! `emit` a no-op, so `#[timed]` degrades to timing only.

pub(crate) use imp::{emit, read};

#[cfg(feature = "perf")]
mod imp {
    use std::{cell::RefCell, collections::HashMap};

    use flux::{
        communication::queue::{Producer, Queue, QueueType},
        utils::directories::{local_share_dir, shmem_dir_queues_with_base},
    };

    use crate::perf::{MAX_EVENTS, PerfSample, raw::HwCounter, schema};

    const QUEUE_SIZE: usize = 2usize.pow(13);

    /// Per-thread counters, one slot per [`schema`] entry (`None` where the
    /// event couldn't be opened — over budget or unsupported).
    struct Counters {
        opened: Vec<Option<HwCounter>>,
    }

    impl Counters {
        fn open() -> Option<Self> {
            let opened: Vec<_> =
                schema().iter().map(|e| HwCounter::event(e.type_, e.config)).collect();
            opened.iter().any(Option::is_some).then_some(Self { opened })
        }

        #[inline]
        fn read(&self) -> PerfSample {
            let mut s = PerfSample::default();
            for (i, c) in self.opened.iter().enumerate().take(MAX_EVENTS) {
                if let Some(c) = c {
                    s.vals[i] = c.read();
                }
            }
            s
        }
    }

    ::std::thread_local! {
        /// Perf pid=0 events bind to the opening thread. None when
        /// perf_event_open is unavailable.
        static COUNTERS: Option<Counters> = Counters::open();
        static PRODUCERS: RefCell<HashMap<&'static str, Producer<PerfSample>>> =
            RefCell::new(HashMap::new());
    }

    /// Current counter snapshot for the calling thread, or `None` when
    /// `perf_event_open` is unavailable.
    #[inline]
    pub(crate) fn read() -> Option<PerfSample> {
        COUNTERS.with(|c| c.as_ref().map(Counters::read))
    }

    fn new_producer(name: &str) -> Producer<PerfSample> {
        let dir = shmem_dir_queues_with_base(local_share_dir(), crate::TIMING.app());
        let _ = std::fs::create_dir_all(&dir);
        let queue: Queue<PerfSample> = Queue::create_or_open_shared(
            dir.join(format!("perf-{name}")),
            QUEUE_SIZE,
            QueueType::MPMC,
        );
        Producer::from(queue)
    }

    /// Stream one call's `sample` onto this thread's `perf-{name}` queue for
    /// surfer (live mode).
    #[inline]
    pub(crate) fn emit(name: &'static str, sample: &PerfSample) {
        PRODUCERS.with(|cell| {
            let mut map = cell.borrow_mut();
            let producer = map.entry(name).or_insert_with(|| new_producer(name));
            producer.produce(sample);
        });
    }
}

#[cfg(not(feature = "perf"))]
mod imp {
    use crate::perf::PerfSample;

    #[inline]
    pub(crate) fn read() -> Option<PerfSample> {
        None
    }

    #[inline]
    pub(crate) fn emit(_name: &'static str, _sample: &PerfSample) {}
}
