//! The live ring drainer: discovers a run's per-thread shmem rings, drains each
//! into a retained heap buffer, and folds the lot into a call tree. The two
//! consumers (the in-process harness and the surfer) drive the same engine
//! and differ only in the [`FrameResolver`] they poll with. Each ring is read
//! from slot 0, so a surfer attaching mid-run reports loss for the
//! pre-attach prefix the producer has already overwritten.
//!
//! Frame names are resolved as marks are drained, not at `fold` time: an
//! surfer reads them from the live producer's binary, which may be gone by
//! the time anyone folds the retained marks into stats.

use std::collections::{HashMap, hash_map::Entry};

use flux::communication::{
    ReadError,
    queue::{ConsumerBare, Queue},
};
use rustc_hash::FxHashMap;

use crate::{
    Schema,
    flamegraph_timer::{
        aggregator::Aggregator,
        fxt,
        mark::{Frame, Mark},
        queue_dir::{QueueDir, RingEntry},
        report::{FlamegraphMeta, TimingStats},
        symbols::FrameResolver,
    },
    perf::PerfSample,
};

pub(super) struct EventsDrainer {
    dir: QueueDir,
    threads: HashMap<String, ThreadDrainer>,
    meta: FlamegraphMeta,
}

impl EventsDrainer {
    pub(super) fn new(dir: QueueDir, schema: Schema) -> Self {
        let meta = FlamegraphMeta { names: FxHashMap::default(), schema };
        Self { dir, threads: HashMap::new(), meta }
    }

    pub(super) fn poll(&mut self, resolver: &impl FrameResolver) {
        for thread in self.dir.event_threads() {
            if let Entry::Vacant(slot) = self.threads.entry(thread) {
                if let Some(thread) = ThreadDrainer::open(&self.dir, slot.key()) {
                    slot.insert(thread);
                }
            }
        }
        for thread in self.threads.values_mut() {
            thread.poll(&mut self.meta.names, resolver);
        }
    }

    pub(super) fn fold(&self) -> TimingStats {
        let mut aggregator = Aggregator::default();
        let mut lost = false;
        for thread in self.threads.values() {
            lost |= thread.lost();
            thread.fold_into(&mut aggregator);
        }
        lost |= aggregator.desynced();
        TimingStats::from_timings(aggregator.into_paths(), self.meta.clone(), lost)
    }

    /// The whole retained mark stream as a Fuchsia FXT trace, with a realtime
    /// anchor so Perfetto/magic-trace shows per-slice wall-clock time. The live
    /// timeline a flamegraph aggregates away.
    pub(super) fn fxt_trace(&self) -> Vec<u8> {
        fxt::trace(
            self.threads.iter().map(|(name, t)| (name.as_str(), t.marks.out.as_slice())),
            &self.meta.names,
        )
    }
}

/// One producing thread's marks and (with `perf`) counter samples, read in
/// lockstep so the aggregator can pair them by index.
struct ThreadDrainer {
    marks: QueueDrainer<Mark>,
    /// `None` when the producer was built without `perf`: the marks ring exists
    /// but the perf ring never does, so the thread folds timing-only. The
    /// `perf` feature gates only the producer's counter reads, never this
    /// drain.
    perf: Option<QueueDrainer<PerfSample>>,
    /// Marks in `marks.out[..resolved]` have already had their frame names
    /// resolved, so each `poll` only resolves the freshly drained tail.
    resolved: usize,
}

impl ThreadDrainer {
    fn open(dir: &QueueDir, token: &str) -> Option<Self> {
        Some(Self {
            marks: QueueDrainer::<Mark>::open(dir, token)?,
            perf: QueueDrainer::<PerfSample>::open(dir, token),
            resolved: 0,
        })
    }

    fn poll(&mut self, names: &mut FxHashMap<u64, String>, resolver: &impl FrameResolver) {
        self.marks.poll();
        if let Some(perf) = &mut self.perf {
            perf.poll();
        }
        // The frame name lives in the producer's binary; `len` says how many
        // bytes to read. Resolve each id once, while the producer is still
        // alive to read it from.
        for mark in &self.marks.out[self.resolved..] {
            if let Frame::Open { id, len } = mark.frame {
                names.entry(id).or_insert_with(|| {
                    resolver.resolve(id, len).unwrap_or_else(|| format!("unknown_{id}"))
                });
            }
        }
        self.resolved = self.marks.out.len();
    }

    fn fold_into(&self, aggregator: &mut Aggregator) {
        let counters = self.perf.as_ref().map_or(&[][..], |p| &p.out);
        aggregator.fold_thread(&self.marks.out, counters);
    }

    /// Whether either ring lost marks, leaving the fold incomplete.
    fn lost(&self) -> bool {
        self.marks.lost || self.perf.as_ref().is_some_and(|p| p.lost)
    }
}

/// A live consumer that drains one ring into a growing heap `Vec`, polled
/// repeatedly across a run.
struct QueueDrainer<T: RingEntry> {
    consumer: ConsumerBare<T>,
    out: Vec<T>,
    /// Set once a `SpedPast` showed the producer overwrote slots we hadn't read
    /// — marks were lost, so the fold built from `out` is incomplete. An
    /// surfer attaching mid-run latches this on its first poll: the
    /// pre-attach prefix is genuinely gone.
    lost: bool,
}

impl<T: RingEntry> QueueDrainer<T> {
    fn open(dir: &QueueDir, token: &str) -> Option<Self> {
        let queue = Queue::<T>::try_open_shared(dir.path::<T>(token)).ok()?;
        // Each ring is its own queue with its own flux group table and the surfer
        // is its only consumer, so the static per-type prefix works as the group
        // label — no per-token string to allocate and leak.
        let mut consumer = ConsumerBare::new(queue, T::PREFIX);

        // Collaborative so the cursor starts at the beginning of the ring.
        consumer.try_init_collaborative();
        Some(Self { consumer, out: Vec::with_capacity(1024), lost: false })
    }

    fn poll(&mut self) {
        let mut scratch = T::EMPTY;
        loop {
            match self.consumer.try_consume(&mut scratch) {
                Ok(()) => self.out.push(scratch),
                Err(ReadError::Empty) => break,
                Err(ReadError::SpedPast) => {
                    self.consumer.recover_after_error();
                    self.lost = true;
                }
            }
        }
    }
}
