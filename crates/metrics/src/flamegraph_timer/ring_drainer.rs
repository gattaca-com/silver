use std::collections::VecDeque;

use flux::communication::{
    ReadError,
    queue::{ConsumerBare, Queue},
};

use crate::{
    allocator::AllocSample,
    flamegraph_timer::{
        mark::Mark,
        queue_dir::{QueueDir, RingEntry},
    },
    perf::PerfSample,
};

/// A live consumer of one ring, tracking each entry's sequence number — its
/// absolute position in the push stream. `pending` holds entries not yet
/// joined into a row (another ring hasn't reached their sequence) and is kept
/// contiguous, ending at `next_seq`, so sequence numbers derive from
/// arithmetic instead of being stored per entry.
pub(super) struct RingDrainer<T: RingEntry> {
    consumer: ConsumerBare<T>,
    pending: VecDeque<T>,
    /// Sequence number the next ring read will yield.
    next_seq: u64,
    /// Entries overwritten before they could be read (producer outran reader).
    missed: u64,
}

impl<T: RingEntry> RingDrainer<T> {
    fn open(dir: &QueueDir, token: &str) -> Option<Self> {
        let queue = Queue::<T>::try_open_shared(dir.path::<T>(token)).ok()?;
        // Each ring is its own queue with its own flux group table and the surfer
        // is its only consumer, so the static per-type prefix works as the group
        // label — no per-token string to allocate and leak.
        let mut consumer = ConsumerBare::new(queue, T::PREFIX);

        // Collaborative so the cursor starts at the beginning of the ring,
        // anchoring `next_seq` at 0.
        consumer.try_init_collaborative();
        Some(Self { consumer, pending: VecDeque::new(), next_seq: 0, missed: 0 })
    }

    fn drain(&mut self) {
        let mut scratch = T::EMPTY;
        loop {
            match self.consumer.try_consume(&mut scratch) {
                Ok(()) => {
                    self.pending.push_back(scratch);
                    self.next_seq += 1;
                }
                Err(ReadError::Empty) => break,
                Err(ReadError::SpedPast) => {
                    // The producer lapped us: recovery jumps the cursor to its
                    // head, so everything from `next_seq` to the head is gone.
                    // The few entries still pending sit right against the hole
                    // and lose their counterparts to it — count them missed
                    // too, keeping `pending` a single contiguous run.
                    self.consumer.recover_after_error();
                    let head = self.consumer.queue_message_count() as u64;
                    self.missed += head.saturating_sub(self.next_seq) + self.pending.len() as u64;
                    self.next_seq = head.max(self.next_seq);
                    self.pending.clear();
                }
            }
        }
    }

    fn first_seq(&self) -> u64 {
        self.next_seq - self.pending.len() as u64
    }

    /// Next pending entry strictly below `limit`, with its sequence number.
    pub(super) fn pop_ready(&mut self, limit: u64) -> Option<(u64, T)> {
        let seq = self.first_seq();
        (seq < limit && !self.pending.is_empty()).then(|| (seq, self.pending.pop_front().unwrap()))
    }

    /// The entry pushed as `seq`; if this ring lost it to a hole, `fallback`
    /// (or `EMPTY`) approximates it. Entries below `seq` lost their mark
    /// instead and are discarded on the way; the mark ring already counts
    /// those events as missed.
    ///
    /// The caller requests ascending sequences and passes its last
    /// already-joined entry as `fallback`, so the approximation is always an
    /// *earlier* value — this method cannot tell a later one apart.
    pub(super) fn take_at(&mut self, seq: u64, fallback: Option<T>) -> T {
        let taken = (seq >= self.first_seq()).then(|| {
            while self.first_seq() < seq {
                self.pending.pop_front();
            }
            self.pending.pop_front()
        });
        taken.flatten().or(fallback).unwrap_or(T::EMPTY)
    }
}

/// A thread's lockstep rings; `perf`/`alloc` are `None` when the producer was
/// built without their feature.
pub(super) struct Rings {
    pub(super) marks: RingDrainer<Mark>,
    pub(super) perf: Option<RingDrainer<PerfSample>>,
    pub(super) alloc: Option<RingDrainer<AllocSample>>,
}

impl Rings {
    pub(super) fn open(dir: &QueueDir, token: &str) -> Option<Self> {
        Some(Self {
            marks: RingDrainer::<Mark>::open(dir, token)?,
            perf: RingDrainer::<PerfSample>::open(dir, token),
            alloc: RingDrainer::<AllocSample>::open(dir, token),
        })
    }

    pub(super) fn drain(&mut self) {
        self.marks.drain();
        if let Some(perf) = &mut self.perf {
            perf.drain();
        }
        if let Some(alloc) = &mut self.alloc {
            alloc.drain();
        }
    }

    /// The sequence number below which every present ring has read (or lost)
    /// its entry — nothing more can arrive under it.
    pub(super) fn slowest_cursor(&self) -> u64 {
        self.marks
            .next_seq
            .min(self.perf.as_ref().map_or(u64::MAX, |r| r.next_seq))
            .min(self.alloc.as_ref().map_or(u64::MAX, |r| r.next_seq))
    }

    /// Marks are the event stream, so only their ring's overruns count as
    /// missed events. A sample ring's own holes don't lose events — a mark
    /// whose sample was overwritten survives with the last retained sample
    /// substituted — and counting them (the rings recover at slightly
    /// different heads) would double-count events whose mark was retained.
    pub(super) fn missed(&self) -> u64 {
        self.marks.missed
    }
}

#[cfg(test)]
mod tests {
    use flux::communication::queue::Producer;

    use super::*;
    use crate::flamegraph_timer::queue_dir::RING_CAPACITY;

    /// An overrun costs exactly the entries between the read cursor and the
    /// producer's head (plus the pending tail stranded against it), and the
    /// drainer resumes with correct sequence numbers — everything downstream
    /// relies on `missed` and the sequence being exact.
    #[test]
    fn overrun_is_counted_exactly_and_indexing_resumes_at_the_head() {
        let _guard = crate::test_shmem::ShmemGuard::new();
        let dir = QueueDir::open();
        let mut producer = Producer::from(dir.ring::<Mark>("ring-drainer-test"));
        let mut drainer = RingDrainer::<Mark>::open(&dir, "ring-drainer-test").unwrap();

        let mark = Mark::from_parts(1, 0, true);
        for _ in 0..3 {
            producer.produce(&mark);
        }
        drainer.drain();
        assert_eq!(drainer.pop_ready(u64::MAX).unwrap().0, 0);
        assert_eq!(drainer.pop_ready(u64::MAX).unwrap().0, 1);

        // Lap the reader; entry 2 is still pending and stranded by the hole.
        let lapped = RING_CAPACITY as u64 + 5;
        for _ in 0..lapped {
            producer.produce(&mark);
        }
        drainer.drain();
        assert_eq!(drainer.missed, lapped + 1);
        assert!(drainer.pop_ready(u64::MAX).is_none(), "nothing readable inside the hole");

        producer.produce(&mark);
        drainer.drain();
        assert_eq!(drainer.pop_ready(u64::MAX).unwrap().0, 3 + lapped, "seq resumes at the head");
        assert_eq!(drainer.missed, lapped + 1, "post-recovery reads are not miscounted");

        // A second overrun accumulates on top of the first.
        for _ in 0..lapped {
            producer.produce(&mark);
        }
        drainer.drain();
        assert_eq!(drainer.missed, 2 * (lapped + 1) - 1, "every hole is counted");
    }

    /// A sample lost to a hole is approximated by the caller's last joined
    /// sample — an earlier sequence — never by the burst entries that
    /// overwrote it; with nothing joined it falls back to `EMPTY`.
    #[test]
    fn take_at_falls_back_to_last_retained_on_a_hole() {
        let _guard = crate::test_shmem::ShmemGuard::new();
        let dir = QueueDir::open();
        let mut producer = Producer::from(dir.ring::<AllocSample>("take-at-test"));
        let mut drainer = RingDrainer::<AllocSample>::open(&dir, "take-at-test").unwrap();

        // Sequence 0 is drained and joined before the burst.
        producer.produce(&AllocSample { allocated: 42, freed: 0 });
        drainer.drain();
        let last_joined = drainer.take_at(0, None);
        assert_eq!(last_joined.allocated, 42);

        // A burst laps the ring; recovery skips to its head, so sequence 1
        // onward is lost even though burst entries still sit in the ring.
        for _ in 0..RING_CAPACITY as u64 + 5 {
            producer.produce(&AllocSample { allocated: 7, freed: 0 });
        }
        drainer.drain();

        assert_eq!(drainer.take_at(3, Some(last_joined)).allocated, 42, "not a burst sample");
        assert_eq!(drainer.take_at(4, None).allocated, 0, "EMPTY when nothing was joined");
    }
}
