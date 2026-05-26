//! Consumer for a flux `timing-{name}` shmem queue. Drains
//! `TimingMessage` events into a running `hdrhistogram::Histogram<u64>`
//! (recording the elapsed-nanos per event). On bucket roll the
//! histogram's percentiles are snapshotted into a 240-deep ring and
//! the histogram is reset.

use std::collections::VecDeque;

use flux::communication::{
    queue::{ConsumerBare, Queue},
    timer::TimingMessage,
};
use hdrhistogram::Histogram;

use crate::{discovery::TimingFile, sources::counters::BUCKET_HISTORY_LEN};

/// Bucket snapshot of one timer's distribution.
#[derive(Clone, Copy, Debug, Default)]
pub struct TimingBucket {
    pub count: u64,
    pub p50_ns: u64,
    pub p99_ns: u64,
}

pub struct TimingSet {
    pub name: String,
    consumer: ConsumerBare<TimingMessage>,
    /// Running histogram for the *current* bucket.
    hist: Histogram<u64>,
    /// Last successfully decoded elapsed-nanos value, for the live
    /// column.
    pub last_ns: u64,
    /// Total events drained since open.
    pub total_count: u64,
    /// Ring of completed-bucket snapshots (newest at back).
    pub history: VecDeque<TimingBucket>,
}

impl TimingSet {
    pub fn open(file: &TimingFile) -> Result<Self, String> {
        // flux `Queue::open_shared` panics on failure; use try_open
        // to surface the error cleanly.
        let queue: Queue<TimingMessage> = Queue::try_open_shared(&file.path)
            .map_err(|e| format!("open_shared({:?}): {e:?}", file.path))?;
        let label: &'static str = Box::leak(format!("surfer-{}", file.name).into_boxed_str());
        // `try_consume` lazily inits the broadcast cursor on first call.
        let consumer = ConsumerBare::<TimingMessage>::new(queue, label);
        Ok(Self {
            name: file.name.clone(),
            consumer,
            // 1 ns .. 60 s, 3 significant digits.
            hist: Histogram::<u64>::new_with_bounds(1, 60_000_000_000, 3).expect("hdrhist bounds"),
            last_ns: 0,
            total_count: 0,
            history: VecDeque::with_capacity(BUCKET_HISTORY_LEN),
        })
    }

    /// Drain everything currently available in the queue.
    pub fn drain(&mut self) {
        let mut msg = TimingMessage::default();
        while self.consumer.try_consume(&mut msg).is_ok() {
            if !msg.is_valid() {
                continue;
            }
            let ns = msg.elapsed().0;
            self.last_ns = ns;
            self.total_count += 1;
            // Saturate at histogram upper bound rather than fail.
            self.hist.saturating_record(ns);
        }
    }

    /// Snapshot p50/p99 + count into the bucket ring, then reset.
    pub fn roll_bucket(&mut self) {
        let bucket = TimingBucket {
            count: self.hist.len(),
            p50_ns: self.hist.value_at_quantile(0.50),
            p99_ns: self.hist.value_at_quantile(0.99),
        };
        if self.history.len() == BUCKET_HISTORY_LEN {
            self.history.pop_front();
        }
        self.history.push_back(bucket);
        self.hist.reset();
    }

    pub fn last_bucket(&self) -> Option<TimingBucket> {
        self.history.back().copied()
    }

    /// Live in-progress bucket aggregates — drained on every UI tick.
    /// Returns `None` when the running histogram is empty.
    pub fn current_bucket(&self) -> Option<TimingBucket> {
        if self.hist.is_empty() {
            None
        } else {
            Some(TimingBucket {
                count: self.hist.len(),
                p50_ns: self.hist.value_at_quantile(0.50),
                p99_ns: self.hist.value_at_quantile(0.99),
            })
        }
    }
}
