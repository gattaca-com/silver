//! Consumer for flux `latency-{name}` shmem queues — the latency side
//! of a flux `Timer`, emitted by tcache consumers (reserve→first-read
//! gap). The processing side is no longer produced: `#[timed]` records
//! into the flamegraph rings now, not flux Timer queues.
//!
//! On `roll_bucket` the running histogram is snapshotted into its
//! 240-deep ring and reset.

use std::{collections::VecDeque, path::Path};

use flux::communication::{
    queue::{ConsumerBare, Queue},
    timer::TimingMessage,
};
use hdrhistogram::Histogram;

use crate::{discovery::TimingFile, sources::counters::BUCKET_HISTORY_LEN};

/// Bucket snapshot of one channel's distribution.
#[derive(Clone, Copy, Debug, Default)]
pub struct TimingBucket {
    pub count: u64,
    pub p50_ns: u64,
    pub p99_ns: u64,
}

/// A tcache consumer's latency stream — reserve→first-read gap.
pub struct TimingChannel {
    consumer: ConsumerBare<TimingMessage>,
    hist: Histogram<u64>,
    pub last_ns: u64,
    pub total_count: u64,
    pub history: VecDeque<TimingBucket>,
}

impl TimingChannel {
    fn open(path: &Path, label: &'static str) -> Result<Self, String> {
        let queue: Queue<TimingMessage> =
            Queue::try_open_shared(path).map_err(|e| format!("open_shared({path:?}): {e:?}"))?;
        let consumer = ConsumerBare::<TimingMessage>::new(queue, label);
        Ok(Self {
            consumer,
            hist: Histogram::<u64>::new_with_bounds(1, 60_000_000_000, 3).expect("hdrhist bounds"),
            last_ns: 0,
            total_count: 0,
            history: VecDeque::with_capacity(BUCKET_HISTORY_LEN),
        })
    }

    pub fn drain(&mut self) {
        let mut msg = TimingMessage::default();
        while self.consumer.try_consume(&mut msg).is_ok() {
            if !msg.is_valid() {
                continue;
            }
            let ns = msg.elapsed().0;
            self.last_ns = ns;
            self.total_count += 1;
            self.hist.saturating_record(ns);
        }
    }

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

    /// Live in-progress bucket — `None` when the running histogram is
    /// empty. Used to extend the chart with a per-tick point.
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

pub struct TimingSet {
    pub name: String,
    pub latency: TimingChannel,
}

impl TimingSet {
    pub fn open(file: &TimingFile) -> Result<Self, String> {
        let label: &'static str = Box::leak(format!("surfer-l-{}", file.name).into_boxed_str());
        let latency = TimingChannel::open(&file.path, label)?;
        Ok(Self { name: file.name.clone(), latency })
    }
}
