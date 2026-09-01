//! Consumer for flux `latency-{name}` / `timing-{name}` shmem queues —
//! the two sides of a flux `Timer`. Latency: tcache reserve→first-read
//! gap, or spine ingestion→consume gap. Processing (`timing-`): the
//! consume handler's duration; emitted by spine consumers only, so a
//! `timing-` queue may exist yet stay empty.
//!
//! On `roll_bucket` the running histogram is snapshotted into its
//! 240-deep ring and reset.

use std::{collections::VecDeque, path::Path};

use flux::communication::{
    ReadError,
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
    /// Largest sample seen since surfer attached (never reset).
    pub max_ns: u64,
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
            max_ns: 0,
            total_count: 0,
            history: VecDeque::with_capacity(BUCKET_HISTORY_LEN),
        })
    }

    #[cfg(test)]
    fn from_consumer(consumer: ConsumerBare<TimingMessage>) -> Self {
        Self {
            consumer,
            hist: Histogram::<u64>::new_with_bounds(1, 60_000_000_000, 3).expect("hdrhist bounds"),
            last_ns: 0,
            max_ns: 0,
            total_count: 0,
            history: VecDeque::with_capacity(BUCKET_HISTORY_LEN),
        }
    }

    pub fn drain(&mut self) {
        let mut msg = TimingMessage::default();
        loop {
            match self.consumer.try_consume(&mut msg) {
                Ok(()) => {}
                Err(ReadError::Empty) => break,
                // The producer lapped us (the busiest timers do, between UI
                // ticks). Resnap to the head and keep draining — stopping
                // here left the channel dead until surfer restarted.
                Err(ReadError::SpedPast) => {
                    self.consumer.recover_after_error();
                    continue;
                }
            }
            if !msg.is_valid() {
                continue;
            }
            let ns = msg.elapsed().0;
            self.last_ns = ns;
            self.max_ns = self.max_ns.max(ns);
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
    pub processing: Option<TimingChannel>,
}

impl TimingSet {
    pub fn has_values(&self) -> bool {
        self.latency.total_count > 0 || self.processing.as_ref().is_some_and(|p| p.total_count > 0)
    }

    pub fn open(file: &TimingFile) -> Result<Self, String> {
        let label: &'static str = Box::leak(format!("surfer-l-{}", file.name).into_boxed_str());
        let latency = TimingChannel::open(&file.path, label)?;
        let processing = file.processing_path.as_ref().and_then(|path| {
            let label: &'static str = Box::leak(format!("surfer-p-{}", file.name).into_boxed_str());
            TimingChannel::open(path, label).ok()
        });
        Ok(Self { name: file.name.clone(), latency, processing })
    }

    pub fn drain(&mut self) {
        self.latency.drain();
        if let Some(p) = &mut self.processing {
            p.drain();
        }
    }

    pub fn roll_bucket(&mut self) {
        self.latency.roll_bucket();
        if let Some(p) = &mut self.processing {
            p.roll_bucket();
        }
    }
}

#[cfg(test)]
mod tests {
    use flux::communication::queue::{Producer, QueueType};

    use super::*;

    /// Regression: the busiest timer queues lap surfer between UI ticks;
    /// `drain` stopping on `SpedPast` left the channel dead until restart.
    /// A lapped consumer must resnap to the head and keep counting.
    #[test]
    fn lapped_drain_recovers_and_keeps_counting() {
        let queue: Queue<TimingMessage> = Queue::new(8, QueueType::SPMC);
        let mut producer = Producer::from(queue);
        let mut ch = TimingChannel::from_consumer(ConsumerBare::new(queue, "lap-test"));
        let msg = TimingMessage::default();

        // First drain initialises the broadcast cursor at the current head.
        ch.drain();
        for _ in 0..3 {
            producer.produce(&msg);
        }
        ch.drain();
        assert_eq!(ch.total_count, 3);

        // Lap the consumer several times over. Recovery resnaps to the
        // head — the next slot the producer will write — so the lapped
        // messages are lost by design and this drain may add nothing.
        for _ in 0..40 {
            producer.produce(&msg);
        }
        ch.drain();
        let after_lap = ch.total_count;

        // The property under test: the channel resumes on the next writes
        // instead of staying dead until surfer restarts.
        for _ in 0..2 {
            producer.produce(&msg);
        }
        ch.drain();
        assert_eq!(ch.total_count, after_lap + 2, "a lapped drain must resnap, not die");
    }
}
