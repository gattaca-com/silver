//! Consumer for flux `timing-{name}` / `latency-{name}` shmem queue
//! pairs. Each `TimingSet` covers one flux `Timer` instance — flux
//! always creates both queue files, but a given Timer may only emit
//! to one side (e.g. `#[timed]` writes only processing, tcache
//! consumer timers write only latency). Channels with no observed
//! events render as "no data" instead of empty graphs.
//!
//! On `roll_bucket` each channel's running histogram is snapshotted
//! into its 240-deep ring and reset.

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

/// One side of a flux `Timer` — either processing or latency.
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

    /// `true` once at least one event has been drained — used by the
    /// pane to decide whether to render a chart for this channel.
    pub fn has_data(&self) -> bool {
        self.total_count > 0
    }
}

pub struct TimingSet {
    pub name: String,
    pub timing: Option<TimingChannel>,
    pub latency: Option<TimingChannel>,
}

impl TimingSet {
    pub fn open(file: &TimingFile) -> Result<Self, String> {
        let timing = if let Some(path) = &file.timing_path {
            let label: &'static str = Box::leak(format!("surfer-t-{}", file.name).into_boxed_str());
            TimingChannel::open(path, label).ok()
        } else {
            None
        };
        let latency = if let Some(path) = &file.latency_path {
            let label: &'static str = Box::leak(format!("surfer-l-{}", file.name).into_boxed_str());
            TimingChannel::open(path, label).ok()
        } else {
            None
        };
        if timing.is_none() && latency.is_none() {
            return Err(format!("no openable queue for {}", file.name));
        }
        Ok(Self { name: file.name.clone(), timing, latency })
    }

    pub fn drain(&mut self) {
        if let Some(c) = &mut self.timing {
            c.drain();
        }
        if let Some(c) = &mut self.latency {
            c.drain();
        }
    }

    pub fn roll_bucket(&mut self) {
        if let Some(c) = &mut self.timing {
            c.roll_bucket();
        }
        if let Some(c) = &mut self.latency {
            c.roll_bucket();
        }
    }

    /// Channel preferred for the table row's summary stats: latency
    /// when present (more interesting for spine/tcache timers), else
    /// timing.
    pub fn primary(&self) -> Option<&TimingChannel> {
        self.latency.as_ref().filter(|c| c.has_data()).or(self.timing.as_ref())
    }
}
