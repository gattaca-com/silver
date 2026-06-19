//! Consumer for `perf-{name}` MPMC queues emitted by `#[timed]` functions
//! built with the `perf` feature. Each `PerfSample` is one call: raw counter
//! values, positional by `silver_metrics::schema()` slot.
//!
//! Samples are summed into 1 s wall-clock buckets (mirroring
//! counters/timings); table stats average over the last
//! `TABLE_WINDOW_BUCKETS` so they track current behaviour, while the full
//! ring feeds the drill-down IPC chart. Counters are looked up by event name
//! (`instructions`, `cpu-cycles`, …); a name absent from the active schema
//! reads zero.

use std::collections::VecDeque;

use flux::communication::queue::{ConsumerBare, Queue};
use silver_metrics::{MAX_EVENTS, PerfSample, slot};

use crate::{discovery::PerfFile, sources::counters::BUCKET_HISTORY_LEN};

/// Table stats average over the last 30 s of 1 s buckets.
const TABLE_WINDOW_BUCKETS: usize = 30;

/// Call count and per-slot counter sums over one wall-clock bucket.
#[derive(Clone, Copy, Debug, Default)]
pub struct PerfBucket {
    pub count: u64,
    pub vals: [u64; MAX_EVENTS],
}

impl PerfBucket {
    /// Summed value of the event labelled `label`, or 0 if it isn't in the
    /// active schema.
    fn val(&self, label: &str) -> u64 {
        slot(label).map_or(0, |i| self.vals[i])
    }

    /// CPU cycles under either spelling perf uses.
    fn cycles(&self) -> u64 {
        self.val("cpu-cycles").max(self.val("cycles"))
    }

    #[inline]
    pub fn ipc(&self) -> f64 {
        let cycles = self.cycles();
        if cycles == 0 { 0.0 } else { self.val("instructions") as f64 / cycles as f64 }
    }
}

pub struct PerfSet {
    pub name: String,
    consumer: ConsumerBare<PerfSample>,
    /// In-progress bucket accumulated across drains since the last roll.
    cur: PerfBucket,
    /// Per-bucket sums over the retained window (240 × 1 s = 4 min).
    pub history: VecDeque<PerfBucket>,
    pub total_count: u64,
}

impl PerfSet {
    pub fn open(file: &PerfFile) -> Result<Self, String> {
        let queue: Queue<PerfSample> = Queue::try_open_shared(&file.path)
            .map_err(|e| format!("open_shared({:?}): {e:?}", file.path))?;
        let label: &'static str = Box::leak(format!("surfer-perf-{}", file.name).into_boxed_str());
        let consumer = ConsumerBare::<PerfSample>::new(queue, label);
        Ok(Self {
            name: file.name.clone(),
            consumer,
            cur: PerfBucket::default(),
            history: VecDeque::with_capacity(BUCKET_HISTORY_LEN),
            total_count: 0,
        })
    }

    /// Drain everything currently available into the in-progress bucket.
    pub fn drain(&mut self) {
        let mut sample = PerfSample::default();
        while self.consumer.try_consume(&mut sample).is_ok() {
            self.cur.count += 1;
            for i in 0..MAX_EVENTS {
                self.cur.vals[i] += sample.vals[i];
            }
            self.total_count += 1;
        }
    }

    /// Snapshot the in-progress bucket into the ring and reset. Driven by
    /// the wall-clock bucket tick, same as counters/timings.
    pub fn roll_bucket(&mut self) {
        if self.history.len() == BUCKET_HISTORY_LEN {
            self.history.pop_front();
        }
        self.history.push_back(self.cur);
        self.cur = PerfBucket::default();
    }

    /// Last `TABLE_WINDOW_BUCKETS` buckets — the table stats window.
    fn recent(&self) -> impl Iterator<Item = &PerfBucket> + '_ {
        self.history.iter().rev().take(TABLE_WINDOW_BUCKETS)
    }

    fn recent_sums(&self) -> PerfBucket {
        let mut acc = PerfBucket::default();
        for b in self.recent() {
            acc.count += b.count;
            for i in 0..MAX_EVENTS {
                acc.vals[i] += b.vals[i];
            }
        }
        acc
    }

    /// Mean calls/s over the table window (buckets are 1 s).
    pub fn call_rate(&self) -> u64 {
        let n = self.history.len().min(TABLE_WINDOW_BUCKETS) as u64;
        if n == 0 { 0 } else { self.recent_sums().count / n }
    }

    /// Mean instructions retired per call over the table window.
    pub fn instr_avg(&self) -> u64 {
        let s = self.recent_sums();
        if s.count == 0 { 0 } else { s.val("instructions") / s.count }
    }

    /// Mean CPU cycles per call over the table window.
    pub fn cycles_avg(&self) -> u64 {
        let s = self.recent_sums();
        if s.count == 0 { 0 } else { s.cycles() / s.count }
    }

    /// Cycle-weighted instructions per cycle over the table window.
    pub fn ipc(&self) -> f64 {
        self.recent_sums().ipc()
    }

    /// Branch misses per 1k instructions over the table window.
    pub fn branch_per_kinstr(&self) -> f64 {
        let s = self.recent_sums();
        let instr = s.val("instructions");
        if instr == 0 { 0.0 } else { s.val("branch-misses") as f64 * 1000.0 / instr as f64 }
    }

    /// Mean LLC misses per call over the table window.
    pub fn cache_miss_avg(&self) -> u64 {
        let s = self.recent_sums();
        if s.count == 0 { 0 } else { s.val("cache-misses") / s.count }
    }

    pub fn has_data(&self) -> bool {
        self.total_count > 0
    }
}

#[cfg(test)]
mod tests {
    use flux::communication::queue::{Producer, Queue, QueueType};

    use super::*;
    use crate::discovery::PerfFile;

    /// Build a sample by metric name (order-independent), so it tracks
    /// whatever the default schema resolves to.
    fn sample(instr: u64, cycles: u64, branch: u64, cache: u64) -> PerfSample {
        let mut s = PerfSample::default();
        s.vals[slot("instructions").unwrap()] = instr;
        s.vals[slot("cpu-cycles").unwrap()] = cycles;
        s.vals[slot("branch-misses").unwrap()] = branch;
        s.vals[slot("cache-misses").unwrap()] = cache;
        s
    }

    #[test]
    fn aggregates_buckets() {
        let tmp = std::env::temp_dir().join(format!("surfer_perf_{}", std::process::id()));
        std::fs::remove_dir_all(&tmp).ok();
        std::fs::create_dir_all(&tmp).unwrap();
        let path = tmp.join("perf-test_fn");
        let queue: Queue<PerfSample> = Queue::create_or_open_shared(&path, 4096, QueueType::MPMC);
        let mut producer = Producer::from(queue);
        let file = PerfFile { name: "test_fn".into(), path: path.clone() };
        let mut set = PerfSet::open(&file).unwrap();
        // Prime the cursor at head before producing (mirrors main.rs).
        set.drain();

        producer.produce(&sample(3000, 1000, 5, 12));
        producer.produce(&sample(1000, 1000, 3, 4));
        set.drain();
        set.roll_bucket();

        assert_eq!(set.total_count, 2);
        assert_eq!(set.call_rate(), 2);
        assert_eq!(set.instr_avg(), 2000);
        assert_eq!(set.cycles_avg(), 1000);
        assert!((set.ipc() - 2.0).abs() < 1e-9, "ipc = {}", set.ipc());
        // 8 misses / 4000 instr = 2 per 1k.
        assert!((set.branch_per_kinstr() - 2.0).abs() < 1e-9);
        assert_eq!(set.cache_miss_avg(), 8);
        assert!(set.has_data());

        std::fs::remove_dir_all(&tmp).ok();
    }
}
