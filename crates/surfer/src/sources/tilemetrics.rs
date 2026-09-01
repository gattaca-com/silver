//! Consumer for a flux `tilemetrics-{name}` SPMC queue. Each
//! `TileSample` represents a 1024-iteration window of one tile's loop:
//! total ticks, busy ticks, busy/avg/min/max per work-iter, loop_count.
//!
//! Samples emit per loop-window — thousands/sec on a hot tile — so a
//! fixed sample count spans only milliseconds and a burst is overwritten
//! before it can be read. Instead we sum busy/total ticks into 1 s
//! wall-clock buckets (mirroring counters/timings) and report
//! utilisation over the retained bucket ring.

use std::collections::VecDeque;

use flux::{
    communication::{
        ReadError,
        queue::{ConsumerBare, Queue},
    },
    tile::metrics::TileSample,
};

use crate::{discovery::TileMetricsFile, sources::counters::BUCKET_HISTORY_LEN};

/// Busy/total tick sums over one wall-clock bucket, plus per-work-iteration
/// busy stats (count + max) so avg/max survive the idle-snapshot problem.
#[derive(Clone, Copy, Debug, Default)]
pub struct UtilBucket {
    pub busy: u64,
    pub total: u64,
    /// Number of work-iterations (busy_count) summed over the bucket.
    pub busy_count: u64,
    /// Largest single work-iteration (ns) seen in the bucket.
    pub busy_max: u64,
}

impl UtilBucket {
    #[inline]
    pub fn utilisation(&self) -> f64 {
        if self.total == 0 { 0.0 } else { self.busy as f64 / self.total as f64 }
    }
}

pub struct TileMetricsSet {
    pub name: String,
    consumer: ConsumerBare<TileSample>,
    pub latest: TileSample,
    /// In-progress bucket accumulated across drains since the last roll.
    cur: UtilBucket,
    /// Per-bucket busy/total over the retained window (240 × 1 s = 4 min).
    pub history: VecDeque<UtilBucket>,
    pub samples_seen: u64,
    /// Cumulative busy/total ticks across the whole run (never reset);
    /// diagnostic for whether any busy time is being attributed at all.
    pub total_busy: u64,
    pub total_ticks: u64,
}

impl TileMetricsSet {
    pub fn open(file: &TileMetricsFile) -> Result<Self, String> {
        let queue: Queue<TileSample> = Queue::try_open_shared(&file.path)
            .map_err(|e| format!("open_shared({:?}): {e:?}", file.path))?;
        let label: &'static str = Box::leak(format!("surfer-{}", file.name).into_boxed_str());
        let consumer = ConsumerBare::<TileSample>::new(queue, label);
        Ok(Self {
            name: file.name.clone(),
            consumer,
            latest: TileSample::default(),
            cur: UtilBucket::default(),
            history: VecDeque::with_capacity(BUCKET_HISTORY_LEN),
            samples_seen: 0,
            total_busy: 0,
            total_ticks: 0,
        })
    }

    /// Drain everything currently available into the in-progress bucket.
    pub fn drain(&mut self) {
        let mut sample = TileSample::default();
        loop {
            match self.consumer.try_consume(&mut sample) {
                Ok(()) => {}
                Err(ReadError::Empty) => break,
                // Lapped: resnap to the head and keep draining — see
                // `TimingChannel::drain`.
                Err(ReadError::SpedPast) => {
                    self.consumer.recover_after_error();
                    continue;
                }
            }
            self.latest = sample;
            self.samples_seen += 1;
            self.cur.busy += sample.busy_ticks;
            self.cur.total += sample.total_ticks();
            self.cur.busy_count += sample.busy_count as u64;
            self.cur.busy_max = self.cur.busy_max.max(sample.busy_max);
            self.total_busy += sample.busy_ticks;
            self.total_ticks += sample.total_ticks();
        }
    }

    /// Snapshot the in-progress bucket into the ring and reset. Driven by
    /// the wall-clock bucket tick, same as counters/timings.
    pub fn roll_bucket(&mut self) {
        if self.history.len() == BUCKET_HISTORY_LEN {
            self.history.pop_front();
        }
        self.history.push_back(self.cur);
        self.cur = UtilBucket::default();
    }

    /// Mean duty cycle over the retained window.
    pub fn util_avg(&self) -> f64 {
        let (busy, total) =
            self.history.iter().fold((0u64, 0u64), |(b, t), e| (b + e.busy, t + e.total));
        if total == 0 { 0.0 } else { busy as f64 / total as f64 }
    }

    /// Busiest single bucket over the retained window.
    pub fn util_peak(&self) -> f64 {
        self.history.iter().map(UtilBucket::utilisation).fold(0.0_f64, f64::max)
    }

    /// Mean ns per work-iteration over the retained window
    /// (busy_sum/busy_count).
    pub fn busy_avg_ns(&self) -> u64 {
        let (sum, count) =
            self.history.iter().fold((0u64, 0u64), |(s, c), e| (s + e.busy, c + e.busy_count));
        if count == 0 { 0 } else { sum / count }
    }

    /// Largest single work-iteration (ns) over the retained window.
    pub fn busy_max_ns(&self) -> u64 {
        self.history.iter().map(|e| e.busy_max).max().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use flux::{
        communication::queue::{Producer, Queue, QueueType},
        tile::metrics::TileMetrics,
        timing::{IngestionTime, Nanos},
    };

    use super::*;
    use crate::discovery::TileMetricsFile;

    /// Synthetic sample with known busy/total ticks. `util = busy / total`.
    #[allow(clippy::field_reassign_with_default)] // busy_min is private; can't use a literal
    fn mk(busy: u64, total: u64) -> TileSample {
        let mut s = TileSample::default();
        s.window_start = Nanos(0);
        s.window_end = Nanos(total);
        s.busy_ticks = busy;
        s
    }

    /// Stand up a real shmem queue + consumer at a unique path. Open the
    /// consumer BEFORE producing: broadcast cursors start at head, so a late
    /// join skips earlier messages.
    fn rig(tag: &str) -> (Producer<TileSample>, TileMetricsSet, std::path::PathBuf) {
        let tmp =
            std::env::temp_dir().join(format!("surfer_tileutil_{tag}_{}", std::process::id()));
        std::fs::remove_dir_all(&tmp).ok();
        std::fs::create_dir_all(&tmp).unwrap();
        let path = tmp.join(format!("tilemetrics-{tag}"));
        let queue: Queue<TileSample> = Queue::create_or_open_shared(&path, 4096, QueueType::SPMC);
        let producer = Producer::from(queue);
        let file = TileMetricsFile { name: tag.into(), path: path.clone() };
        let mut set = TileMetricsSet::open(&file).unwrap();
        // Prime the cursor at head before producing — the broadcast consumer
        // anchors on first consume, so a pre-produce drain avoids skipping the
        // backlog (mirrors main.rs's startup drain).
        set.drain();
        (producer, set, tmp)
    }

    /// Drives drain → roll_bucket → util_avg/util_peak end-to-end through the
    /// queue, isolating the surfer arithmetic from the flux producer path.
    #[test]
    fn util_calculation_over_buckets() {
        let (mut producer, mut set, tmp) = rig("calc");

        // No buckets rolled yet.
        assert_eq!(set.util_avg(), 0.0);
        assert_eq!(set.util_peak(), 0.0);

        // Bucket A: 200/1000 + 600/1000 → busy 800, total 2000, util 0.4.
        producer.produce(&mk(200, 1000));
        producer.produce(&mk(600, 1000));
        set.drain();
        set.roll_bucket();

        // Bucket B: 100/1000 → util 0.1.
        producer.produce(&mk(100, 1000));
        set.drain();
        set.roll_bucket();

        // avg = (800+100)/(2000+1000) = 0.3; peak = busiest bucket = 0.4.
        assert!((set.util_avg() - 0.3).abs() < 1e-9, "avg={}", set.util_avg());
        assert!((set.util_peak() - 0.4).abs() < 1e-9, "peak={}", set.util_peak());
        assert_eq!(set.total_busy, 900);
        assert_eq!(set.total_ticks, 3000);
        assert_eq!(set.samples_seen, 3);

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// A nonzero-busy sample MUST produce nonzero util. If the live TUI shows
    /// zeros, busy_ticks is zero upstream (flux/did_work), not here.
    #[test]
    fn nonzero_busy_yields_nonzero_util() {
        let (mut producer, mut set, tmp) = rig("nz");

        producer.produce(&mk(1, 1_000_000));
        set.drain();
        set.roll_bucket();

        assert!(set.util_avg() > 0.0, "avg={}", set.util_avg());
        assert!(set.util_peak() > 0.0, "peak={}", set.util_peak());
        assert_eq!(set.total_busy, 1);

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// Producer-side bracket: drive the real flux
    /// `TileMetrics::begin/end(true)` over a full SAMPLE_WINDOW with
    /// measurable work, then read the emitted sample. Confirms that
    /// `did_work=true` + real elapsed time yields `busy_ticks > 0` — i.e.
    /// the flux timing attribution itself works.
    #[test]
    fn flux_producer_attributes_busy() {
        let tmp = std::env::temp_dir().join(format!("surfer_fluxprod_{}", std::process::id()));
        std::fs::remove_dir_all(&tmp).ok();
        std::fs::create_dir_all(&tmp).unwrap();

        // TileMetrics::new creates the queue under the app's shmem dir.
        let mut tm = TileMetrics::new(&tmp, "fluxprodapp", "fluxprod");

        // Attach the consumer before producing (prime cursor at head).
        let sources = crate::discovery::discover(&tmp, "fluxprodapp").unwrap();
        let file = sources.tilemetrics.iter().find(|f| f.name == "fluxprod").unwrap();
        let mut set = TileMetricsSet::open(file).unwrap();
        set.drain();

        // One full window of did_work=true iterations with real work between
        // begin and end so the busy timer has something to measure.
        let mut acc = 0u64;
        for _ in 0..1024 {
            tm.begin(IngestionTime::now());
            for i in 0..4096u64 {
                acc = acc.wrapping_add(std::hint::black_box(i));
            }
            tm.end(true);
        }
        std::hint::black_box(acc);

        set.drain();
        set.roll_bucket();
        assert!(set.samples_seen >= 1, "no sample emitted");
        assert!(set.total_busy > 0, "flux attributed zero busy despite did_work=true");
        assert!(set.util_avg() > 0.0, "avg={}", set.util_avg());

        std::fs::remove_dir_all(&tmp).ok();
    }
}
