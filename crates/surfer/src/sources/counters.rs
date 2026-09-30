//! Sampling and bucketed history over a `silver_observe::CounterMap`.
//!
//! Holds (current, previous_sample) snapshots so the UI can render
//! deltas without recomputing on every frame.

use std::{collections::VecDeque, io};

use silver_observe::{CounterFile, CounterMap, hide_zero, names_for};

/// Bucket-roll cadence, in seconds. 1 s gives sub-slot resolution on
/// counter rates; trade-off is shorter retention at fixed depth.
pub const BUCKET_SECS: u64 = 1;
/// 1 s bucket × 240 = 4 minutes of history.
pub const BUCKET_HISTORY_LEN: usize = 240;
/// 10 ticks (100 ms) per 1 s bucket — same 4-minute span as the bucket ring.
pub const TICK_HISTORY_LEN: usize = BUCKET_HISTORY_LEN * 10;

pub struct CounterSet {
    pub name: String,
    pub slot_names: Vec<String>,
    /// Whether `slot_names` come from a registered schema (`true`) or
    /// are positional fallbacks because no schema was wired up
    /// (`false`).
    pub schema_registered: bool,
    /// Zero-valued slots are hidden (dense pre-allocated layouts where
    /// only touched slots carry signal).
    hide_zero: bool,
    pub map: CounterMap,
    /// Last sampled values, one per slot.
    pub current: Vec<u64>,
    /// Highest `tcache_length()` seen since open; meaningless for other sets.
    pub max_length: u64,
    /// Previous sample — for delta-vs-tick rendering.
    pub previous: Vec<u64>,
    /// Values at the start of the current bucket.
    bucket_start: Vec<u64>,
    /// Per-slot ring of completed-bucket deltas (newest at back).
    pub history: Vec<VecDeque<u64>>,
    /// Per-slot ring of absolute values sampled at each bucket close —
    /// drives the drill-in value chart.
    pub value_history: Vec<VecDeque<u64>>,
    /// Per-slot ring of per-tick (100 ms) deltas — drives the drill-in
    /// delta chart alongside `history`.
    pub tick_history: Vec<VecDeque<u64>>,
    /// `false` until the first `sample()` call. The first sample
    /// primes `previous` and `bucket_start` so initial deltas start
    /// at 0 rather than a wraparound (matters for slots initialised
    /// to non-zero sentinels like `u64::MAX`).
    primed: bool,
}

impl CounterSet {
    pub fn open(file: &CounterFile) -> io::Result<Self> {
        let map = CounterMap::open(file)?;
        let slot_count = map.slot_count();
        let (slot_names, schema_registered) = names_for(&file.name, slot_count);
        let hide_zero = hide_zero(&file.name);

        Ok(Self {
            name: file.name.clone(),
            slot_names,
            schema_registered,
            hide_zero,
            map,
            current: vec![0; slot_count],
            max_length: 0,
            previous: vec![0; slot_count],
            bucket_start: vec![0; slot_count],
            history: (0..slot_count).map(|_| VecDeque::with_capacity(BUCKET_HISTORY_LEN)).collect(),
            value_history: (0..slot_count)
                .map(|_| VecDeque::with_capacity(BUCKET_HISTORY_LEN))
                .collect(),
            tick_history: (0..slot_count).map(|_| VecDeque::new()).collect(),
            primed: false,
        })
    }

    /// Read all slots into `current`, after copying the previous tick's
    /// values into `previous`.
    pub fn sample(&mut self) {
        self.previous.copy_from_slice(&self.current);
        self.map.read_into(&mut self.current);
        if !self.primed {
            // Prime previous/bucket_start to the first observed values
            // so deltas start at 0. Slots initialised to non-zero
            // sentinels (e.g. tcache tails = u64::MAX) would otherwise
            // produce a wraparound delta on the first roll.
            self.previous.copy_from_slice(&self.current);
            self.bucket_start.copy_from_slice(&self.current);
            self.primed = true;
        }
        for i in 0..self.current.len() {
            // Same sentinel handling as `roll_bucket`; gauge decrements
            // wrap negative deltas through the u64, matching `history`.
            let delta = if self.current[i] == u64::MAX || self.previous[i] == u64::MAX {
                0
            } else {
                self.current[i].wrapping_sub(self.previous[i])
            };
            let t = &mut self.tick_history[i];
            if t.len() == TICK_HISTORY_LEN {
                t.pop_front();
            }
            t.push_back(delta);
        }
    }

    pub fn slot_count(&self) -> usize {
        self.current.len()
    }

    /// Lowest published tail of a tcache set. Sentinel slots are unused and
    /// do not drag the minimum; with no consumer published at all, the ring
    /// holds what the producer sees, `head - capacity` clamped at 0.
    pub fn tcache_min_tail(&self) -> u64 {
        let capacity = self.current.first().copied().unwrap_or(0);
        let head = self.current.get(1).copied().unwrap_or(0);
        let tails = || self.current.iter().skip(2).copied();
        if tails().any(|t| t != u64::MAX) {
            tails().map(|t| if t == u64::MAX { head } else { t }).min().unwrap_or(head)
        } else {
            head.saturating_sub(capacity)
        }
    }

    pub fn tcache_length(&self) -> u64 {
        self.current.get(1).copied().unwrap_or(0).saturating_sub(self.tcache_min_tail())
    }

    pub fn sample_tcache(&mut self) {
        self.sample();
        self.max_length = self.max_length.max(self.tcache_length());
    }

    /// Traffic counters are monotonic so rows appear and stay; gauge
    /// slots (mesh size) can drop back to zero and re-hide.
    pub fn slot_visible(&self, i: usize) -> bool {
        !self.hide_zero || self.current.get(i).copied().unwrap_or(0) != 0
    }

    pub fn visible_slots(&self) -> usize {
        if !self.hide_zero {
            return self.current.len();
        }
        self.current.iter().filter(|&&v| v != 0).count()
    }

    /// Close the current bucket: for each slot, compute
    /// `current - bucket_start` and push to the per-slot history ring
    /// (drop oldest when full). Then snapshot `current` into
    /// `bucket_start` so the next bucket starts accumulating from now.
    ///
    /// Sentinel handling: when either endpoint of the delta is
    /// `u64::MAX` (TCache tail "unused-slot" sentinel; not a real
    /// metric value anywhere else), the delta is recorded as 0. This
    /// suppresses garbage spikes when a slot transitions to/from
    /// sentinel state — common at startup if the mmap file was reused
    /// from a previous run.
    pub fn roll_bucket(&mut self) {
        for i in 0..self.current.len() {
            let delta = if self.current[i] == u64::MAX || self.bucket_start[i] == u64::MAX {
                0
            } else {
                self.current[i].wrapping_sub(self.bucket_start[i])
            };
            let h = &mut self.history[i];
            if h.len() == BUCKET_HISTORY_LEN {
                h.pop_front();
            }
            h.push_back(delta);

            let v = &mut self.value_history[i];
            if v.len() == BUCKET_HISTORY_LEN {
                v.pop_front();
            }
            v.push_back(self.current[i]);

            self.bucket_start[i] = self.current[i];
        }
    }

    /// Most recent completed bucket delta for slot `i`, or 0 if no
    /// bucket has rolled yet.
    pub fn last_bucket_delta(&self, i: usize) -> u64 {
        self.history.get(i).and_then(|h| h.back().copied()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use silver_common::declare_counters;
    use tempfile::TempDir;

    declare_counters! {
        SurferTestCounters => "surfer_smoke" {
            Alpha,
            Beta,
            Gamma,
        }
    }

    #[test]
    fn discover_open_sample() {
        let tmp = TempDir::new().unwrap();
        SurferTestCounters::init_with_base(tmp.path(), "surfer_test").unwrap();

        SurferTestCounters::Alpha.set(0);
        SurferTestCounters::Beta.set(0);
        SurferTestCounters::Gamma.set(0);
        SurferTestCounters::Alpha.add(11);
        SurferTestCounters::Beta.set(42);

        let sources = silver_observe::discover(tmp.path(), "surfer_test").unwrap();
        let file = sources.counters.iter().find(|f| f.name == "surfer_smoke").unwrap();

        let mut set = super::CounterSet::open(file).unwrap();
        set.sample();

        // After init() the slot count == _Count discriminant.
        assert_eq!(set.slot_count(), 3);
        assert_eq!(set.current[0], 11);
        assert_eq!(set.current[1], 42);
        assert_eq!(set.current[2], 0);

        // Mutate, re-sample, check delta.
        SurferTestCounters::Alpha.add(5);
        set.sample();
        assert_eq!(set.current[0], 16);
        assert_eq!(set.previous[0], 11);
    }
}
