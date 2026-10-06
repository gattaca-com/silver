//! The node's shmem metrics sources, reduced to one bucket each between
//! encodes. Insertion-only across rediscovery; ids are never reused.

use std::{collections::HashSet, path::Path};

use flux::{
    communication::{
        queue::{Consumer, Queue},
        timer::TimingMessage,
    },
    tile::metrics::TileSample,
};
use hdrhistogram::Histogram;
use silver_log::warn;
use silver_observe::{CounterFile, CounterMap, discover, names_for};
use silver_observe_wire::{Encoder, Source, SourceClass, TileUtil, TimingChannel, TimingStats};

/// Upper bound of the recorded range: a 60 s gap is far past any sane stage.
const HIST_MAX_NS: u64 = 60_000_000_000;
const TCACHE_FIXED_SLOTS: usize = 2;
/// Counter slots also sampled at the fast cadence and published as source
/// `fast:{source}`, for intra-slot resolution the 1 s bucket cannot give.
const FAST: &[(&str, &[&str])] = &[
    ("beacon_state", &["AttestationRootMemoHit", "AttestationRootMemoMiss"]),
    ("network", &[
        "P2pGossipBytesRecv",
        "P2pGossipBytesSent",
        "P2pRpcBytesRecv",
        "P2pRpcBytesSent",
    ]),
];

struct CounterSource {
    id: u16,
    class: SourceClass,
    name: String,
    map: CounterMap,
    values: Vec<u64>,
}

struct FastSource {
    id: u16,
    name: String,
    /// Index into `ExportSources::counters`.
    parent: usize,
    slots: Vec<usize>,
    slot_names: Vec<String>,
    values: Vec<u64>,
}

struct TimingHist {
    consumer: Consumer<TimingMessage>,
    hist: Histogram<u64>,
}

impl TimingHist {
    fn open(path: &Path, label: String) -> Result<Self, String> {
        let queue = Queue::try_open_shared(path).map_err(|e| format!("{path:?}: {e:?}"))?;
        Ok(Self {
            // Lapping is recoverable and expected under bursts.
            consumer: Consumer::new(queue, Box::leak(label.into_boxed_str())).without_log(),
            hist: Histogram::new_with_bounds(1, HIST_MAX_NS, 3).expect("hdrhistogram bounds"),
        })
    }

    fn drain(&mut self) {
        let Self { consumer, hist } = self;
        while consumer.consume(|msg| {
            if msg.is_valid() {
                hist.saturating_record(msg.elapsed().0);
            }
        }) {}
    }

    fn take(&mut self, source_id: u16, channel: TimingChannel) -> TimingStats {
        let stats = TimingStats {
            source_id,
            channel,
            count: self.hist.len(),
            p50_ns: self.hist.value_at_quantile(0.50),
            p99_ns: self.hist.value_at_quantile(0.99),
            max_ns: self.hist.max(),
        };
        self.hist.reset();
        stats
    }
}

struct TimingSource {
    id: u16,
    name: String,
    latency: TimingHist,
    processing: Option<TimingHist>,
}

struct TileSource {
    id: u16,
    name: String,
    consumer: Consumer<TileSample>,
    bucket: TileUtil,
}

impl TileSource {
    fn drain(&mut self) {
        let Self { consumer, bucket, .. } = self;
        while consumer.consume(|sample| {
            bucket.busy += sample.busy_ticks;
            bucket.total += sample.total_ticks();
            bucket.busy_count += sample.busy_count as u64;
            bucket.busy_max = bucket.busy_max.max(sample.busy_max);
        }) {}
    }
}

#[derive(Default)]
pub struct ExportSources {
    counters: Vec<CounterSource>,
    fast: Vec<FastSource>,
    timings: Vec<TimingSource>,
    tiles: Vec<TileSource>,
    build_info: Option<String>,
    seen: HashSet<String>,
    next_id: u16,
    tile_utils: Vec<TileUtil>,
    timing_stats: Vec<TimingStats>,
}

pub struct SeriesCounts {
    pub counter_slots: usize,
    pub tcache_slots: usize,
    pub timing_channels: usize,
    pub tiles: usize,
}

impl ExportSources {
    pub fn discover(&mut self, base_dir: &Path, app_name: &str) {
        let found = match discover(base_dir, app_name) {
            Ok(found) => found,
            Err(e) => {
                warn!(%e, "discovery failed");
                return;
            }
        };
        if found.build_info.is_some() {
            self.build_info = found.build_info;
        }

        let counters = found.counters.iter().map(|f| (f, SourceClass::Counters));
        let tcaches = found.tcaches.iter().map(|f| (f, SourceClass::TCache));
        for (file, class) in counters.chain(tcaches) {
            if let Some(id) = self.claim(class, &file.name) {
                self.open_counter(id, class, file);
            }
        }
        for file in &found.timings {
            let Some(id) = self.claim(SourceClass::Timing, &file.name) else { continue };
            let latency = match TimingHist::open(&file.path, format!("export-l-{}", file.name)) {
                Ok(h) => h,
                Err(e) => {
                    warn!(name = file.name, %e, "timing source skipped");
                    continue;
                }
            };
            let processing = file
                .processing_path
                .as_ref()
                .and_then(|path| TimingHist::open(path, format!("export-p-{}", file.name)).ok());
            self.timings.push(TimingSource { id, name: file.name.clone(), latency, processing });
        }
        for file in &found.tilemetrics {
            let Some(id) = self.claim(SourceClass::Tile, &file.name) else { continue };
            let queue = match Queue::try_open_shared(&file.path) {
                Ok(q) => q,
                Err(e) => {
                    warn!(name = file.name, e = ?e, "tile source skipped");
                    continue;
                }
            };
            let label = Box::leak(format!("export-{}", file.name).into_boxed_str());
            self.tiles.push(TileSource {
                id,
                name: file.name.clone(),
                consumer: Consumer::new(queue, label).without_log(),
                bucket: TileUtil { source_id: id, ..TileUtil::default() },
            });
        }
    }

    /// A failed open still burns the id: the name stays claimed so a broken
    /// file is not retried and logged every rediscovery.
    fn claim(&mut self, class: SourceClass, name: &str) -> Option<u16> {
        if !self.seen.insert(format!("{}/{name}", class as u8)) {
            return None;
        }
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1)?;
        Some(id)
    }

    fn open_counter(&mut self, id: u16, class: SourceClass, file: &CounterFile) {
        match CounterMap::open(file) {
            Ok(map) => {
                let values = vec![0; map.slot_count()];
                self.counters.push(CounterSource {
                    id,
                    class,
                    name: file.name.clone(),
                    map,
                    values,
                });
                self.open_fast(self.counters.len() - 1);
            }
            Err(e) => warn!(name = file.name, %e, "counter source skipped"),
        }
    }

    fn open_fast(&mut self, parent: usize) {
        let c = &self.counters[parent];
        let Some((_, wanted)) = FAST.iter().find(|(name, _)| *name == c.name) else { return };
        let (names, _) = names_for(&c.name, c.values.len());
        let slots: Vec<_> =
            (0..names.len()).filter(|&i| wanted.contains(&names[i].as_str())).collect();
        if slots.is_empty() {
            return;
        }
        let name = format!("fast:{}", c.name);
        let slot_names = slots.iter().map(|&i| names[i].clone()).collect();
        let Some(id) = self.claim(SourceClass::Counters, &name) else { return };
        let values = vec![0; slots.len()];
        self.fast.push(FastSource { id, name, parent, slots, slot_names, values });
    }

    pub fn encode_fast(&mut self, enc: &mut Encoder, ts_ns: u64, emit: &mut impl FnMut(&[u8])) {
        let Self { fast, counters, .. } = self;
        for f in fast {
            let map = &counters[f.parent].map;
            for (v, &slot) in f.values.iter_mut().zip(&f.slots) {
                *v = map.load(slot);
            }
            enc.counter_values(ts_ns, f.id, &f.values, emit);
        }
    }

    pub fn drain(&mut self) {
        for t in &mut self.timings {
            t.latency.drain();
            if let Some(p) = &mut t.processing {
                p.drain();
            }
        }
        for t in &mut self.tiles {
            t.drain();
        }
    }

    pub fn encode_bucket(&mut self, enc: &mut Encoder, ts_ns: u64, emit: &mut impl FnMut(&[u8])) {
        for c in &mut self.counters {
            c.map.read_into(&mut c.values);
            enc.counter_values(ts_ns, c.id, &c.values, emit);
        }

        self.tile_utils.clear();
        for t in &mut self.tiles {
            self.tile_utils.push(t.bucket);
            t.bucket = TileUtil { source_id: t.id, ..TileUtil::default() };
        }
        enc.tile_utils(ts_ns, &self.tile_utils, emit);

        self.timing_stats.clear();
        for t in &mut self.timings {
            self.timing_stats.push(t.latency.take(t.id, TimingChannel::Latency));
            if let Some(p) = &mut t.processing {
                self.timing_stats.push(p.take(t.id, TimingChannel::Processing));
            }
        }
        enc.timings(ts_ns, &self.timing_stats, emit);
    }

    pub fn encode_descriptors(&self, enc: &mut Encoder, ts_ns: u64, emit: &mut impl FnMut(&[u8])) {
        let counters =
            self.counters.iter().map(|c| Source { id: c.id, class: c.class, name: &c.name });
        let timings = self.timings.iter().map(|t| Source {
            id: t.id,
            class: SourceClass::Timing,
            name: &t.name,
        });
        let tiles =
            self.tiles.iter().map(|t| Source { id: t.id, class: SourceClass::Tile, name: &t.name });
        let fast = self.fast.iter().map(|f| Source {
            id: f.id,
            class: SourceClass::Counters,
            name: &f.name,
        });
        let sources: Vec<_> = counters.chain(fast).chain(timings).chain(tiles).collect();
        enc.sources(ts_ns, &sources, emit);

        for c in &self.counters {
            let (mut names, _) = names_for(&c.name, c.values.len());
            // Consumers register after the tcache is created, so names are
            // re-read on every describe.
            if c.class == SourceClass::TCache {
                for (i, name) in names.iter_mut().enumerate().skip(TCACHE_FIXED_SLOTS) {
                    let consumer = c.map.consumer_name(i - TCACHE_FIXED_SLOTS);
                    if !consumer.is_empty() {
                        *name = consumer.to_owned();
                    }
                }
            }
            enc.slot_names(ts_ns, c.id, &names, emit);
        }

        for f in &self.fast {
            enc.slot_names(ts_ns, f.id, &f.slot_names, emit);
        }

        if let Some(build_info) = &self.build_info {
            enc.build_info(ts_ns, build_info, emit);
        }
    }

    pub fn series_counts(&self) -> SeriesCounts {
        let slots =
            |class| self.counters.iter().filter(|c| c.class == class).map(|c| c.values.len()).sum();
        SeriesCounts {
            counter_slots: slots(SourceClass::Counters),
            tcache_slots: slots(SourceClass::TCache),
            timing_channels: self.timings.iter().map(|t| 1 + t.processing.is_some() as usize).sum(),
            tiles: self.tiles.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use silver_common::declare_counters;
    use silver_observe_wire::{HEADER_LEN, Header, Kind};
    use tempfile::TempDir;

    use super::*;

    declare_counters! {
        ExportTestCounters => "export_smoke" {
            Alpha,
            Beta,
        }
    }

    // Same layout as `BeaconStateCounters`, whose names `names_for` applies.
    declare_counters! {
        FastTestCounters => "beacon_state" {
            AttestationPoolFull,
            AttestationUnknownRoot,
            SeenAggregatesFull,
            AttestationRootMemoFull,
            AttestationRootMemoHit,
            AttestationRootMemoMiss,
            VoteBatchSize,
            VoteBatchFallback,
            SyncContributionPoolFull,
        }
    }

    #[test]
    fn fast_source_republishes_only_its_slots() {
        let tmp = TempDir::new().unwrap();
        FastTestCounters::init_with_base(tmp.path(), "fast_test").unwrap();
        FastTestCounters::AttestationRootMemoHit.set(30);
        FastTestCounters::AttestationRootMemoMiss.set(12);
        FastTestCounters::VoteBatchSize.set(99);

        let mut sources = ExportSources::default();
        sources.discover(tmp.path(), "fast_test");
        assert_eq!(sources.fast.len(), 1);
        assert_eq!(sources.fast[0].name, "fast:beacon_state");
        assert_eq!(sources.fast[0].slot_names, [
            "AttestationRootMemoHit",
            "AttestationRootMemoMiss"
        ]);

        let mut enc = Encoder::new(1, 2);
        let mut dgrams = Vec::new();
        sources.encode_fast(&mut enc, 0, &mut |d| dgrams.push(d.to_vec()));
        assert_eq!(dgrams.len(), 1);
        let values = &dgrams[0][HEADER_LEN + 8..];
        assert_eq!(values[..8], 30u64.to_le_bytes());
        assert_eq!(values[8..], 12u64.to_le_bytes());
    }

    #[test]
    fn discovered_counters_are_described_then_bucketed() {
        let tmp = TempDir::new().unwrap();
        ExportTestCounters::init_with_base(tmp.path(), "export_test").unwrap();
        ExportTestCounters::Alpha.set(7);
        ExportTestCounters::Beta.set(9);

        let mut sources = ExportSources::default();
        sources.discover(tmp.path(), "export_test");
        sources.discover(tmp.path(), "export_test");
        assert_eq!(sources.counters.len(), 1, "rediscovery is insertion-only");

        let mut enc = Encoder::new(1, 2);
        let mut dgrams = Vec::new();
        sources.encode_descriptors(&mut enc, 0, &mut |d| dgrams.push(d.to_vec()));
        sources.encode_bucket(&mut enc, 0, &mut |d| dgrams.push(d.to_vec()));

        let kinds: Vec<_> = dgrams.iter().map(|d| Header::parse(d).unwrap().kind).collect();
        assert_eq!(kinds, [Kind::Sources, Kind::SlotNames, Kind::CounterValues]);

        let names = &dgrams[1][HEADER_LEN + 8..];
        assert_eq!(names, b"\x06slot_0\x06slot_1", "unregistered schema: positional labels");
        let values = &dgrams[2][HEADER_LEN + 8..];
        assert_eq!(values[..8], 7u64.to_le_bytes());
        assert_eq!(values[8..], 9u64.to_le_bytes());
    }
}
