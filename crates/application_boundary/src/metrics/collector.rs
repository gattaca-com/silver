use std::{
    collections::HashSet,
    fs::{self, ReadDir},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use flux::{
    communication::{queue::Consumer, timer::TimingMessage},
    tile::metrics::TileSample,
    timing::Nanos,
};
use silver_log::counts::LogName;
use silver_observe::{
    CounterFile, CounterMap, SlotKind, SourceKind, consume_elapsed, consume_sample, sample_reader,
    slot_kind, slot_name,
};

use super::exposition::{
    BUILD_INFO, CURRENT_VALUE, EVENTS, Histogram, RAW_SLOT, Snapshot, TCACHE_CAPACITY, TCACHE_HEAD,
    TCACHE_TAIL, TILE_BUSY, TILE_BUSY_MAX, TILE_ITERATIONS, TILE_OBSERVED, TILE_UTILISATION,
    escape,
};

const BATCH: usize = 32;
const RENDER_SLOTS: usize = 8;
const TCACHE_NAME_BYTES: usize = 32;

#[derive(Default)]
struct TileTotals {
    busy: u64,
    total: u64,
    count: u64,
    max: u64,
}

impl TileTotals {
    fn record(&mut self, s: &TileSample) {
        self.busy += s.busy_ticks;
        self.total += s.total_ticks();
        self.count += u64::from(s.busy_count);
        self.max = self.max.max(s.busy_max);
    }
}

enum Samples {
    Timer(Consumer<TimingMessage>, Histogram),
    Tile(Consumer<TileSample>, TileTotals, TileTotals),
}

struct QueueSource {
    labels: String,
    samples: Samples,
}

impl QueueSource {
    fn drain_batch(&mut self) -> bool {
        for _ in 0..BATCH {
            let read = match &mut self.samples {
                Samples::Timer(reader, hist) => {
                    consume_elapsed(reader, |elapsed| hist.record(Nanos::from(elapsed).0))
                }
                Samples::Tile(reader, total, window) => consume_sample(reader, |s| {
                    total.record(s);
                    window.record(s);
                }),
            };
            if !read {
                return false;
            }
        }
        true
    }

    fn encode(&mut self, text: &mut Snapshot) {
        let labels = &self.labels;
        match &mut self.samples {
            Samples::Timer(_, hist) => hist.encode(text, labels),
            Samples::Tile(_, total, window) => {
                text.sample(&TILE_BUSY, labels, total.busy as f64 / 1e9);
                text.sample(&TILE_OBSERVED, labels, total.total as f64 / 1e9);
                text.sample(&TILE_ITERATIONS, labels, total.count);
                text.sample(
                    &TILE_UTILISATION,
                    labels,
                    window.busy as f64 / window.total.max(1) as f64,
                );
                text.sample(&TILE_BUSY_MAX, labels, window.max as f64 / 1e9);
                *window = TileTotals::default();
            }
        }
    }
}

struct Counters {
    tcache: bool,
    group: String,
    map: CounterMap,
    labels: Vec<String>,
}

impl Counters {
    /// Consumer and log-site names are fixed by discovery time, so every
    /// slot's labels are built here once.
    fn open(file: CounterFile, dir: &Path) -> Option<Self> {
        let map = CounterMap::open(&file).ok()?;
        let slots = 0..map.slot_count();
        let labels = match file.name.strip_prefix("tcache-") {
            Some(cache) => {
                let names = fs::read(dir.join(format!("tcache-names-{cache}"))).unwrap_or_default();
                let cache = escape(cache);
                slots
                    .map(|slot| match slot.checked_sub(2) {
                        None => format!("cache=\"{cache}\""),
                        Some(tail) => {
                            let name =
                                names.chunks(TCACHE_NAME_BYTES).nth(tail).unwrap_or_default();
                            let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
                            let consumer = escape(&String::from_utf8_lossy(&name[..end]));
                            format!("cache=\"{cache}\",slot=\"{tail}\",consumer=\"{consumer}\"")
                        }
                    })
                    .collect()
            }
            None => {
                let log_names = match file.name.as_str() {
                    "log" => LogName::read(&dir.join("log-names")).ok()?,
                    _ => Vec::new(),
                };
                let source = escape(&file.name);
                slots
                    .map(|slot| {
                        let name = match log_names.get(slot) {
                            Some(LogName { level, file, line, .. }) => {
                                format!("{level} {file}:{line}")
                            }
                            None => slot_name(&file.name, slot),
                        };
                        format!("source=\"{source}\",slot=\"{slot}\",name=\"{}\"", escape(&name))
                    })
                    .collect()
            }
        };
        Some(Self { tcache: file.name.starts_with("tcache-"), group: file.name, map, labels })
    }

    fn encode(&self, slot: usize, text: &mut Snapshot) {
        let value = self.map.load(slot);
        let family = if self.tcache {
            match slot {
                0 => &TCACHE_CAPACITY,
                1 => &TCACHE_HEAD,
                _ if value == u64::MAX => return,
                _ => &TCACHE_TAIL,
            }
        } else {
            match slot_kind(&self.group, slot) {
                SlotKind::Counter => &EVENTS,
                SlotKind::Gauge => &CURRENT_VALUE,
                SlotKind::Untyped => &RAW_SLOT,
            }
        };
        text.sample(family, &self.labels[slot], value);
    }
}

struct Render {
    text: Arc<Snapshot>,
    source: usize,
    slot: usize,
    queue: usize,
}

pub(super) struct Collector {
    dir: PathBuf,
    scanned_epoch: Option<u64>,
    entries: Option<ReadDir>,
    opened: HashSet<String>,
    counters: Vec<Counters>,
    queues: Vec<QueueSource>,
    build_labels: Option<String>,
    drain: usize,
    next_snapshot: Instant,
    next_drain: Instant,
    queues_left: usize,
    queue_backlog: bool,
    render: Option<Render>,
    /// The previous snapshot; rendered into again once no scrape holds it.
    spare: Option<Arc<Snapshot>>,
    pub snapshot: Option<Arc<Snapshot>>,
}

impl Collector {
    pub fn new(dir: PathBuf) -> Self {
        let now = Instant::now();
        Self {
            dir,
            scanned_epoch: None,
            entries: None,
            opened: HashSet::new(),
            counters: vec![],
            queues: vec![],
            build_labels: None,
            drain: 0,
            queues_left: 0,
            queue_backlog: false,
            next_snapshot: now,
            next_drain: now,
            render: None,
            spare: None,
            snapshot: None,
        }
    }

    /// Tiles create some sources lazily, so the directory is read again once
    /// per epoch and only new sources are opened.
    pub fn discover(&mut self, epoch: u64) {
        if self.scanned_epoch != Some(epoch) && self.entries.is_none() {
            self.scanned_epoch = Some(epoch);
            self.entries = fs::read_dir(&self.dir).ok();
        }
    }

    fn open(&mut self, kind: SourceKind, name: &str, path: &Path) -> Option<()> {
        let labels = format!("source=\"{}\"", escape(name));
        match kind {
            SourceKind::Build => {
                let build = fs::read_to_string(path).ok()?;
                let mut fields = build.trim().splitn(3, " · ");
                let mut field = || escape(fields.next().unwrap_or(""));
                let (commit, version, timestamp) = (field(), field(), field());
                self.build_labels = Some(format!(
                    "commit=\"{commit}\",version=\"{version}\",timestamp=\"{timestamp}\""
                ));
            }
            SourceKind::Counters => {
                let file = CounterFile { name: name.to_owned(), path: path.to_owned() };
                self.counters.push(Counters::open(file, &self.dir)?);
            }
            SourceKind::Latency | SourceKind::Processing => {
                let channel = if kind == SourceKind::Latency { "latency" } else { "processing" };
                let reader = sample_reader(path, "prometheus").ok()?;
                self.queues.push(QueueSource {
                    labels: format!("{labels},channel=\"{channel}\""),
                    samples: Samples::Timer(reader, Histogram::default()),
                });
            }
            SourceKind::Tile => self.queues.push(QueueSource {
                labels: format!("tile=\"{}\"", escape(name)),
                samples: Samples::Tile(
                    sample_reader(path, "prometheus").ok()?,
                    TileTotals::default(),
                    TileTotals::default(),
                ),
            }),
        }
        Some(())
    }

    fn discover_one(&mut self) {
        let Some(entry) = self.entries.as_mut().and_then(Iterator::next) else {
            self.entries = None;
            return
        };
        let Ok(entry) = entry else { return };
        let Ok(file) = entry.file_name().into_string() else { return };
        if self.opened.contains(&file) {
            return;
        }
        if let Some((kind, name)) = SourceKind::parse(&file) &&
            self.open(kind, name, &entry.path()).is_some()
        {
            self.opened.insert(file);
        }
    }

    fn begin_render(&mut self) -> Render {
        let mut text = self.spare.take().filter(|s| Arc::strong_count(s) == 1).unwrap_or_default();
        Arc::get_mut(&mut text).expect("spare snapshot unshared").clear();
        Render { text, source: 0, slot: 0, queue: 0 }
    }

    fn render_batch(&mut self) {
        let Some(render) = &mut self.render else { return };
        let text = Arc::get_mut(&mut render.text).expect("snapshot unpublished while rendering");
        if let Some(c) = self.counters.get(render.source) {
            let end = (render.slot + RENDER_SLOTS).min(c.map.slot_count());
            for i in render.slot..end {
                c.encode(i, text);
            }
            render.slot = end;
            if end == c.map.slot_count() {
                render.source += 1;
                render.slot = 0;
            }
        } else if let Some(q) = self.queues.get_mut(render.queue) {
            q.encode(text);
            render.queue += 1;
        } else {
            if let Some(labels) = &self.build_labels {
                text.sample(&BUILD_INFO, labels, 1);
            }
            text.finish();
            let text = self.render.take().expect("rendering").text;
            self.spare = self.snapshot.replace(text);
        }
    }

    pub fn pump(&mut self, now: Instant, deadline: Instant) -> bool {
        if now >= self.next_snapshot && self.render.is_none() && self.entries.is_none() {
            self.render = Some(self.begin_render());
            self.next_snapshot = now + Duration::from_secs(1);
        }
        if self.queues_left == 0 && now >= self.next_drain {
            self.queues_left = self.queues.len();
            self.queue_backlog = false;
            self.next_drain = now + Duration::from_millis(1);
        }
        while self.entries.is_some() || self.render.is_some() || self.queues_left > 0 {
            if self.entries.is_some() {
                self.discover_one();
            }
            if self.queues_left > 0 {
                self.queue_backlog |= self.queues[self.drain].drain_batch();
                self.drain = (self.drain + 1) % self.queues.len();
                self.queues_left -= 1;
                if self.queues_left == 0 && self.queue_backlog {
                    self.next_drain = now;
                }
            }
            self.render_batch();
            if Instant::now() >= deadline {
                break;
            }
        }
        self.entries.is_some() ||
            self.render.is_some() ||
            self.queues_left > 0 ||
            self.next_drain <= now
    }
}
