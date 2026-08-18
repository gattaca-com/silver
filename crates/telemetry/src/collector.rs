//! The daemon's single tile: drains the node's `#[timed]` rings into rotating
//! fxt segments and, when a ClickHouse endpoint is configured, feeds the same
//! loop's spine envelopes to the block-events inserter. The daemon follows one
//! node for its whole life — it stops when that node exits, and the start
//! script brings up a fresh one alongside the next.

use std::{
    fs, io,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use bytesize::ByteSize;
use flate2::{Compression, write::GzEncoder};
use flux::{spine::SpineAdapter, tile::Tile};
use flux_profiler::{CrossProcessReader, Loss, published_pid};
use silver_common::{APP_NAME, Nanos, SilverSpine};
use tracing::{info, warn};

use crate::{block_events::BlockEventsInserter, config::Args};

/// Loop iterations between the pid-file reads that detect the node's exit;
/// ~1 s at the tile's loop pacing.
const PID_CHECK_EVERY: u32 = 100;

/// Also what `prune` treats as ours, so a shared directory keeps the rest.
/// Gzip and not a denser codec because it is the only compression Perfetto
/// unwraps before sniffing the trace format.
const SEGMENT_SUFFIX: &str = ".fxt.gz";

const ATTACH_POLL: Duration = Duration::from_millis(100);

/// How often completed frames are appended to the current segment. Each append
/// restates that segment's string table, so a much shorter one pays more in
/// preamble than it carries in events.
const DUMP_INTERVAL: Nanos = Nanos::from_secs(30);

/// Retained marks past this append ahead of the interval — a ceiling on the
/// daemon's own memory, not a tuning knob.
const MAX_BUFFERED: u64 = ByteSize::gib(2).as_u64();

pub struct TraceCollector {
    reader: CrossProcessReader,
    dir: PathBuf,
    period: Nanos,
    retain_bytes: u64,
    next_dump: Nanos,
    db_inserter: Option<BlockEventsInserter>,
    polls: u32,
}

impl TraceCollector {
    pub fn attach_to_node(args: Args) -> Result<Self, String> {
        let file_config = args.file_config()?;
        fs::create_dir_all(&args.dir).map_err(|e| format!("{}: {e}", args.dir.display()))?;

        // Block events are only consumed once the tile is up, so this wait is
        // the window in which a starting node's first ones go unseen.
        info!("waiting for the node's rings");
        let mut reader = loop {
            if let Some(reader) = CrossProcessReader::attach(APP_NAME) {
                break reader;
            }
            thread::sleep(ATTACH_POLL);
        };
        info!(pid = reader.pid(), "attached");

        reader.filter_short_frames(args.filter_short_frames);

        let telemetry = &file_config.telemetry;
        let db_inserter = telemetry.clickhouse_url.as_deref().map(|url| {
            BlockEventsInserter::open(url, telemetry.network.as_deref(), &file_config.chain_config)
        });

        // Floored at a second: `round_to_interval` divides by the period.
        let period = Nanos::from_secs(args.period.as_secs().max(1));
        Ok(Self::new(reader, args.dir, period, args.retain.as_u64(), db_inserter))
    }

    fn new(
        reader: CrossProcessReader,
        dir: PathBuf,
        period: Nanos,
        retain_bytes: u64,
        db_inserter: Option<BlockEventsInserter>,
    ) -> Self {
        Self { reader, dir, period, retain_bytes, next_dump: Nanos::now(), db_inserter, polls: 0 }
    }

    fn buffered_over_budget(&self) -> bool {
        self.reader.events().retained_bytes() as u64 > MAX_BUFFERED
    }

    /// Drops the oldest segments until the directory fits `retain_bytes`. The
    /// newest survives any budget: the segment being appended to keeps the
    /// spike it is recording rather than trading it for the history.
    fn prune(dir: &Path, retain_bytes: u64) {
        let mut segments: Vec<_> = fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(SEGMENT_SUFFIX))
            .filter_map(|e| {
                let meta = e.metadata().ok()?;
                Some((meta.modified().ok()?, e.path(), meta.len()))
            })
            .collect();
        segments.sort_unstable();

        let mut total: u64 = segments.iter().map(|(_, _, bytes)| bytes).sum();
        for (_, path, bytes) in &segments[..segments.len().saturating_sub(1)] {
            if total <= retain_bytes {
                return;
            }
            match fs::remove_file(path) {
                Ok(()) => {
                    total -= bytes;
                    info!(path = %path.display(), bytes, "pruned segment");
                }
                Err(e) => warn!(path = %path.display(), %e, "prune failed"),
            }
        }
    }

    fn append(&mut self, now: Nanos) {
        let mut loss = Loss::default();
        let mut retained = 0;
        for thread in self.reader.events().threads() {
            retained += thread.marks.len();
            loss.missed += thread.loss.missed;
            loss.dropped += thread.loss.dropped;

            if thread.loss.is_lossy() {
                info!(
                    thread = thread.name,
                    retained = thread.marks.len(),
                    missed = thread.loss.missed,
                    dropped = thread.loss.dropped,
                    "lossy ring"
                );
            }
        }
        let path = self.segment_path(now);
        match self.dump(&path) {
            Ok(bytes) => info!(
                path = %path.display(),
                bytes,
                marks = retained,
                missed = loss.missed,
                dropped = loss.dropped,
                "appended to segment"
            ),
            Err(e) => warn!(
                path = %path.display(),
                %e,
                marks = retained,
                "append failed; marks held for the next one"
            ),
        }
        Self::prune(&self.dir, self.retain_bytes);
    }

    /// Rotation is nothing but this name changing, so marks within one append
    /// interval of a boundary land in whichever file the append falls in.
    fn segment_path(&self, now: Nanos) -> PathBuf {
        let stamp = now.round_to_interval(self.period).with_fmt_utc("%Y-%m-%d_%H-%M-%S");
        self.dir.join(format!("{APP_NAME}_{stamp}_pid{}{SEGMENT_SUFFIX}", self.reader.pid()))
    }

    /// One gzip member per append, finalised in place, so the segment is a
    /// complete `.gz` at every point between appends. Level 1 because this runs
    /// on the drain loop and every second spent is a second of ring overrun:
    /// 8x faster than level 6 for ~18% more bytes.
    fn dump(&mut self, path: &Path) -> io::Result<u64> {
        let at = |step: &'static str| {
            move |e: io::Error| io::Error::new(e.kind(), format!("{step}: {e}"))
        };

        let file =
            fs::OpenOptions::new().create(true).append(true).open(path).map_err(at("open"))?;
        let mut encoder = GzEncoder::new(file, Compression::new(1));
        self.reader.dump_and_release(&mut encoder).map_err(at("dump"))?;
        let file = encoder.finish().map_err(at("finish"))?;
        file.metadata().map(|m| m.len()).map_err(at("size"))
    }

    /// A restarted node publishes a new pid, so a mismatch means the node we
    /// attached to is gone.
    fn producer_exited(&self) -> bool {
        published_pid(APP_NAME) != Some(self.reader.pid())
    }
}

impl Tile<SilverSpine> for TraceCollector {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        if let Some(inserter) = &mut self.db_inserter {
            inserter.sample(adapter);
        }

        while self.reader.poll() {}
        let now = Nanos::now();
        if now >= self.next_dump || self.buffered_over_budget() {
            self.append(now);
            self.next_dump = now + DUMP_INTERVAL;
        }

        self.polls += 1;
        if self.polls.is_multiple_of(PID_CHECK_EVERY) && self.producer_exited() {
            info!(pid = self.reader.pid(), "producer exited");
            adapter.request_stop_scope();
        }

        // Draining the rings is invisible to the adapter, and under `flux/park`
        // an idle-looking loop in a single-tile process parks with nobody left
        // to signal it.
        adapter.mark_work();
    }

    fn teardown(mut self, _adapter: &mut SpineAdapter<SilverSpine>) {
        self.append(Nanos::now());
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Read, time::SystemTime};

    use flate2::read::MultiGzDecoder;
    use flux_profiler::{enable_profiler, test_shmem::ShmemGuard, timed};

    use super::*;

    const MAGIC: &[u8] = b"\x10\x00\x04FxT\x16\x00";

    #[timed]
    fn traced_work() {
        std::hint::black_box(0);
    }

    /// 999_997_200 unix seconds is 2001-09-09T01:00:00Z; the daemon starts
    /// 46m40s into that hour.
    const HOUR_START: u64 = 999_997_200;
    const STARTED_AT: u64 = HOUR_START + 2_800;

    fn collector(reader: CrossProcessReader, dir: PathBuf) -> TraceCollector {
        TraceCollector::new(reader, dir, Nanos::from_hours(1), u64::MAX, None)
    }

    /// Prune sorts by mtime, so fixtures need distinct ones — set, not slept
    /// for; `hours_old` orders them and `bytes` is what the budget sees.
    fn backdate(path: &Path, bytes: usize, hours_old: u64) {
        std::fs::write(path, vec![0u8; bytes]).unwrap();
        let modified = SystemTime::now() - Duration::from_secs(hours_old * 3600);
        std::fs::File::options().write(true).open(path).unwrap().set_modified(modified).unwrap();
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn the_clock_alone_decides_which_segment_an_append_lands_in() {
        let guard = ShmemGuard::new();
        enable_profiler(guard.app());

        std::thread::Builder::new()
            .name("segment-producer".to_owned())
            .spawn(|| {
                for _ in 0..4 {
                    traced_work();
                }
            })
            .unwrap()
            .join()
            .unwrap();

        let mut reader = CrossProcessReader::attach(guard.app()).expect("pid published");
        while reader.poll() {}

        let dir = std::env::temp_dir().join(format!("segments-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut collector = collector(reader, dir.clone());

        let started_at = Nanos::from_secs(STARTED_AT);
        collector.append(started_at);
        collector.append(started_at + Nanos::from_secs(60));
        collector.append(Nanos::from_secs(HOUR_START) + Nanos::from_hours(1));

        let pid = collector.reader.pid();
        assert_eq!(
            names(&dir),
            [
                format!("{APP_NAME}_2001-09-09_01-00-00_pid{pid}.fxt.gz"),
                format!("{APP_NAME}_2001-09-09_02-00-00_pid{pid}.fxt.gz"),
            ],
            "both mid-hour appends share 01-00-00; the one an hour on opens 02-00-00"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn appends_share_one_segment_and_stay_readable() {
        let guard = ShmemGuard::new();
        enable_profiler(guard.app());

        let mut reader = CrossProcessReader::attach(guard.app()).expect("pid published");
        let dir = std::env::temp_dir().join(format!("appends-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        traced_work();
        while reader.poll() {}
        let mut collector = collector(reader, dir.clone());

        let at = Nanos::from_secs(STARTED_AT);
        collector.append(at);
        let path = collector.segment_path(at);
        let after_first = std::fs::metadata(&path).unwrap().len();

        traced_work();
        while collector.reader.poll() {}
        collector.append(at);
        assert_eq!(names(&dir).len(), 1, "both appends went to the interval's own file");
        assert!(
            std::fs::metadata(&path).unwrap().len() > after_first,
            "the second append extended the file"
        );

        let mut trace = Vec::new();
        MultiGzDecoder::new(std::fs::File::open(&path).unwrap())
            .read_to_end(&mut trace)
            .expect("every member is finalised, so the whole file decodes");
        assert_eq!(
            trace.windows(MAGIC.len()).filter(|w| *w == MAGIC).count(),
            2,
            "one self-contained trace per append"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn segment(hour: u64) -> String {
        format!("{APP_NAME}_2001-09-09_0{hour}-00-00_pid7.fxt.gz")
    }

    /// Three equal segments, oldest first, and an older file that is not ours:
    /// counting or dropping `notes.txt` changes what the budget leaves behind.
    fn segment_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        backdate(&dir.join("notes.txt"), 100, 5);
        for hour in 1..=3 {
            backdate(&dir.join(segment(hour)), 100, 4 - hour);
        }
        dir
    }

    #[test]
    fn prunes_oldest_first_to_the_budget() {
        let dir = segment_dir("prune-budget");

        TraceCollector::prune(&dir, 250);

        assert_eq!(
            names(&dir),
            ["notes.txt".to_owned(), segment(2), segment(3)],
            "300 bytes against a 250 budget drops the oldest, then stops once it fits"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn keeps_the_newest_and_what_is_not_ours() {
        let dir = segment_dir("prune-floor");

        TraceCollector::prune(&dir, 0);

        assert_eq!(
            names(&dir),
            ["notes.txt".to_owned(), segment(3)],
            "a budget under one segment still keeps the last cut"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
