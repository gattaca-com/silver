//! The daemon's single tile: drains the node's `#[timed]` rings into rotating
//! fxt segments and, when a ClickHouse endpoint is configured, feeds the same
//! loop's spine envelopes to the block-events inserter. The daemon follows one
//! node for its whole life — it stops when that node exits, and the start
//! script brings up a fresh one alongside the next.

use std::{
    fs,
    fs::File,
    io,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

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

pub struct TraceCollector {
    reader: CrossProcessReader,
    dir: PathBuf,
    period: Nanos,
    segment_start: Nanos,
    retain_bytes: u64,
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

        if let Some(min) = args.filter_short_frames {
            reader.filter_short_frames(min);
        }

        let db_inserter = file_config
            .telemetry
            .clickhouse_url
            .map(|url| BlockEventsInserter::open(&url, &file_config.chain_config));

        // Floored at a second: `round_to_interval` divides by it.
        let period = Nanos::from_secs(args.period.as_secs().max(1));
        Ok(Self::new(reader, args.dir, period, args.retain.as_u64(), db_inserter, Nanos::now()))
    }

    fn new(
        reader: CrossProcessReader,
        dir: PathBuf,
        period: Nanos,
        retain_bytes: u64,
        db_inserter: Option<BlockEventsInserter>,
        now: Nanos,
    ) -> Self {
        let segment_start = now.round_to_interval(period);
        Self { reader, dir, period, segment_start, retain_bytes, db_inserter, polls: 0 }
    }

    fn next_cut(&self) -> Nanos {
        self.segment_start + self.period
    }

    /// Opens the interval we are now in, which a stalled loop can wake several
    /// boundaries past — never the one that just closed.
    fn dump_segment(&mut self) {
        self.write_segment();
        Self::prune(&self.dir, self.retain_bytes);
        self.segment_start = Nanos::now().round_to_interval(self.period);
    }

    /// Drops the oldest segments until the directory fits `retain_bytes`. The
    /// newest survives any budget: an over-budget cut keeps the spike it
    /// just recorded rather than trading it for the history.
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

    fn write_segment(&mut self) {
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
        let path = self.segment_path();
        match self.dump(&path) {
            Ok(file) => info!(
                path = %path.display(),
                bytes = file.metadata().map(|m| m.len()).unwrap_or(0),
                marks = retained,
                missed = loss.missed,
                dropped = loss.dropped,
                "wrote segment"
            ),
            Err(e) => warn!(
                path = %path.display(),
                %e,
                marks = retained,
                partial_removed = std::fs::remove_file(&path).is_ok(),
                "segment write failed; marks held for the next one"
            ),
        }
    }

    /// Stamped with the interval's start, so a `1h` segment named `14-00-00`
    /// holds the marks from 14:00 onwards.
    fn segment_path(&self) -> PathBuf {
        let stamp = self.segment_start.with_fmt_utc("%Y-%m-%d_%H-%M-%S");
        self.dir.join(format!("{APP_NAME}_{stamp}_pid{}{SEGMENT_SUFFIX}", self.reader.pid()))
    }

    fn dump(&mut self, path: &Path) -> io::Result<File> {
        let at = |step: &'static str| {
            move |e: io::Error| io::Error::new(e.kind(), format!("{step}: {e}"))
        };

        let file = File::create(path).map_err(at("create"))?;
        let mut encoder = GzEncoder::new(file, Compression::default());
        self.reader.dump_and_release(&mut encoder).map_err(at("dump"))?;
        encoder.finish().map_err(at("finish"))
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
        if Nanos::now() >= self.next_cut() {
            self.dump_segment();
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
        self.write_segment();
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use flux_profiler::{enable_profiler, test_shmem::ShmemGuard, timed};

    use super::*;

    #[timed]
    fn traced_work() {
        std::hint::black_box(0);
    }

    /// 999_997_200 unix seconds is 2001-09-09T01:00:00Z; the daemon starts
    /// 46m40s into that hour.
    const HOUR_START: u64 = 999_997_200;
    const STARTED_AT: u64 = HOUR_START + 2_800;

    fn collector(reader: CrossProcessReader, dir: PathBuf) -> TraceCollector {
        TraceCollector::new(
            reader,
            dir,
            Nanos::from_hours(1),
            u64::MAX,
            None,
            Nanos::from_secs(STARTED_AT),
        )
    }

    /// Prune sorts by mtime, so fixtures need distinct ones — set, not slept
    /// for; `hours_old` orders them and `bytes` is what the budget sees.
    fn backdate(path: &Path, bytes: usize, hours_old: u64) {
        std::fs::write(path, vec![0u8; bytes]).unwrap();
        let modified = SystemTime::now() - Duration::from_secs(hours_old * 3600);
        File::options().write(true).open(path).unwrap().set_modified(modified).unwrap();
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
    fn writes_a_segment_every_interval() {
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
        reader.poll();

        let dir = std::env::temp_dir().join(format!("segments-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut collector = collector(reader, dir.clone());

        let hour = Nanos::from_hours(1);
        assert_eq!(
            collector.segment_start,
            Nanos::from_secs(HOUR_START),
            "a mid-hour start rounds down to the hour it is in"
        );

        collector.write_segment();
        collector.reader.poll();
        collector.segment_start += hour;
        collector.write_segment();

        let pid = collector.reader.pid();
        assert_eq!(
            names(&dir),
            [
                format!("{APP_NAME}_2001-09-09_01-00-00_pid{pid}.fxt.gz"),
                format!("{APP_NAME}_2001-09-09_02-00-00_pid{pid}.fxt.gz"),
            ],
            "the idle second interval is a file too, named for its own start"
        );
        collector.dump_segment();
        let start = collector.segment_start;
        assert_eq!(start, start.round_to_interval(collector.period), "next segment on the grid");
        assert_eq!(collector.next_cut(), start + hour);

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
