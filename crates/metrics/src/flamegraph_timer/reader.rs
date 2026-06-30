use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::{
    Schema,
    flamegraph_timer::{
        drainer::EventsDrainer,
        queue_dir::{QueueDir, enable_surfer},
        report::TimingStats,
        symbols::{InProcessSymbolsResolver, RemoteSymbolsResolver},
    },
};

/// Reads a *running* silver's `#[timed]` marks from its shmem rings and folds
/// them into a call tree on demand. The producer is a different process, so
/// names are read from its on-disk binary rather than dereferenced.
///
/// Polling is cumulative — every mark since attach is retained — so the fold
/// covers the whole run, and memory grows with the marks produced.
pub struct FlamegraphReader {
    drainer: EventsDrainer,
    resolver: RemoteSymbolsResolver,
    pid: u32,
}

impl FlamegraphReader {
    /// The pid of the *live* producer under `app`, or `None` if none has
    /// produced yet or the last one exited. Its change across calls signals a
    /// restart, so a consumer can re-[`attach`](Self::attach).
    pub fn published_pid(app: &str) -> Option<u32> {
        QueueDir::open_app(app).live_pid()
    }

    /// Attaches to the live silver registered under `app`, or `None` if none is
    /// running.
    pub fn attach(app: &str) -> Option<Self> {
        let dir = QueueDir::open_app(app);
        let pid = dir.live_pid()?;
        let schema = dir.perf_schema().unwrap_or_else(Schema::empty);
        Some(Self {
            drainer: EventsDrainer::new(dir, schema),
            resolver: RemoteSymbolsResolver::new(pid),
            pid,
        })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn poll(&mut self) {
        self.drainer.poll(&self.resolver);
    }

    pub fn stats(&self) -> TimingStats {
        self.drainer.fold()
    }

    pub fn export_trace(&self) -> Vec<u8> {
        self.drainer.fxt_trace()
    }
}

/// The perf harness's in-process reader: enables `#[timed]` production and
/// drains every thread's ring on a background thread until
/// [`collect`](Self::collect) stops it and folds the whole run.
pub struct LocalReader {
    stop: Arc<AtomicBool>,
    handle: JoinHandle<EventsDrainer>,
}

impl LocalReader {
    pub fn start() -> Self {
        enable_surfer();
        let stop = Arc::new(AtomicBool::new(false));
        let handle = {
            let stop = stop.clone();
            thread::Builder::new()
                .name("flamegraph-reader".to_owned())
                .spawn(move || Self::run(stop))
                .expect("spawn flamegraph reader")
        };
        Self { stop, handle }
    }

    /// Stop the background reader and fold the whole run into stats.
    pub fn collect(self) -> TimingStats {
        self.stop.store(true, Ordering::Release);
        let drainer = self
            .handle
            .join()
            .unwrap_or_else(|_| EventsDrainer::new(QueueDir::open(), Schema::local().clone()));
        drainer.fold()
    }

    fn run(stop: Arc<AtomicBool>) -> EventsDrainer {
        // Boots with the producer, so it reads the whole run from slot 0 and any
        // loss is a genuine overrun, not a pre-attach gap.
        let mut drainer = EventsDrainer::new(QueueDir::open(), Schema::local().clone());
        loop {
            drainer.poll(&InProcessSymbolsResolver);
            // Poll once more after stop is observed: producers have finished by
            // then, so this pass flushes their tails.
            if stop.load(Ordering::Acquire) {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        drainer
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;
    use crate::flamegraph_timer::{Frame, record};

    #[test]
    fn drain_discovers_every_thread_ring() {
        let _guard = crate::test_shmem::ShmemGuard::new();
        let reader = LocalReader::start();

        let spawn = |tag: &'static str, reps: usize| {
            thread::Builder::new()
                .name(format!("drainer-{tag}"))
                .spawn(move || {
                    let (outer, inner) = ("outer", "inner");
                    for _ in 0..reps {
                        record(Frame::open(outer));
                        record(Frame::open(inner));
                        record(Frame::close(inner));
                        record(Frame::close(outer));
                    }
                })
                .unwrap()
        };

        spawn("a", 3).join().unwrap();
        spawn("b", 5).join().unwrap();

        let stats = reader.collect();
        assert!(!stats.missed_events(), "test rings are larger than the few marks produced");
        assert_eq!(stats.aggregate_leaf("outer").1, 8, "both threads' outer frames");
        assert_eq!(stats.aggregate_leaf("inner").1, 8, "both threads' inner frames");
    }

    /// The surfer path: produce marks, then fold them through
    /// [`FlamegraphReader`], which resolves names from the producer's on-disk
    /// binary (here our own process) rather than by dereferencing the id.
    #[test]
    fn flamegraph_reader_resolves_names_cross_process() {
        let _guard = crate::test_shmem::ShmemGuard::new();
        enable_surfer();

        thread::Builder::new()
            .name("surfer-producer".to_owned())
            .spawn(|| {
                let (alpha, beta) = ("alpha", "beta");
                for _ in 0..4 {
                    record(Frame::open(alpha));
                    record(Frame::open(beta));
                    record(Frame::close(beta));
                    record(Frame::close(alpha));
                }
            })
            .unwrap()
            .join()
            .unwrap();

        let mut reader = FlamegraphReader::attach(crate::TIMING.app()).expect("pid published");
        reader.poll();
        let stats = reader.stats();

        assert!(!stats.missed_events());
        assert_eq!(stats.aggregate_leaf("alpha").1, 4, "name resolved from on-disk binary");
        assert_eq!(stats.aggregate_leaf("beta").1, 4);

        // The producer is gone; re-polling the now-static ring must not invent
        // marks, so the cumulative fold stays put (no perpetual churn at idle).
        reader.poll();
        reader.poll();
        let again = reader.stats();
        assert_eq!(again.aggregate_leaf("alpha").1, 4, "re-poll of a static ring changed the fold");
        assert_eq!(again.aggregate_leaf("beta").1, 4);
    }

    #[test]
    fn exports_fxt_trace() {
        let _guard = crate::test_shmem::ShmemGuard::new();
        enable_surfer();

        thread::Builder::new()
            .name("trace-producer".to_owned())
            .spawn(|| {
                let (outer, inner) = ("outer", "inner");
                record(Frame::open(outer));
                record(Frame::open(inner));
                record(Frame::close(inner));
                record(Frame::close(outer));
            })
            .unwrap()
            .join()
            .unwrap();

        let mut reader = FlamegraphReader::attach(crate::TIMING.app()).expect("pid published");
        reader.poll();

        let trace = reader.export_trace();
        assert_eq!(&trace[..8], b"\x10\x00\x04FxT\x16\x00", "FXT magic record");
        assert!(contains(&trace, b"trace-producer"), "track named after the thread");
        assert!(contains(&trace, b"outer") && contains(&trace, b"inner"), "frame names present");
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
