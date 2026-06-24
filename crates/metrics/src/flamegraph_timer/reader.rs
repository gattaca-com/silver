use std::{
    collections::{HashMap, hash_map::Entry},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use flux::communication::{
    ReadError,
    queue::{ConsumerBare, Queue},
};

use crate::flamegraph_timer::{
    builder::{Builder, CallStackTiming, Event, Mark},
    queue_dir::QueueDir,
};
#[cfg(feature = "perf")]
use crate::perf::PerfSample;

const EMPTY_MARK: Mark = Mark { name: Event::Close, ts: 0 };

static READER: Mutex<Option<Reader>> = Mutex::new(None);

pub fn enable() {
    crate::TIMING.set_harness();
    QueueDir::open().clear_stale();

    let mut reader = READER.lock().unwrap();
    if reader.is_none() {
        *reader = Some(Reader::spawn());
    }
}

/// Returns the folded timings and whether any ring lapped (marks lost, so the
/// timings are incomplete).
pub(super) fn drain() -> (Vec<CallStackTiming>, bool) {
    let Some(reader) = READER.lock().unwrap().take() else { return (Vec::new(), false) };

    let mut builder = Builder::default();
    let mut lapped = false;
    for stream in reader.stop_and_collect() {
        lapped |= stream.lapped;
        #[cfg(feature = "perf")]
        builder.fold_thread(&stream.marks, &stream.perf);
        #[cfg(not(feature = "perf"))]
        builder.fold_thread(&stream.marks, &[]);
    }
    (builder.finish(), lapped)
}

/// Background reader: spawned by [`enable`], it discovers per-thread rings and
/// drains them into heap until [`drain`] stops it and folds the result.
struct Reader {
    stop: Arc<AtomicBool>,
    handle: JoinHandle<Vec<ThreadStream>>,
}

impl Reader {
    fn spawn() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let handle = {
            let stop = stop.clone();
            thread::Builder::new()
                .name("flamegraph-reader".to_owned())
                .spawn(move || run(stop))
                .expect("spawn flamegraph reader")
        };
        Self { stop, handle }
    }

    fn stop_and_collect(self) -> Vec<ThreadStream> {
        self.stop.store(true, Ordering::Release);
        self.handle.join().unwrap_or_default()
    }
}

fn run(stop: Arc<AtomicBool>) -> Vec<ThreadStream> {
    let dir = QueueDir::open();
    let mut rings: HashMap<String, ThreadRings> = HashMap::new();
    loop {
        for token in dir.event_tokens() {
            if let Entry::Vacant(slot) = rings.entry(token) {
                if let Some(thread_rings) = ThreadRings::open(&dir, slot.key()) {
                    slot.insert(thread_rings);
                }
            }
        }
        for thread_rings in rings.values_mut() {
            thread_rings.poll();
        }
        // Poll once more after the stop is observed: producers have finished by
        // then, so this pass flushes their tails.
        if stop.load(Ordering::Acquire) {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    rings.into_values().map(ThreadRings::into_stream).collect()
}

/// A live consumer that drains one ring into a growing heap `Vec`. Polled
/// repeatedly by the reader; survivors of the run are folded at `drain`.
struct RingStream<T: Copy> {
    consumer: ConsumerBare<T>,
    out: Vec<T>,
    scratch: T,
    /// Set once the ring wrapped before we drained it — marks were lost, so the
    /// fold built from `out` is incomplete.
    lapped: bool,
}

impl<T: Copy> RingStream<T> {
    fn open(path: &Path, scratch: T, label: &'static str) -> Option<Self> {
        let queue = Queue::<T>::try_open_shared(path).ok()?;
        let mut consumer = ConsumerBare::new(queue, label);
        consumer.try_init_collaborative();
        Some(Self { consumer, out: Vec::new(), scratch, lapped: false })
    }

    fn poll(&mut self) {
        loop {
            match self.consumer.try_consume(&mut self.scratch) {
                Ok(()) => self.out.push(self.scratch),
                Err(ReadError::Empty) => break,
                // The ring wrapped before we drained it: resync past the gap and
                // flag the loss so the perf gate fails instead of measuring a
                // truncated stream. Raise RING_CAPACITY if it recurs.
                Err(ReadError::SpedPast) => {
                    self.consumer.recover_after_error();
                    self.lapped = true;
                }
            }
        }
    }
}

/// One producing thread's marks and (with `perf`) counter samples, read in
/// lockstep so `Builder::fold_thread` can pair them by index.
struct ThreadRings {
    marks: RingStream<Mark>,
    #[cfg(feature = "perf")]
    perf: RingStream<PerfSample>,
}

impl ThreadRings {
    fn open(dir: &QueueDir, token: &str) -> Option<Self> {
        let marks = RingStream::open(&dir.path("events", token), EMPTY_MARK, fresh_label())?;
        #[cfg(feature = "perf")]
        let perf = RingStream::open(
            &dir.path("perf-events", token),
            PerfSample::default(),
            fresh_label(),
        )?;
        Some(Self {
            marks,
            #[cfg(feature = "perf")]
            perf,
        })
    }

    fn poll(&mut self) {
        self.marks.poll();
        #[cfg(feature = "perf")]
        self.perf.poll();
    }

    fn into_stream(self) -> ThreadStream {
        #[cfg(feature = "perf")]
        let lapped = self.marks.lapped || self.perf.lapped;
        #[cfg(not(feature = "perf"))]
        let lapped = self.marks.lapped;
        ThreadStream {
            marks: self.marks.out,
            #[cfg(feature = "perf")]
            perf: self.perf.out,
            lapped,
        }
    }
}

/// A finished thread's accumulated marks (and counter samples) — plain data the
/// reader hands back to be folded, leaving the live consumers behind.
struct ThreadStream {
    marks: Vec<Mark>,
    #[cfg(feature = "perf")]
    perf: Vec<PerfSample>,
    lapped: bool,
}

fn fresh_label() -> &'static str {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    Box::leak(format!("flamegraph-stream-{}", NEXT.fetch_add(1, Ordering::Relaxed)).into())
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;
    use crate::flamegraph_timer::{Event, record};

    fn marks(timings: &[CallStackTiming], leaf: &str) -> u64 {
        timings
            .iter()
            .filter(|t| t.call_stack.last().is_some_and(|n| n.ends_with(leaf)))
            .map(|t| t.samples.tracked_ns.len() as u64)
            .sum()
    }

    #[test]
    fn drain_discovers_every_thread_ring() {
        let _guard = crate::test_shmem::ShmemGuard::new();
        enable();

        let spawn = |tag: &'static str, reps: usize| {
            thread::Builder::new()
                .name(format!("drainer-{tag}"))
                .spawn(move || {
                    for _ in 0..reps {
                        record(Event::Open("outer"));
                        record(Event::Open("inner"));
                        record(Event::Close);
                        record(Event::Close);
                    }
                })
                .unwrap()
        };

        spawn("a", 3).join().unwrap();
        spawn("b", 5).join().unwrap();

        let (timings, lapped) = drain();
        assert!(!lapped, "test rings are larger than the few marks produced");
        assert_eq!(marks(&timings, "outer"), 8, "both threads' outer frames");
        assert_eq!(marks(&timings, "inner"), 8, "both threads' inner frames");
    }
}
