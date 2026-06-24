use std::sync::OnceLock;

use flux::{communication::queue::Producer, timing::Instant};

use crate::flamegraph_timer::{
    builder::{Event, Mark},
    queue_dir::QueueDir,
};
#[cfg(feature = "perf")]
use crate::perf::PerfSample;
#[cfg(feature = "perf")]
use crate::perf::read;

thread_local! {
    static PRODUCERS: OnceLock<Producers> = const { OnceLock::new() };
}

struct Producers {
    marks: Producer<Mark>,
    #[cfg(feature = "perf")]
    perf: Producer<PerfSample>,
}

impl Producers {
    fn for_current_thread() -> Self {
        let dir = QueueDir::open();
        let token = thread_token();
        Producers {
            marks: Producer::from(dir.ring::<Mark>("events", &token)),
            #[cfg(feature = "perf")]
            perf: Producer::from(dir.ring::<PerfSample>("perf-events", &token)),
        }
    }

    fn push(&self, event: Event) {
        // `Producer` is `Copy`; the thread-local stores it behind a shared `&`,
        // so produce through a local copy of the cheap handle.
        let ts = Instant::now().0;
        let mut marks = self.marks;
        marks.produce(&Mark { name: event, ts });
        #[cfg(feature = "perf")]
        {
            let mut perf = self.perf;
            perf.produce(&read().unwrap_or_default());
        }
    }
}

fn thread_token() -> String {
    let thread = std::thread::current();
    match thread.name() {
        Some(name) => name.to_owned(),
        None => format!("{:?}", thread.id()),
    }
}

#[inline]
pub(crate) fn record(event: Event) {
    if !crate::TIMING.is_harness() {
        return;
    }
    PRODUCERS.with(|cell| cell.get_or_init(Producers::for_current_thread).push(event));
}
