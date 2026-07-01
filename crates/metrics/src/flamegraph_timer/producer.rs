use std::sync::OnceLock;

use flux::{communication::queue::Producer, timing::Instant};

#[cfg(feature = "alloc-profile")]
use crate::allocator::{self, AllocSample};
use crate::flamegraph_timer::{
    mark::{Frame, Mark},
    queue_dir::QueueDir,
};
#[cfg(feature = "perf")]
use crate::perf::{PerfSample, read};

thread_local! {
    static PRODUCERS: OnceLock<Producers> = const { OnceLock::new() };
}

struct Producers {
    marks: Producer<Mark>,
    #[cfg(feature = "perf")]
    perf: Producer<PerfSample>,
    #[cfg(feature = "alloc-profile")]
    alloc: Producer<AllocSample>,
}

impl Producers {
    fn for_current_thread() -> Self {
        let dir = QueueDir::open();
        let token = thread_token();
        Producers {
            marks: Producer::from(dir.ring::<Mark>(&token)),
            #[cfg(feature = "perf")]
            perf: Producer::from(dir.ring::<PerfSample>(&token)),
            #[cfg(feature = "alloc-profile")]
            alloc: Producer::from(dir.ring::<AllocSample>(&token)),
        }
    }

    fn push(&self, frame: Frame) {
        // `Producer` is `Copy`; the thread-local stores it behind a shared `&`,
        // so produce through a local copy of the cheap handle.
        let ts = Instant::now().0;
        let mut marks = self.marks;
        marks.produce(&Mark { frame, ts });
        #[cfg(feature = "perf")]
        {
            let mut perf = self.perf;
            perf.produce(&read().unwrap_or_default());
        }
        #[cfg(feature = "alloc-profile")]
        {
            let mut alloc = self.alloc;
            alloc.produce(&allocator::read());
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
pub(crate) fn record(frame: Frame) {
    PRODUCERS.with(|cell| cell.get_or_init(Producers::for_current_thread).push(frame));
}
