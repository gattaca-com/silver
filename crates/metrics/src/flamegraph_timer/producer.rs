use std::sync::OnceLock;

use flux::communication::queue::Producer;

#[cfg(feature = "alloc-profile")]
use crate::allocator::{self, AllocSample};
use crate::flamegraph_timer::{mark::Mark, queue_dir::QueueDir};
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

    fn push(&self, mark: Mark) {
        // `QueueDir::ring` unlinks any leftover backing before creating, so no
        // slot can hold a crashed writer's poison and `produce_first`'s
        // unpoison pass (which `Producer::produce` would re-run on every call
        // here, as the thread-local only hands out `&self`) is unnecessary.
        self.marks.produce_without_first(&mark);
        #[cfg(feature = "perf")]
        self.perf.produce_without_first(&read().unwrap_or_default());
        #[cfg(feature = "alloc-profile")]
        self.alloc.produce_without_first(&allocator::read());
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
pub(crate) fn record_open(name: &'static str) {
    PRODUCERS.with(|cell| cell.get_or_init(Producers::for_current_thread).push(Mark::open(name)));
}

#[inline]
pub(crate) fn record_close(name: &'static str) {
    PRODUCERS.with(|cell| cell.get_or_init(Producers::for_current_thread).push(Mark::close(name)));
}
