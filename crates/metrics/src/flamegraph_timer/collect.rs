use std::{
    cell::RefCell,
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use flux::timing::Instant;

use crate::perf::{self, PerfSample};

struct Frame {
    name: &'static str,
    start: Instant,
    /// Total tracked ns of timed children that have already exited under
    /// this frame — subtracted to get the frame's untracked time.
    total_tracked_ns: u64,
    /// Counter snapshot at entry; `None` when the `perf` feature is off or
    /// `perf_event_open` is unavailable. Mirrors `start`/`total_tracked_ns`
    /// for the hardware-counter dimension.
    perf_start: Option<PerfSample>,
    total_tracked_perf: PerfSample,
}

thread_local! {
    static CALL_STACK: RefCell<Vec<Frame>> = const { RefCell::new(Vec::new()) };
}

#[derive(Default)]
pub(super) struct CallStackSamples {
    pub(super) tracked_ns: Vec<u64>,
    pub(super) total_untracked_ns: u64,
    /// Summed entry→exit counter deltas across calls; all-zero when the
    /// `perf` feature is off. `total_untracked_perf` excludes children, like
    /// `total_untracked_ns`.
    pub(super) tracked_perf: PerfSample,
    pub(super) total_untracked_perf: PerfSample,
}

pub(super) struct CallStackTiming {
    pub(super) call_stack: Vec<&'static str>,
    pub(super) samples: CallStackSamples,
}

/// Cross-thread aggregation map: every thread's `stack_exit` merges its
/// finished frame into this one shared map, so the `Mutex` is required even
/// though the live call stack is thread-local.
type SharedPathSink = Mutex<HashMap<Vec<&'static str>, CallStackSamples>>;
static SINK: OnceLock<SharedPathSink> = OnceLock::new();

pub fn enable() {
    let _ = SINK.set(Mutex::new(HashMap::new()));
}

pub(super) fn drain() -> Vec<CallStackTiming> {
    let Some(sink) = SINK.get() else { return Vec::new() };
    std::mem::take(&mut *sink.lock().unwrap())
        .into_iter()
        .map(|(call_stack, samples)| CallStackTiming { call_stack, samples })
        .collect()
}

pub(crate) fn is_enabled() -> bool {
    SINK.get().is_some()
}

#[inline]
pub(crate) fn stack_enter(name: &'static str, start: Instant) {
    if SINK.get().is_some() {
        let perf_start = perf::read();
        CALL_STACK.with(|s| {
            s.borrow_mut().push(Frame {
                name,
                start,
                total_tracked_ns: 0,
                perf_start,
                total_tracked_perf: PerfSample::default(),
            })
        });
    }
}

#[inline]
pub(crate) fn stack_exit() {
    let Some(sink) = SINK.get() else { return };
    let perf_end = perf::read();
    CALL_STACK.with(|s| {
        let mut stack = s.borrow_mut();
        let Some(frame) = stack.pop() else { return };
        let tracked_ns = frame.start.elapsed().as_nanos() as u64;
        let untracked_ns = tracked_ns.saturating_sub(frame.total_tracked_ns);

        // Counter delta over the call; zero when either snapshot is absent.
        let tracked_perf = match (perf_end, frame.perf_start) {
            (Some(end), Some(start)) => end.delta(&start),
            _ => PerfSample::default(),
        };
        let untracked_perf = tracked_perf.delta(&frame.total_tracked_perf);

        let path: Vec<&'static str> = stack.iter().map(|f| f.name).chain([frame.name]).collect();
        if let Some(parent) = stack.last_mut() {
            parent.total_tracked_ns += tracked_ns;
            parent.total_tracked_perf = parent.total_tracked_perf.add(&tracked_perf);
        }

        let mut map = sink.lock().unwrap();
        let entry = map.entry(path).or_default();
        entry.tracked_ns.push(tracked_ns);
        entry.total_untracked_ns += untracked_ns;
        entry.tracked_perf = entry.tracked_perf.add(&tracked_perf);
        entry.total_untracked_perf = entry.total_untracked_perf.add(&untracked_perf);
    });
}
