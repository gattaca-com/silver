use flux::timing::Duration;
use rustc_hash::FxHashMap;

use crate::{
    flamegraph_timer::mark::{Frame, Mark},
    perf::PerfSample,
};

#[derive(Default)]
pub(crate) struct CallStackSamples {
    pub(crate) tracked_ns: Vec<u64>,
    pub(crate) total_untracked_ns: u64,
    /// Summed entry→exit counter deltas across calls; all-zero when the
    /// `perf` feature is off. `total_untracked_perf` excludes children, like
    /// `total_untracked_ns`.
    pub(crate) tracked_perf: PerfSample,
    pub(crate) total_untracked_perf: PerfSample,
}

struct OpenFrame {
    id: u64,
    ts: u64,
    perf: PerfSample,
    total_tracked_ns: u64,
    total_tracked_perf: PerfSample,
}

/// Folds mark streams into call-path timings keyed by portable frame id,
/// independent of how the marks were transported (in-process buffers or a
/// cross-process shmem ring). Frame ids stay opaque: resolving them to names
/// needs the producer's binary and belongs to the reader that owns it.
///
/// Each `fold_thread` call folds a mark stream from a fresh stack, so a
/// cumulative tree comes from re-folding the whole retained stream (as the perf
/// harness does at [`drain`]), not from folding disjoint windows.
#[derive(Default)]
pub(crate) struct Aggregator {
    paths: FxHashMap<Vec<u64>, CallStackSamples>,
    /// A close popped an open with a different id — the stream desynced, so the
    /// folded stats are unreliable (surfaced as `missed_events`). See
    /// [`Self::fold_thread`].
    desynced: bool,
}

impl Aggregator {
    pub(crate) fn fold_thread(&mut self, marks: &[Mark], counters: &[PerfSample]) {
        // `counters[i]` is the snapshot pushed right after `marks[i]` (same
        // producer thread, lockstep order), so the two are index-aligned over
        // their common prefix. A live drain (surfer reading while the producer
        // runs) can snapshot the rings a push apart, leaving a 1-ish tail
        // mismatch — benign: the extra counter is ignored and a mark missing
        // its counter falls back to zero below. Perf off ⇒ `counters` empty.
        let mut stack: Vec<OpenFrame> = Vec::new();
        for (i, mark) in marks.iter().enumerate() {
            let sample = counters.get(i).copied().unwrap_or_default();
            let closing_id = match mark.frame {
                Frame::Open { id, .. } => {
                    stack.push(OpenFrame {
                        id,
                        ts: mark.ts,
                        perf: sample,
                        total_tracked_ns: 0,
                        total_tracked_perf: PerfSample::default(),
                    });
                    continue;
                }
                Frame::Close { id } => id,
            };

            let Some(frame) = stack.pop() else { continue };
            // Drop guards close in reverse open order, so a close must pop its
            // own open. A mismatch means the stream desynced (a producer
            // crash/restart, or a ring overwrite reordering marks); we still
            // attribute to the popped frame but flag the fold as unreliable.
            debug_assert_eq!(closing_id, frame.id, "timed close popped a non-matching open");
            self.desynced |= closing_id != frame.id;
            let tracked_ns = Duration(mark.ts.saturating_sub(frame.ts)).as_nanos() as u64;
            let untracked_ns = tracked_ns.saturating_sub(frame.total_tracked_ns);
            let tracked_perf = sample.delta(&frame.perf);
            let untracked_perf = tracked_perf.delta(&frame.total_tracked_perf);

            let path: Vec<u64> = stack.iter().map(|f| f.id).chain([frame.id]).collect();
            if let Some(parent) = stack.last_mut() {
                parent.total_tracked_ns += tracked_ns;
                parent.total_tracked_perf = parent.total_tracked_perf.add(&tracked_perf);
            }

            let entry = self.paths.entry(path).or_default();
            entry.tracked_ns.push(tracked_ns);
            entry.total_untracked_ns += untracked_ns;
            entry.tracked_perf = entry.tracked_perf.add(&tracked_perf);
            entry.total_untracked_perf = entry.total_untracked_perf.add(&untracked_perf);
        }
    }

    pub(crate) fn desynced(&self) -> bool {
        self.desynced
    }

    pub(crate) fn into_paths(self) -> FxHashMap<Vec<u64>, CallStackSamples> {
        self.paths
    }
}
