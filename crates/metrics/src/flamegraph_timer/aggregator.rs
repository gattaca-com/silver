use flux::timing::Duration;
use rustc_hash::FxHashMap;

use crate::{
    allocator::AllocSample,
    flamegraph_timer::{counters::Counters, mark::Mark},
    perf::PerfSample,
};

#[derive(Default)]
pub(crate) struct CallStackSamples {
    pub(crate) tracked_ns: Vec<u64>,
    pub(crate) total_untracked_ns: u64,
    /// Summed entry→exit counter deltas across calls; the `perf`/`alloc` slots
    /// are all-zero when their feature is off. `total_untracked` excludes
    /// children, like `total_untracked_ns`.
    pub(crate) tracked: Counters,
    pub(crate) total_untracked: Counters,
}

struct OpenFrame {
    id: u64,
    ts: u64,
    counters: Counters,
    total_tracked_ns: u64,
    total_tracked: Counters,
}

/// One thread's mark stream folded into call-path timings keyed by portable
/// frame id, independent of how the marks were transported (in-process buffers
/// or a cross-process shmem ring). Frame ids stay opaque: resolving them to
/// names needs the producer's binary and belongs to the reader that owns it.
///
/// Folding is one-shot over the whole retained stream from a fresh stack, so a
/// cumulative tree comes from re-[`new`](Self::new)ing on the grown stream, not
/// from folding disjoint windows.
pub(crate) struct Aggregator {
    pub(crate) paths: FxHashMap<Vec<u64>, CallStackSamples>,
}

impl Aggregator {
    pub(crate) fn new(marks: &[Mark], perf: &[PerfSample], alloc: &[AllocSample]) -> Self {
        // `perf[i]`/`alloc[i]` ride the same drain row as `marks[i]` (the rings
        // are joined by push sequence number, see the drainer), so pairing by
        // position is exact; a feature-off slice is empty and folds to zero.
        // The join also guarantees well-formedness: every close pops its own
        // open.
        let mut paths = FxHashMap::<Vec<u64>, CallStackSamples>::default();
        let mut stack: Vec<OpenFrame> = Vec::new();
        for (i, mark) in marks.iter().enumerate() {
            let sample = Counters {
                perf: perf.get(i).copied().unwrap_or_default(),
                alloc: alloc.get(i).copied().unwrap_or_default(),
            };
            if mark.is_open() {
                stack.push(OpenFrame {
                    id: mark.id,
                    ts: mark.ts,
                    counters: sample,
                    total_tracked_ns: 0,
                    total_tracked: Counters::default(),
                });
                continue;
            }

            let Some(frame) = stack.pop() else { continue };
            debug_assert_eq!(mark.id, frame.id, "timed close popped a non-matching open");
            let tracked_ns = Duration(mark.ts.saturating_sub(frame.ts)).as_nanos() as u64;
            let untracked_ns = tracked_ns.saturating_sub(frame.total_tracked_ns);
            let tracked = sample.delta(&frame.counters);
            let untracked = tracked.delta(&frame.total_tracked);

            let path: Vec<u64> = stack.iter().map(|f| f.id).chain([frame.id]).collect();
            if let Some(parent) = stack.last_mut() {
                parent.total_tracked_ns += tracked_ns;
                parent.total_tracked = parent.total_tracked.add(&tracked);
            }

            let entry = paths.entry(path).or_default();
            entry.tracked_ns.push(tracked_ns);
            entry.total_untracked_ns += untracked_ns;
            entry.tracked = entry.tracked.add(&tracked);
            entry.total_untracked = entry.total_untracked.add(&untracked);
        }
        Self { paths }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(id: u64, ts: u64) -> Mark {
        Mark::from_parts(id, ts, true)
    }

    fn close(id: u64, ts: u64) -> Mark {
        Mark::from_parts(id, ts, false)
    }

    fn alloc(allocated: u64, freed: u64) -> AllocSample {
        AllocSample { allocated, freed }
    }

    /// A parent frame that allocates around a child: the child's bytes are
    /// charged to the child path, and excluded from the parent's untracked.
    #[test]
    fn alloc_deltas_attribute_to_paths_excluding_children() {
        let marks = [open(1, 0), open(2, 0), close(2, 0), close(1, 0)];
        // Snapshots ride after each mark: parent enters at 0/0, allocates 30
        // before the child, the child allocates 100 and frees 40, then the
        // parent allocates 70 more after the child returns.
        let allocs = [alloc(0, 0), alloc(30, 0), alloc(130, 40), alloc(200, 40)];

        let paths = Aggregator::new(&marks, &[], &allocs).paths;

        let child = &paths[&vec![1, 2]];
        assert_eq!(child.tracked.alloc.allocated, 100);
        assert_eq!(child.tracked.alloc.freed, 40);

        let parent = &paths[&vec![1]];
        assert_eq!(parent.tracked.alloc.allocated, 200, "parent's full subtree");
        // Untracked = parent total (200) minus the child it called (100) = 100.
        assert_eq!(parent.total_untracked.alloc.allocated, 100, "child's bytes excluded");
    }

    #[test]
    fn absent_alloc_slice_folds_to_zero() {
        let marks = [open(1, 0), close(1, 0)];
        let paths = Aggregator::new(&marks, &[], &[]).paths;
        assert_eq!(paths[&vec![1]].tracked.alloc.allocated, 0);
    }
}
