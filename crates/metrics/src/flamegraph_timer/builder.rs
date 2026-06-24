use std::collections::HashMap;

use flux::timing::Duration;

use crate::perf::PerfSample;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) enum Event {
    Open(&'static str),
    Close,
}

/// One open (B) or close (E) frame transition. `name` carries the frame on
/// open and is `""` on close — the builder pops the matching open off the
/// per-thread stack. `repr(C)` + `Copy` so it lives in a flux `Queue<Mark>`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct Mark {
    pub(super) name: Event,
    pub(super) ts: u64,
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

struct OpenFrame {
    id: usize,
    ts: u64,
    perf: PerfSample,
    total_tracked_ns: u64,
    total_tracked_perf: PerfSample,
}

/// A frame's portable id: its name's pointer. `#[timed]` names come from
/// `type_name`/`concat!`, which produce one `&'static str` per frame per
/// monomorphization, so the pointer is a 1:1 stand-in for the string identity
/// within a run — keying paths by id groups them identically to keying by the
/// string, while staying meaningful once marks cross a process boundary (where
/// the raw pointer is resolved back through `Symbols`, not dereferenced).
fn frame_id(name: &'static str) -> usize {
    name.as_ptr() as usize
}

/// Resolves a frame id back to its name. Populated as marks are folded; the
/// transport carries ids, and the name is recovered here.
#[derive(Default)]
struct Symbols(HashMap<usize, &'static str>);

impl Symbols {
    fn insert(&mut self, id: usize, name: &'static str) {
        self.0.entry(id).or_insert(name);
    }

    fn resolve(&self, id: usize) -> &'static str {
        self.0.get(&id).copied().unwrap_or_default()
    }
}

/// Folds per-thread mark streams into call-path timings, independent of how the
/// marks were transported (in-process buffers today, a cross-process shmem ring
/// later). Paths are keyed by portable frame ids; `symbols` resolves them back
/// to names at `finish`.
#[derive(Default)]
pub(super) struct Builder {
    paths: HashMap<Vec<usize>, CallStackSamples>,
    symbols: Symbols,
}

impl Builder {
    pub(super) fn fold_thread(&mut self, marks: &[Mark], counters: &[PerfSample]) {
        // `counters[i]` is the snapshot pushed right after `marks[i]` (same
        // producer thread, lockstep order), so the two are index-aligned over
        // their common prefix. A live drain (surfer reading while the producer
        // runs) can snapshot the rings a push apart, leaving a 1-ish tail
        // mismatch — benign: the extra counter is ignored and a mark missing
        // its counter falls back to zero below. Perf off ⇒ `counters` empty.
        let mut stack: Vec<OpenFrame> = Vec::new();
        for (i, mark) in marks.iter().enumerate() {
            let sample = counters.get(i).copied().unwrap_or_default();
            if let Event::Open(name) = mark.name {
                let id = frame_id(name);
                self.symbols.insert(id, name);
                stack.push(OpenFrame {
                    id,
                    ts: mark.ts,
                    perf: sample,
                    total_tracked_ns: 0,
                    total_tracked_perf: PerfSample::default(),
                });
                continue;
            }

            let Some(frame) = stack.pop() else { continue };
            let tracked_ns = Duration(mark.ts.saturating_sub(frame.ts)).as_nanos() as u64;
            let untracked_ns = tracked_ns.saturating_sub(frame.total_tracked_ns);
            let tracked_perf = sample.delta(&frame.perf);
            let untracked_perf = tracked_perf.delta(&frame.total_tracked_perf);

            let path: Vec<usize> = stack.iter().map(|f| f.id).chain([frame.id]).collect();
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

    pub(super) fn finish(self) -> Vec<CallStackTiming> {
        let Self { paths, symbols } = self;
        paths
            .into_iter()
            .map(|(ids, samples)| CallStackTiming {
                call_stack: ids.iter().map(|&id| symbols.resolve(id)).collect(),
                samples,
            })
            .collect()
    }
}
