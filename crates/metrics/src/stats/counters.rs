//! The per-mark snapshot riding alongside a `#[timed]` frame. Both dimensions
//! are monotonic and folded in lockstep, which is why they share one struct
//! rather than a parallel field per dimension.

use crate::profiler::{allocator::AllocSample, perf::PerfSample};

#[derive(Clone, Copy, Default, serde::Serialize)]
pub(crate) struct Counters {
    pub(crate) perf: PerfSample,
    pub(crate) alloc: AllocSample,
}

impl Counters {
    pub(crate) fn delta(&self, earlier: &Self) -> Self {
        Self { perf: self.perf.delta(&earlier.perf), alloc: self.alloc.delta(&earlier.alloc) }
    }

    pub(crate) fn add(&self, other: &Self) -> Self {
        Self { perf: self.perf.add(&other.perf), alloc: self.alloc.add(&other.alloc) }
    }
}
