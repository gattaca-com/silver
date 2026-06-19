//! Hardware performance counters for `#[timed]` (distinct from the shmem app
//! counters in `declare_counters!`). The hot path is deliberately dumb: read
//! the opened counters into a fixed [`PerfSample`] and either fold the raw
//! deltas into the call tree (harness mode) or stream them onto the
//! `perf-{name}` queue (live mode). All labelling and derived ratios happen in
//! postprocessing.
//!
//! Layers (read top-down):
//! - [`events`] — name → perf_event_open `(type, config)` for this CPU; the
//!   single place to add a metric. Pure logic, no I/O on the hot path.
//! - [`sample`] — [`PerfSample`], the raw value record.
//! - [`source`] — per-thread rdpmc [`read`]/[`emit`], feature-gated.
//! - `raw` — the rdpmc primitive (only compiled with the `perf` feature).
//!
//! Collection is gated behind the `perf` feature; without it (or when
//! `perf_event_paranoid` blocks the events) [`read`] returns `None` and
//! [`emit`] is a no-op, so `#[timed]` degrades to timing only.

mod events;
#[cfg(feature = "perf")]
mod raw;
mod sample;
mod source;

pub use events::{EventSpec, schema, slot};
pub use sample::{MAX_EVENTS, PerfSample};
pub(crate) use source::{emit, read};
