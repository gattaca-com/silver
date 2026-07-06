//! Capture `#[timed]` call trees into per-thread shmem rings and read them
//! back — in-process ([`InProcessReader`]) or from a running producer
//! ([`CrossProcessReader`]) — as sample-aligned event streams and FXT traces.
//! Self-contained (no dependency on the rest of the crate), so the whole
//! directory can move to flux wholesale.

pub mod allocator;
mod drainer;
mod fxt;
mod mark;
pub(crate) mod perf;
mod producer;
mod queue_dir;
mod reader;
mod ring_drainer;
mod symbols;
mod timing;

pub(crate) use drainer::FlamegraphMeta;
pub use drainer::{EventsDrainer, Loss, ThreadEvents};
pub(crate) use mark::Mark;
#[cfg(test)]
pub(crate) use queue_dir::test_shmem;
pub use queue_dir::{enable_profiler, live_apps, published_pid};
pub use reader::{CrossProcessReader, InProcessReader};
pub use timing::TimerGuard;
