//! Capture #[timed] call trees and render them as a call tree or JSON. Marks
//! are produced into per-thread shmem rings; the call tree is folded either
//! in-process (the perf harness) or by an overseer reading the rings of a
//! running silver ([`FlamegraphReader`]).

mod aggregator;
mod call_tree;
mod drainer;
mod mark;
mod names;
mod producer;
mod queue_dir;
mod reader;
pub mod report;
mod symbols;

pub(crate) use mark::Frame;
pub(crate) use producer::record;
pub use queue_dir::enable_overseer;
pub use reader::{FlamegraphReader, LocalReader};
