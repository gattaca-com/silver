//! Capture #[timed] call trees and render them as a call tree or JSON. Marks
//! are produced into per-thread shmem rings; the call tree is folded either
//! in-process (the perf harness) or by a surfer reading the rings of a
//! running silver ([`FlamegraphReader`]).

mod aggregator;
mod call_tree;
mod drainer;
mod fxt;
mod mark;
mod names;
mod producer;
mod queue_dir;
mod reader;
pub mod report;
mod symbols;

pub(crate) use mark::Frame;
pub(crate) use producer::record;
pub use queue_dir::enable_surfer;
pub use reader::{FlamegraphReader, LocalReader};
