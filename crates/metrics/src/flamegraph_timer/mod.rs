//! Capture #[timed] call trees in-process and render them as a call tree or
//! JSON.

mod builder;
mod producer;
mod queue_dir;
mod reader;
pub mod report;

pub(crate) use builder::Event;
pub(crate) use producer::record;
pub use reader::enable;
