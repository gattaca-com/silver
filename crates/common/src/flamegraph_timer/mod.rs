//! Capture #[timed] call trees in-process and render them as a call tree or
//! JSON.

pub mod collect;
pub mod report;

pub use collect::enable;
pub(crate) use collect::{is_enabled, stack_enter, stack_exit};
