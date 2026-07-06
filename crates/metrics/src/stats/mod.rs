//! Fold drained `#[timed]` event streams into per-path stats and render them
//! as a call tree or JSON.

mod aggregator;
mod call_tree;
mod counters;
mod names;
mod report;

pub use report::{TimingStats, fold_stats};
