//! End-to-end test harness for the silver gossip stack.
//!
//! Spawns two full tile stacks (publisher + echo) in one process with distinct
//! flux `path_suffix` values so their shmem queue trees don't collide. Tests
//! drive the harness from a single thread, ticking both stacks' `loop_body`.

mod harness;
mod inject;
mod stack;
mod stats;

pub use harness::TwoStackHarness;
pub use stack::{EchoStack, PublisherStack, keypair_from_seed};
pub use stats::Stats;
