//! End-to-end test harness for the silver gossip stack.
//!
//! Spawns two full tile stacks (publisher + echo) in one process with distinct
//! flux `path_suffix` values so their shmem queue trees don't collide. Tests
//! drive the harness from a single thread, ticking both stacks' `loop_body`.

mod harness;
pub mod inject;
mod stack;
mod stats;

#[cfg(feature = "lh-client")]
pub mod lh_client;
#[cfg(feature = "lh-client")]
pub mod lh_gossip;

pub use harness::TwoStackHarness;
#[cfg(feature = "lh-client")]
pub use lh_client::LhClient;
#[cfg(feature = "lh-client")]
pub use lh_gossip::LhGossipClient;
pub use stack::{
    EchoCompressionHalf, EchoNetworkHalf, EchoStack, PublisherStack, keypair_from_seed,
};
pub use stats::Stats;
