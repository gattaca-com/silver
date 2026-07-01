//! Per-thread allocated/freed byte accounting for the flamegraph rings.

mod sample;
pub use sample::AllocSample;

#[cfg(feature = "alloc-profile")]
mod counting;
#[cfg(feature = "alloc-profile")]
pub use counting::CountingAllocator;
#[cfg(feature = "alloc-profile")]
pub(crate) use counting::read;
