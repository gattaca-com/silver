//! Generic persistent SSZ hash tree.
//!
//! Two layers that compose like the existing `FinalizedValidators` /
//! `ValidatorsDelta` split, but agnostic about what each leaf encodes.
//! Callers keep their domain data wherever it already lives (the
//! existing flat arrays in `FinalizedValidators`, `EpochData`,
//! `SlotData`, …) and put a `FinalizedHashTree` next to it. Whenever
//! a source field changes, the caller recomputes the affected leaf
//! `B256` and pokes it into the tree.
//!
//! - [`finalized`] — flat segment tree, owned by the finalized side.
//! - [`delta`]     — persistent overlay, owned by the per-fork side.
//!
//! This module is hash-only. SSZ semantics that go above the physical
//! tree — `mix_in_length` for `List<T, N>`, extra zero-hash folding
//! when the SSZ list limit is larger than the tree's `max_elements` —
//! are applied by the caller around `root_hash()`. Same for leaf
//! encoding: each `B256` is whatever SSZ root the caller wants to
//! commit to.

mod delta;
mod finalized;
mod state;

#[cfg(test)]
mod tests;

pub use delta::{DeltaHashTree, DeltaNode};
pub use finalized::FinalizedHashTree;
pub use state::HashTreeState;
