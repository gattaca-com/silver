use super::{delta::DeltaHashTree, finalized::FinalizedHashTree};
use crate::types::B256;

/// Per-fork merged view: raw pointer to the tile-owned finalized base
/// + owned [`DeltaHashTree`]. Safety: pointee is boxed (stable address) and
///   outlives the state; only `delta` is mutated through this struct.
pub struct HashTreeState {
    finalized: *const FinalizedHashTree,
    delta: DeltaHashTree,
}

impl Clone for HashTreeState {
    fn clone(&self) -> Self {
        Self { finalized: self.finalized, delta: self.delta.clone() }
    }
}

impl HashTreeState {
    pub fn with_empty_delta(finalized: &FinalizedHashTree) -> Self {
        Self { finalized: finalized as *const _, delta: DeltaHashTree::new_at(finalized) }
    }

    #[inline]
    pub fn finalized(&self) -> &FinalizedHashTree {
        // Safety: pointer is set from a live tile-owned reference at
        // construction; tile outlives every state.
        unsafe { &*self.finalized }
    }

    #[inline]
    pub fn delta(&self) -> &DeltaHashTree {
        &self.delta
    }

    pub fn set_leaf(&mut self, i: usize, leaf: B256) {
        let max_elements = self.finalized().max_elements();
        debug_assert!(
            i < max_elements,
            "leaf index out of range: i={i}, max_elements={}",
            max_elements
        );
        self.delta = self.finalized().set_delta_leaf_in_range(
            &self.delta,
            i as u32,
            0,
            max_elements as u32,
            leaf,
        );
    }

    pub fn root_hash(&self) -> B256 {
        self.finalized().resolve_delta_hash(&self.delta)
    }

    /// Fold this fork's delta into `base`. Caller is expected to follow up with
    /// `prune_to_base` on every fork (including this one) so unused delta nodes
    /// are freed.
    pub fn promote_into_base(&self, base: &mut FinalizedHashTree) {
        base.promote_delta_at(&self.delta, FinalizedHashTree::root());
    }

    /// Memory compaction after promotion
    pub fn prune_to_base(&mut self, base: &FinalizedHashTree) {
        base.prune_delta_at(&mut self.delta, FinalizedHashTree::root());
    }
}
