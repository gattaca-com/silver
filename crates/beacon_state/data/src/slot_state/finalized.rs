use super::delta::SlotStateDelta;
use crate::types::{B256, SLOTS_PER_HISTORICAL_ROOT, SlotState};

/// Finalized base for the slot tier: the canonical `SlotState` scalars plus the
/// `block_roots`/`state_roots` circular buffers (indexed by `slot % HR`).
// size: ~1 KB inline (SlotState scalars + 3 × Box/Vec headers); heap 512 KB
// (2 × HR × 32 B root rings) + the eth1_votes Vec.
#[derive(Clone)]
pub struct SlotStateFinalized {
    pub(super) slot: SlotState,
    pub(super) block_roots: Box<[B256]>,
    pub(super) state_roots: Box<[B256]>,
}

impl Default for SlotStateFinalized {
    fn default() -> Self {
        Self {
            slot: Default::default(),
            block_roots: vec![[0u8; 32]; SLOTS_PER_HISTORICAL_ROOT].into_boxed_slice(),
            state_roots: vec![[0u8; 32]; SLOTS_PER_HISTORICAL_ROOT].into_boxed_slice(),
        }
    }
}

impl SlotStateFinalized {
    /// Build from already-parsed parts (the decompose bridge — it owns the SSZ
    /// layout but not these private fields). `block_roots`/`state_roots` must
    /// each be `SLOTS_PER_HISTORICAL_ROOT` long.
    pub fn from_parts(slot: SlotState, block_roots: Box<[B256]>, state_roots: Box<[B256]>) -> Self {
        debug_assert_eq!(block_roots.len(), SLOTS_PER_HISTORICAL_ROOT);
        debug_assert_eq!(state_roots.len(), SLOTS_PER_HISTORICAL_ROOT);
        Self { slot, block_roots, state_roots }
    }
}

impl SlotStateFinalized {
    /// Fold a fork's delta into the base: adopt its `SlotState`, then write its
    /// appended block/state roots into the circular buffers at the slots they
    /// cover (`(old_fin_slot + i) % cap`). The data half of finalization.
    pub(super) fn promote(&mut self, delta: &SlotStateDelta) {
        let old_fin_slot = self.slot.slot as usize;
        // Copy the winner's scalars into the (heap-stable) base in place — never
        // replace the base allocation, so a concurrent checkpoint-snapshot read
        // of `eth1_votes` can't dangle. See [`crate::slot_state`].
        self.slot.clone_from(&delta.slot);

        let block_cap = self.block_roots.len();
        debug_assert!(delta.block_roots.len() <= block_cap, "delta block_roots exceeds ring cap");
        for (i, r) in delta.block_roots.iter().enumerate() {
            self.block_roots[(old_fin_slot + i) % block_cap] = *r;
        }
        let state_cap = self.state_roots.len();
        debug_assert!(delta.state_roots.len() <= state_cap, "delta state_roots exceeds ring cap");
        for (i, r) in delta.state_roots.iter().enumerate() {
            self.state_roots[(old_fin_slot + i) % state_cap] = *r;
        }
    }
}
