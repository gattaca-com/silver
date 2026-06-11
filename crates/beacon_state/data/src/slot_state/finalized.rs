use std::io::{self, Write};

use super::delta::SlotStateDelta;
use crate::{
    buffer::write_ring_window,
    encode::write_b256_slice,
    types::{B256, SLOTS_PER_HISTORICAL_ROOT, SlotState},
};

// size: ~1 KB inline (SlotState scalars + 2 × Box headers); heap 512 KB
// (2 × HR × 32 B root rings).
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

    #[inline]
    pub(crate) fn state(&self) -> &SlotState {
        &self.slot
    }

    /// SSZ-encode the `block_roots` then `state_roots` circular buffers
    /// (consecutive fixed-part fields, spec index order) — checkpoint
    /// encoding.
    pub(crate) fn write_roots_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        write_b256_slice(w, &self.block_roots)?;
        write_b256_slice(w, &self.state_roots)
    }

    /// Fold a fork's delta into the base: adopt its `SlotState`, then write its
    /// appended block/state roots into the circular buffers at the slots they
    /// cover (`(old_fin_slot + i) % cap`). The data half of finalization.
    pub(super) fn promote(&mut self, delta: &SlotStateDelta) {
        let old_fin_slot = self.slot.slot as usize;
        self.slot.clone_from(&delta.slot);

        write_ring_window(&mut self.block_roots, old_fin_slot, &delta.block_roots);
        write_ring_window(&mut self.state_roots, old_fin_slot, &delta.state_roots);
    }
}
