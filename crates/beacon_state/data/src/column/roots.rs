use super::{ColumnGroup, ColumnReader, ColumnSpec, ColumnWriteView};
use crate::{
    ring::Id,
    types::{B256, Epoch, SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT, Slot},
};

/// `Vector[Root, SLOTS_PER_HISTORICAL_ROOT]`, written pointwise: `process_slot`
/// overwrites the bucket at `slot % SLOTS_PER_HISTORICAL_ROOT` every slot.
pub struct BlockRoots;
impl ColumnSpec for BlockRoots {
    type Val = B256;
    type Page = [B256; 32];
    const SSZ_LIMIT: usize = SLOTS_PER_HISTORICAL_ROOT;
    const IS_LIST: bool = false;
}

/// `block_roots`' twin, written in the same `process_slot`.
pub struct StateRoots;
impl ColumnSpec for StateRoots {
    type Val = B256;
    type Page = [B256; 32];
    const SSZ_LIMIT: usize = SLOTS_PER_HISTORICAL_ROOT;
    const IS_LIST: bool = false;
}

pub type BlockRootsGroup = ColumnGroup<BlockRoots>;
pub type BlockRootsId = Id<BlockRootsGroup>;
pub type StateRootsGroup = ColumnGroup<StateRoots>;
pub type StateRootsId = Id<StateRootsGroup>;

pub type RootsView<'a, M> = ColumnReader<'a, M>;
pub type RootsWriteView<'a, M> = ColumnWriteView<'a, M>;

impl RootsView<'_, BlockRoots> {
    /// Spec `get_block_root_at_slot`; valid for the last
    /// `SLOTS_PER_HISTORICAL_ROOT` slots, as the spec's assertion says.
    #[inline]
    pub fn at_slot(&self, slot: Slot) -> B256 {
        self.get(slot as usize % SLOTS_PER_HISTORICAL_ROOT)
    }

    /// Root at the slot before `epoch` starts, saturating to slot zero.
    ///
    /// A head at the decision slot supplies its own root without a history
    /// read. Otherwise, availability is measured from `state_slot`: a
    /// checkpoint state can be ahead of its latest block. Returns `None`
    /// for overwritten history.
    pub fn duty_dependent_root(
        &self,
        epoch: Epoch,
        head_slot: Slot,
        head_root: B256,
        state_slot: Slot,
    ) -> Option<B256> {
        let decision_slot = (epoch * SLOTS_PER_EPOCH).saturating_sub(1);
        debug_assert!(
            decision_slot <= head_slot,
            "epoch {epoch} decides at slot {decision_slot}, past the head at {head_slot}"
        );
        debug_assert!(
            head_slot <= state_slot,
            "the state at {state_slot} is behind its head at {head_slot}"
        );
        if head_slot == decision_slot {
            return Some(head_root);
        }
        (state_slot - decision_slot <= SLOTS_PER_HISTORICAL_ROOT as u64)
            .then(|| self.at_slot(decision_slot))
    }

    /// Slot of the block with `root`, if the ring holds it at or below
    /// `from_slot`. Fork choice is what writes a root here, so a hit means
    /// "seen and validated".
    pub fn slot_of(&self, root: &B256, from_slot: Slot) -> Option<Slot> {
        let oldest = from_slot.saturating_sub(SLOTS_PER_HISTORICAL_ROOT as u64 - 1);
        let mut slot = (oldest..=from_slot).rev().find(|&s| self.at_slot(s) == *root)?;
        while slot > oldest && self.at_slot(slot - 1) == *root {
            slot -= 1;
        }
        Some(slot)
    }
}

impl RootsWriteView<'_, BlockRoots> {
    #[inline]
    pub fn at_slot(&self, slot: Slot) -> B256 {
        self.reader().at_slot(slot)
    }
}
