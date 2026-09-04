use super::{ColumnGroup, ColumnReader, ColumnSpec, ColumnWriteView};
use crate::{
    ring::Id,
    types::{B256, SLOTS_PER_HISTORICAL_ROOT, Slot},
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
