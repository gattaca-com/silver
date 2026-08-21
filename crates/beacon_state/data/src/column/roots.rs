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

    /// [`Self::at_slot`] while the ring still records `slot`: it covers the
    /// `SLOTS_PER_HISTORICAL_ROOT` slots below `state_slot`, whose own entry is
    /// written by the `process_slot` that leaves it. An empty slot's entry
    /// repeats the last block's root, as the spec accessor's own does.
    pub fn recorded_at(&self, slot: Slot, state_slot: Slot) -> Option<B256> {
        let recorded = slot < state_slot && state_slot <= slot + SLOTS_PER_HISTORICAL_ROOT as u64;
        recorded.then(|| self.at_slot(slot))
    }

    /// The root of the block proposed at `slot`, when the ring proves one was:
    /// `process_slot` repeats the previous entry through a slot that carried no
    /// block, so an entry differing from its predecessor is the mark of a block
    /// of the slot's own.
    pub fn proposed_at(&self, slot: Slot, state_slot: Slot) -> Option<B256> {
        let root = self.recorded_at(slot, state_slot)?;
        let Some(previous) = slot.checked_sub(1) else {
            return Some(root);
        };
        (self.recorded_at(previous, state_slot)? != root).then_some(root)
    }

    /// Whether the ring holds `root` at or below `from_slot`. Fork choice is
    /// what writes a root here, so membership means "seen and validated".
    /// Walks most-recent-first: a queried parent is virtually always a slot or
    /// two back, while a miss costs the whole ring either way.
    pub fn contains(&self, root: &B256, from_slot: Slot) -> bool {
        (0..SLOTS_PER_HISTORICAL_ROOT as u64)
            .any(|back| self.at_slot(from_slot.saturating_sub(back)) == *root)
    }
}

impl RootsWriteView<'_, BlockRoots> {
    #[inline]
    pub fn at_slot(&self, slot: Slot) -> B256 {
        self.reader().at_slot(slot)
    }
}
