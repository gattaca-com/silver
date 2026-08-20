use super::{
    LongtailGroup, LongtailId,
    finalized::{LongtailState, hash_summaries},
    sync_committees::SyncCommittees,
};
use crate::{
    merkle::B256,
    ring::Slot as RingSlot,
    types::{HistoricalSummary, SYNC_COMMITTEE_SIZE, SyncCommittee},
};

/// The delta is `Some` for a fork that crossed a sync-committee / historical
/// rotation, else `None` and reads fall through to the base.
#[derive(Clone, Copy)]
pub struct LongtailView<'a> {
    base: &'a LongtailState,
    delta: Option<&'a LongtailState>,
}

impl<'a> LongtailView<'a> {
    #[inline]
    pub(crate) fn new(base: &'a LongtailState, delta: Option<&'a LongtailState>) -> Self {
        Self { base, delta }
    }

    /// Exposes the sync-committee scalars; for the merged
    /// `historical_summaries` view use [`Self::historical_summary`] /
    /// [`Self::historical_summaries_len`].
    #[inline]
    pub fn state(&self) -> &'a LongtailState {
        self.delta.unwrap_or(self.base)
    }

    #[inline]
    pub fn sync_committees(&self) -> &'a SyncCommittees {
        self.state().sync_committees()
    }

    /// SSZ `hash_tree_root` of the merged `historical_summaries` list — stored
    /// at the append, so this is a read.
    #[inline]
    pub fn historical_summaries_root(&self) -> B256 {
        self.state().historical_summaries_root
    }

    /// `historical_summaries[ix]` merged: the base's full log, then the delta's
    /// post-finalization appends.
    #[inline]
    pub fn historical_summary(&self, ix: usize) -> Option<HistoricalSummary> {
        let base = &self.base.historical_summaries;
        if ix < base.len() {
            return Some(base[ix]);
        }
        let j = ix - base.len();
        self.delta.and_then(|d| d.historical_summaries.get(j).copied())
    }

    #[inline]
    pub fn historical_summaries_len(&self) -> usize {
        self.base.historical_summaries.len() +
            self.delta.map_or(0, |d| d.historical_summaries.len())
    }
}

pub struct LongtailWriteView<'a> {
    base: &'a LongtailState,
    fork: RingSlot<'a, LongtailGroup>,
}

impl<'a> LongtailWriteView<'a> {
    /// Fresh fork: copy the base's sync committees (roots included) and
    /// summaries root; the `historical_summaries` log itself stays empty
    /// (cleared by `reset`), and the base's root already covers it.
    #[inline]
    pub(super) fn fresh(base: &'a LongtailState, mut fork: RingSlot<'a, LongtailGroup>) -> Self {
        fork.committees.clone_from(&base.committees);
        fork.historical_summaries_root = base.historical_summaries_root;
        Self { base, fork }
    }

    /// Fork whose delta already carries its state (roll_from / reanchor).
    #[inline]
    pub(super) fn derived(base: &'a LongtailState, fork: RingSlot<'a, LongtailGroup>) -> Self {
        Self { base, fork }
    }

    #[inline]
    pub fn commit(self) -> LongtailId {
        self.fork.commit()
    }

    #[inline]
    pub fn reader(&self) -> LongtailView<'_> {
        LongtailView::new(self.base, Some(&self.fork))
    }

    #[inline]
    pub fn rotate_sync_committees(
        &mut self,
        new_next: &SyncCommittee,
        indices: [u32; SYNC_COMMITTEE_SIZE],
    ) {
        self.fork.committees.rotate(new_next, indices);
    }

    /// Append one summary and re-root the merged list — once per 8192 slots,
    /// so the O(len) fold stays off the state-root path.
    #[inline]
    pub fn push_historical_summary(&mut self, h: HistoricalSummary) {
        self.fork.historical_summaries.push(h);
        self.fork.historical_summaries_root = hash_summaries(
            self.base.historical_summaries.iter().chain(&self.fork.historical_summaries),
        );
    }
}
