use super::{LongtailGroup, LongtailId, finalized::LongtailState};
use crate::{buffer::Slot as RingSlot, types::HistoricalSummary};

/// Value-layer read over the longtail tier (base + optional per-fork delta).
/// The delta is `Some` for a fork that crossed a sync-committee / historical
/// rotation, else `None` and reads fall through to the base.
/// `historical_summary` merges the base's full log with the delta's appended
/// tail.
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

    /// Effective longtail state — the fork's if it has a delta, else the base.
    /// Exposes the sync-committee scalars; for the merged
    /// `historical_summaries` view use [`Self::historical_summary`] /
    /// [`Self::historical_summaries_len`].
    #[inline]
    pub fn state(&self) -> &'a LongtailState {
        self.delta.unwrap_or(self.base)
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
    fork: RingSlot<'a, LongtailGroup, LongtailState>,
}

impl<'a> LongtailWriteView<'a> {
    #[inline]
    pub(super) fn new(
        base: &'a LongtailState,
        fork: RingSlot<'a, LongtailGroup, LongtailState>,
    ) -> Self {
        Self { base, fork }
    }

    #[inline]
    pub fn commit(self) -> LongtailId {
        self.fork.commit()
    }

    /// Read view over the same fork — mirrors `SlotStateWriteView::reader`.
    #[inline]
    pub fn reader(&self) -> LongtailView<'_> {
        LongtailView::new(self.base, Some(&self.fork))
    }

    /// Mutable handle to the fork's working [`LongtailState`].
    #[inline]
    pub fn state_mut(&mut self) -> &mut LongtailState {
        &mut self.fork
    }

    /// Seed the fresh fork's sync committees + indices from the finalized base;
    /// the `historical_summaries` log stays empty (cleared by `reset`).
    #[inline]
    pub(super) fn seed_from_base(&mut self) {
        self.fork.current_sync_committee = self.base.current_sync_committee;
        self.fork.next_sync_committee = self.base.next_sync_committee;
        self.fork.sync_committee_indices = self.base.sync_committee_indices;
    }

    #[inline]
    pub fn push_historical_summary(&mut self, h: HistoricalSummary) {
        self.fork.historical_summaries.push(h);
    }
}
