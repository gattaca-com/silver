use crate::{
    buffer::Reset,
    types::{HistoricalSummary, SYNC_COMMITTEE_SIZE, SyncCommittee},
};

/// Longtail tier state: sync committees + their resolved validator indices +
/// the cumulative `historical_summaries` log. Used as BOTH the finalized base
/// AND the per-fork delta entry — for the base `historical_summaries` is the
/// full list; for a fork delta it holds only the post-finalization appends.
// size: ~50 KB (two SyncCommittees + sync_committee_indices). The base's
// `historical_summaries` Vec GROWS, so the base allocation is realloc-prone;
// `promote` extends in place rather than replacing it.
#[derive(Clone)]
pub struct LongtailState {
    pub current_sync_committee: SyncCommittee,
    pub next_sync_committee: SyncCommittee,
    pub sync_committee_indices: [u32; SYNC_COMMITTEE_SIZE],
    pub historical_summaries: Vec<HistoricalSummary>,
}

impl Default for LongtailState {
    fn default() -> Self {
        Self {
            current_sync_committee: Default::default(),
            next_sync_committee: Default::default(),
            sync_committee_indices: [0u32; SYNC_COMMITTEE_SIZE],
            historical_summaries: Default::default(),
        }
    }
}

impl LongtailState {
    /// Fold a fork's delta into the base: sync committees + indices are
    /// absolute (replace), then **extend** the cumulative
    /// `historical_summaries` log with the delta's post-finalization
    /// appends. The data half of finalization.
    pub(super) fn promote(&mut self, delta: &LongtailState) {
        self.current_sync_committee = delta.current_sync_committee;
        self.next_sync_committee = delta.next_sync_committee;
        self.sync_committee_indices = delta.sync_committee_indices;
        self.historical_summaries.extend_from_slice(&delta.historical_summaries);
    }

    /// Re-base a survivor longtail entry after `promoted` was folded into the
    /// base. Sync committees are absolute (replace, no re-base); only the
    /// cumulative `historical_summaries` log drops the promoted prefix.
    pub(super) fn prune_to_base(&mut self, promoted: &LongtailState) {
        let drop = promoted.historical_summaries.len().min(self.historical_summaries.len());
        self.historical_summaries.drain(..drop);
    }
}

impl Reset for LongtailState {
    fn reset(&mut self) {
        self.current_sync_committee = SyncCommittee::default();
        self.next_sync_committee = SyncCommittee::default();
        self.sync_committee_indices = [0u32; SYNC_COMMITTEE_SIZE];
        self.historical_summaries.clear();
    }

    fn reset_from(&mut self, other: &Self) {
        self.current_sync_committee = other.current_sync_committee;
        self.next_sync_committee = other.next_sync_committee;
        self.sync_committee_indices = other.sync_committee_indices;
        self.historical_summaries.clone_from(&other.historical_summaries);
    }
}
