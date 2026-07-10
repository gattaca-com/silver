use std::io::{self, Write};

use flux_profiler::timed;

use crate::{
    DecomposeError, FinalizedValidators,
    decompose::common::{F22, F23, HISTORICAL_SUMMARY_SSZ_SIZE, Offsets, b256},
    reanchor::drain_promoted_prefix,
    ring::Reset,
    types::{HistoricalSummary, SYNC_COMMITTEE_SIZE, SyncCommittee},
};

const HISTORICAL_SUMMARIES_LIMIT: usize = 1 << 24;

/// Used as BOTH the finalized base AND the per-fork delta entry — for the base
/// `historical_summaries` is the full list; for a fork delta it holds only the
/// post-finalization appends.
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
    /// SSZ-encode the cumulative `historical_summaries` log — checkpoint
    /// section body. Callers hold the group's promote barrier
    /// (`with_finalized_locked`).
    pub(crate) fn write_historical_summaries_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        for hs in self.historical_summaries.iter() {
            w.write_all(&hs.block_summary_root)?;
            w.write_all(&hs.state_summary_root)?;
        }
        Ok(())
    }

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
        drain_promoted_prefix(&mut self.historical_summaries, promoted.historical_summaries.len());
    }
}

// `validators` resolves the sync-committee → validator indices.
impl LongtailState {
    #[timed]
    pub(crate) fn from_ssz(
        ssz: &[u8],
        o: &Offsets,
        validators: &FinalizedValidators,
    ) -> Result<Self, DecomposeError> {
        let mut lt = Self::default();

        read_sync_committee(ssz, F22, "current", &mut lt.current_sync_committee)?;
        read_sync_committee(ssz, F23, "next", &mut lt.next_sync_committee)?;

        let hs_bytes = &ssz[o.hist_summaries..o.pending_deposits];
        if !hs_bytes.len().is_multiple_of(HISTORICAL_SUMMARY_SSZ_SIZE) {
            return Err(DecomposeError::HistoricalSummariesLenNotMultiple { len: hs_bytes.len() });
        }
        let hs_count = hs_bytes.len() / HISTORICAL_SUMMARY_SSZ_SIZE;
        if hs_count > HISTORICAL_SUMMARIES_LIMIT {
            return Err(DecomposeError::TooManyHistoricalSummaries {
                n: hs_count,
                max: HISTORICAL_SUMMARIES_LIMIT,
            });
        }
        lt.historical_summaries.reserve_exact(hs_count);
        for i in 0..hs_count {
            let s = &hs_bytes[i * HISTORICAL_SUMMARY_SSZ_SIZE..];
            lt.historical_summaries.push(HistoricalSummary {
                block_summary_root: b256(s, 0),
                state_summary_root: b256(s, 32),
            });
        }

        for i in 0..SYNC_COMMITTEE_SIZE {
            let pk = lt.current_sync_committee.pubkeys[i];
            lt.sync_committee_indices[i] =
                validators.find_by_pubkey(&pk).map(|i| i as u32).unwrap_or(u32::MAX);
        }

        Ok(lt)
    }
}

fn read_sync_committee(
    s: &[u8],
    off: usize,
    which: &'static str,
    sc: &mut SyncCommittee,
) -> Result<(), DecomposeError> {
    const SC_SIZE: usize = SYNC_COMMITTEE_SIZE * 48 + 48;
    let end = off.checked_add(SC_SIZE).ok_or(DecomposeError::SyncCommitteeOutOfBounds {
        which,
        off,
        end: 0,
        len: s.len(),
    })?;
    let bytes = s.get(off..end).ok_or(DecomposeError::SyncCommitteeOutOfBounds {
        which,
        off,
        end,
        len: s.len(),
    })?;
    for i in 0..SYNC_COMMITTEE_SIZE {
        sc.pubkeys[i].copy_from_slice(&bytes[i * 48..(i + 1) * 48]);
    }
    sc.aggregate_pubkey
        .copy_from_slice(&bytes[SYNC_COMMITTEE_SIZE * 48..SYNC_COMMITTEE_SIZE * 48 + 48]);
    Ok(())
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
