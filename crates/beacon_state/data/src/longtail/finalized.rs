use std::io::{self, Write};

use flux_profiler::timed;

use super::sync_committees::SyncCommittees;
use crate::{
    DecomposeError, FinalizedValidators,
    decompose::common::{F22, F23, HISTORICAL_SUMMARY_SSZ_SIZE, Offsets, b256},
    merkle::{B256, MerkleStack, hash_list},
    reanchor::drain_promoted_prefix,
    ring::Reset,
    types::{HISTORICAL_ROOTS_LIMIT, HistoricalSummary, SYNC_COMMITTEE_SIZE, SyncCommittee},
};

/// Used as BOTH the finalized base AND the per-fork delta entry — for the base
/// `historical_summaries` is the full list; for a fork delta it holds only the
/// post-finalization appends.
///
/// `historical_summaries_root` is the root of the *effective* list (base ++ a
/// delta's appends), so it is written by
/// [`LongtailWriteView`](super::LongtailWriteView) — the one place both halves
/// are in scope — and adopted by `promote`.
// size: ~50 KB (the SyncCommittees bundle). The base's `historical_summaries`
// Vec GROWS, so the base allocation is realloc-prone; `promote` extends in
// place rather than replacing it.
#[derive(Clone, Default)]
pub struct LongtailState {
    pub(super) committees: SyncCommittees,
    pub(super) historical_summaries: Vec<HistoricalSummary>,
    pub(super) historical_summaries_root: B256,
}

impl LongtailState {
    #[inline]
    pub fn sync_committees(&self) -> &SyncCommittees {
        &self.committees
    }

    #[inline]
    pub(crate) fn historical_summaries_len(&self) -> usize {
        self.historical_summaries.len()
    }

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
        self.committees.clone_from(&delta.committees);
        self.historical_summaries.extend_from_slice(&delta.historical_summaries);
        self.historical_summaries_root = delta.historical_summaries_root;
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

        lt.committees.fill_rehashing(|current, next| {
            read_sync_committee(ssz, F22, "current", current)?;
            read_sync_committee(ssz, F23, "next", next)
        })?;

        let hs_bytes = &ssz[o.hist_summaries..o.pending_deposits];
        if !hs_bytes.len().is_multiple_of(HISTORICAL_SUMMARY_SSZ_SIZE) {
            return Err(DecomposeError::HistoricalSummariesLenNotMultiple { len: hs_bytes.len() });
        }
        let hs_count = hs_bytes.len() / HISTORICAL_SUMMARY_SSZ_SIZE;
        if hs_count > HISTORICAL_ROOTS_LIMIT {
            return Err(DecomposeError::TooManyHistoricalSummaries {
                n: hs_count,
                max: HISTORICAL_ROOTS_LIMIT,
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

        lt.historical_summaries_root = hash_summaries(&lt.historical_summaries);

        lt.committees.set_indices(std::array::from_fn(|i| {
            let pk = &lt.committees.current().pubkeys[i];
            validators.find_by_pubkey(pk).map_or(u32::MAX, |i| i as u32)
        }));

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
        self.committees = SyncCommittees::default();
        self.historical_summaries.clear();
        self.historical_summaries_root = B256::default();
    }

    fn reset_from(&mut self, other: &Self) {
        self.committees.clone_from(&other.committees);
        self.historical_summaries.clone_from(&other.historical_summaries);
        self.historical_summaries_root = other.historical_summaries_root;
    }
}

/// `hash_tree_root` of `List[HistoricalSummary, HISTORICAL_ROOTS_LIMIT]` — the
/// O(len) recompute the stored root replaces on the read path; runs at the one
/// append per 8192 slots and at decompose.
pub(super) fn hash_summaries<'a>(
    summaries: impl IntoIterator<Item = &'a HistoricalSummary>,
) -> B256 {
    hash_list(
        MerkleStack::new(HISTORICAL_ROOTS_LIMIT),
        summaries.into_iter().map(HistoricalSummary::leaf),
    )
}
