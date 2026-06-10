use super::delta::InactivityScoresDelta;
use crate::{ColumnLenMismatch, decompose::u64_le};

/// Finalized base for `inactivity_scores: List[u64, VALIDATOR_REGISTRY_LIMIT]`.
/// Sized to validator capacity; `count` is the finalized list length (kept in
/// lockstep with the validator registry), so the group is self-contained.
pub struct FinalizedInactivityScores {
    pub(super) data: Box<[u64]>,
    pub(super) count: usize,
}

impl FinalizedInactivityScores {
    /// Base decoded from the SSZ `inactivity_scores` byte range (little-endian
    /// `u64`s, `count` of them) over a `cap`-sized buffer; `new(cap, 0, &[])`
    /// is the empty base.
    pub(super) fn new(
        cap: usize,
        count: usize,
        ssz_bytes: &[u8],
    ) -> Result<Self, ColumnLenMismatch> {
        if ssz_bytes.len() != count * 8 {
            return Err(ColumnLenMismatch { bytes: ssz_bytes.len(), expected: count });
        }
        debug_assert!(count <= cap, "inactivity count exceeds capacity");
        let mut data = vec![0u64; cap].into_boxed_slice();
        for (i, s) in data.iter_mut().enumerate().take(count) {
            *s = u64_le(ssz_bytes, i * 8);
        }
        Ok(Self { data, count })
    }

    /// Finalized list length.
    #[inline]
    pub fn count(&self) -> usize {
        self.count
    }

    #[inline]
    pub fn get(&self, i: usize) -> u64 {
        self.data[i]
    }

    /// Fold a fork's edits into the base, then adopt its length — the data half
    /// of finalization.
    pub(super) fn promote(&mut self, delta: &InactivityScoresDelta) {
        for &(idx, v) in delta.edits() {
            self.data[idx as usize] = v;
        }
        self.count = delta.total();
    }
}
