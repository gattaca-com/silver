use super::delta::ParticipationDelta;
use crate::ColumnLenMismatch;

/// Finalized base for an `epoch_participation: List[ParticipationFlags,
/// VALIDATOR_REGISTRY_LIMIT]` column (previous or current). Sized to validator
/// capacity; `count` is the finalized length, kept lockstep with the registry.
pub struct FinalizedParticipation {
    pub(super) data: Box<[u8]>,
    pub(super) count: usize,
}

impl FinalizedParticipation {
    /// Base decoded from the SSZ participation byte range (one flag byte per
    /// validator, `count` of them) over a `cap`-sized buffer; `new(cap, 0,
    /// &[])` is the empty base.
    pub(super) fn new(
        cap: usize,
        count: usize,
        ssz_bytes: &[u8],
    ) -> Result<Self, ColumnLenMismatch> {
        if ssz_bytes.len() != count {
            return Err(ColumnLenMismatch { bytes: ssz_bytes.len(), expected: count });
        }
        debug_assert!(count <= cap, "participation count exceeds capacity");
        let mut data = vec![0u8; cap].into_boxed_slice();
        data[..count].copy_from_slice(ssz_bytes);
        Ok(Self { data, count })
    }

    /// Finalized list length.
    #[inline]
    pub fn count(&self) -> usize {
        self.count
    }

    #[inline]
    pub fn get(&self, i: usize) -> u8 {
        self.data[i]
    }

    /// Fold a fork's edits into the base, then adopt its length.
    pub(super) fn promote(&mut self, delta: &ParticipationDelta) {
        for &(idx, v) in delta.edits() {
            self.data[idx as usize] = v;
        }
        self.count = delta.total();
    }
}
