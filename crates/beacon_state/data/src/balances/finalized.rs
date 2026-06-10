use crate::{ColumnLenMismatch, decompose::u64_le, hash_tree::FinalizedHashTree, sparse::Edits};

/// Balances of validators: values plus the packed-chunk merkle tree over them.
/// `count` is the finalized validator count (the live length lives on the
/// per-fork delta), mirroring `FinalizedValidators::validator_count`.
pub struct FinalizedBalances {
    pub(super) data: Box<[u64]>,
    pub(super) hash: FinalizedHashTree,
    pub(super) count: usize,
}

impl FinalizedBalances {
    /// Base decoded from the SSZ `balances` byte range (little-endian `u64`s,
    /// `count` of them), plus the packed-chunk merkle tree over it;
    /// `new(cap, 0, &[])` is the empty base.
    pub(super) fn new(
        cap: usize,
        count: usize,
        ssz_bytes: &[u8],
    ) -> Result<Self, ColumnLenMismatch> {
        if ssz_bytes.len() != count * 8 {
            return Err(ColumnLenMismatch { bytes: ssz_bytes.len(), expected: count });
        }
        let cap = cap.next_multiple_of(4);
        debug_assert!(count <= cap, "balances exceed capacity");

        let mut data = vec![0u64; cap].into_boxed_slice();
        for (i, slot) in data.iter_mut().enumerate().take(count) {
            *slot = u64_le(ssz_bytes, i * 8);
        }

        let hash = FinalizedHashTree::from_leaves(
            ssz_bytes.chunks(32).map(|src| {
                let mut leaf = [0u8; 32];
                leaf[..src.len()].copy_from_slice(src);
                leaf
            }),
            data.len() / 4,
        );
        Ok(Self { data, hash, count })
    }

    /// Finalized validator count.
    #[inline]
    pub fn count(&self) -> usize {
        self.count
    }

    pub(super) fn apply_edits(&mut self, edits: &Edits<u64>) {
        for &(idx, val) in edits.iter() {
            self.data[idx as usize] = val;
        }
    }
}
