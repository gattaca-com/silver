use super::pack_chunk;
use crate::{
    decompose::{DecomposeError, u64_le},
    hash_tree::FinalizedHashTree,
    types::B256,
};

/// Balances of validators
pub struct FinalizedBalances {
    pub(super) data: Box<[u64]>,
    pub(super) hash: FinalizedHashTree,
}

impl FinalizedBalances {
    pub fn with_seed_balances(cap: usize, balances: &[u64]) -> Self {
        let cap = cap.next_multiple_of(4);
        debug_assert!(balances.len() <= cap, "balances seed exceeds capacity");

        let mut data = vec![0u64; cap].into_boxed_slice();
        data[..balances.len()].copy_from_slice(balances);

        Self::from_parts(
            data,
            balances.chunks(4).map(|c| {
                let mut vals = [0u64; 4];
                vals[..c.len()].copy_from_slice(c);
                pack_chunk(vals)
            }),
        )
    }

    pub(crate) fn from_ssz(cap: usize, bytes: &[u8], n: usize) -> Result<Self, DecomposeError> {
        if !bytes.len().is_multiple_of(8) || bytes.len() / 8 != n {
            return Err(DecomposeError::BalancesLenMismatch { bytes: bytes.len(), validators: n });
        }

        let cap = cap.next_multiple_of(4);
        debug_assert!(n <= cap, "balances ssz exceeds capacity");

        let mut data = vec![0u64; cap].into_boxed_slice();
        for (i, slot) in data.iter_mut().enumerate().take(n) {
            *slot = u64_le(bytes, i * 8);
        }

        Ok(Self::from_parts(
            data,
            bytes.chunks(32).map(|src| {
                let mut leaf = [0u8; 32];
                leaf[..src.len()].copy_from_slice(src);
                leaf
            }),
        ))
    }

    fn from_parts(data: Box<[u64]>, leaves: impl ExactSizeIterator<Item = B256>) -> Self {
        let hash = FinalizedHashTree::from_leaves(leaves, data.len() / 4);
        Self { data, hash }
    }

    pub(super) fn apply_edits(&mut self, edits: &[(u32, u64)]) {
        for &(idx, val) in edits {
            self.data[idx as usize] = val;
        }
    }
}
