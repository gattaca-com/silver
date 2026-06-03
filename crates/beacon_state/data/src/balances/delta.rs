use super::{finalized::FinalizedBalances, pack_chunk};
use crate::{
    buffer::Reset,
    hash_tree::DeltaHashTree,
    sparse::Edits,
    types::{B256, VALIDATOR_REGISTRY_LIMIT},
};

/// Per-fork sparse delta over [`FinalizedBalances`]. Sorted `(idx, value)`
/// edits; an index past `base_count` with no edit reads the spec default `0`.
/// `hash_overlay` mirrors the edits as a persistent overlay on the base's
/// packed-chunk hash tree, so the list root is recomputed from cached subtree
/// hashes rather than re-merkleized from scratch.
#[derive(Default, Clone)]
pub struct BalancesDelta {
    pub edits: Edits<u64>,
    pub hash_overlay: DeltaHashTree,
}

impl BalancesDelta {
    #[inline]
    pub fn effective_balance(&self, base: &FinalizedBalances, base_count: usize, ix: usize) -> u64 {
        if let Some(v) =
            self.edits.binary_search_by_key(&(ix as u32), |(k, _)| *k).ok().map(|p| self.edits[p].1)
        {
            return v;
        }
        if ix < base_count { base.data[ix] } else { 0 }
    }

    pub fn iter<'b>(
        &'b self,
        base: &'b FinalizedBalances,
        base_count: usize,
        total: usize,
    ) -> impl Iterator<Item = u64> + 'b {
        let edits: &[(u32, u64)] = &self.edits;
        let base = &base.data[..base_count];
        let mut cursor = 0usize;
        (0..total).map(move |i| {
            if cursor < edits.len() && edits[cursor].0 as usize == i {
                let v = edits[cursor].1;
                cursor += 1;
                v
            } else if i < base.len() {
                base[i]
            } else {
                0
            }
        })
    }

    #[inline]
    pub fn set(&mut self, base: &FinalizedBalances, idx: u32, v: u64) {
        self.set_many(base, &[(idx, v)]);
    }

    pub fn set_many(&mut self, base: &FinalizedBalances, changes: &[(u32, u64)]) {
        debug_assert!(
            changes.windows(2).all(|w| w[0].0 < w[1].0),
            "set_many input must be ascending with distinct indices",
        );
        self.edits.merge_in_place(changes);

        for group in changes.chunk_by(|a, b| a.0 / 4 == b.0 / 4) {
            self.recompute_chunk(base, group[0].0 / 4);
        }
    }

    #[inline]
    pub fn list_root(&self, base: &FinalizedBalances, total: usize) -> B256 {
        const CHUNK_DEPTH: u32 = (VALIDATOR_REGISTRY_LIMIT / 4).trailing_zeros();
        base.hash.ssz_list_root(&self.hash_overlay, CHUNK_DEPTH, total)
    }

    /// Fold this delta into `base`: edits into `data`, then promote the hash
    /// overlay's cached hashes into the base tree (zero SHA).
    pub fn promote_into_base(&self, base: &mut FinalizedBalances) {
        base.apply_edits(&self.edits);
        base.hash.promote_delta(&self.hash_overlay);
    }

    pub fn prune_to_base(&mut self, base: &FinalizedBalances, new_base_count: usize) {
        self.edits
            .retain(|(idx, v)| (*idx as usize) >= new_base_count || base.data[*idx as usize] != *v);
        base.hash.prune_delta(&mut self.hash_overlay);
    }

    fn recompute_chunk(&mut self, base: &FinalizedBalances, chunk: u32) {
        let b = (chunk * 4) as usize;
        let mut vals = [base.data[b], base.data[b + 1], base.data[b + 2], base.data[b + 3]];

        let start = self.edits.partition_point(|(k, _)| (*k as usize) < b);
        for &(k, v) in self.edits[start..].iter().take_while(|(k, _)| (*k as usize) < b + 4) {
            vals[k as usize - b] = v;
        }
        base.hash.set_delta_leaf(&mut self.hash_overlay, chunk as usize, pack_chunk(vals));
    }
}

impl Reset for BalancesDelta {
    fn reset(&mut self) {
        self.edits.clear();
        self.hash_overlay = DeltaHashTree::default();
    }
    fn reset_from(&mut self, other: &Self) {
        self.edits.clone_from(&other.edits);
        self.hash_overlay = other.hash_overlay.clone();
    }
}
