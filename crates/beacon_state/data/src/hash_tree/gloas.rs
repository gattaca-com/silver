use super::{DeltaHashTree, FinalizedHashTree};
use crate::{
    merkle::mix_in_length,
    progressive::{
        PROGRESSIVE_SEGMENT_START, fold_progressive_spine, progressive_segment_of_chunk,
        progressive_segments_for,
    },
    types::B256,
};

#[derive(Default)]
pub struct GloasFinalized {
    segs: Box<[FinalizedHashTree]>,
}

impl GloasFinalized {
    pub fn from_leaf_hashes(
        mut leaves: impl ExactSizeIterator<Item = B256>,
        capacity: usize,
    ) -> Self {
        let capacity = capacity.max(1);
        debug_assert!(leaves.len() <= capacity);
        let last_seg = progressive_segment_of_chunk(capacity - 1) as usize;
        let segs = (0..=last_seg)
            .map(|k| {
                let seg_cap = 1usize << (2 * k);
                FinalizedHashTree::from_leaves(leaves.by_ref().take(seg_cap), seg_cap)
            })
            .collect();
        Self { segs }
    }

    #[inline]
    fn leaf_seg(i: usize) -> (usize, usize) {
        let k = progressive_segment_of_chunk(i) as usize;
        (k, i - PROGRESSIVE_SEGMENT_START[k])
    }

    pub(crate) fn promote_delta(&mut self, winner: &GloasDeltaHashTree) {
        for (seg, delta) in self.segs.iter_mut().zip(&winner.segs) {
            seg.promote_delta(delta);
        }
    }

    pub(crate) fn prune_delta_against(
        &self,
        delta: &mut GloasDeltaHashTree,
        winner: &GloasDeltaHashTree,
    ) {
        for (k, seg) in self.segs.iter().enumerate() {
            seg.prune_delta_against(&mut delta.segs[k], &winner.segs[k]);
        }
    }
}

#[derive(Clone, Default)]
pub struct GloasDeltaHashTree {
    segs: Vec<DeltaHashTree>,
}

impl GloasDeltaHashTree {
    pub fn new_at(finalized: &GloasFinalized) -> Self {
        Self { segs: vec![DeltaHashTree::default(); finalized.segs.len()] }
    }

    #[inline]
    pub fn set_leaf(&mut self, finalized: &GloasFinalized, i: usize, leaf: B256) {
        let (k, local) = GloasFinalized::leaf_seg(i);
        self.segs[k].set_leaf(&finalized.segs[k], local, leaf);
    }

    pub fn set_leaves(&mut self, finalized: &GloasFinalized, sorted: &[(u32, B256)]) {
        debug_assert!(
            sorted.windows(2).all(|w| w[0].0 < w[1].0),
            "set_leaves needs ascending, distinct indices",
        );

        let mut rest = sorted;
        while let Some(&(first, _)) = rest.first() {
            let (k, _) = GloasFinalized::leaf_seg(first as usize);

            let seg_start = PROGRESSIVE_SEGMENT_START[k] as u32;
            let seg_end = PROGRESSIVE_SEGMENT_START[k + 1] as u32;
            let split = rest.partition_point(|(i, _)| *i < seg_end);

            let (in_seg, tail) = rest.split_at(split);
            self.segs[k] = finalized.segs[k].set_delta_leaves(
                &self.segs[k],
                in_seg,
                FinalizedHashTree::root(),
                seg_start,
                seg_start + finalized.segs[k].max_elements() as u32,
            );

            rest = tail;
        }
    }

    pub(crate) fn rebase(&mut self, base: &GloasFinalized, winner: &GloasDeltaHashTree) {
        for (k, seg) in self.segs.iter_mut().enumerate() {
            seg.rebase(&base.segs[k], &winner.segs[k]);
        }
    }

    /// EIP-7916 `hash_tree_root` for the `ProgressiveList` backed by
    /// `finalized` + this delta: spine fold over segment roots
    /// (`Bytes32(0)` above the last populated segment), then the length
    /// mix-in.
    pub fn ssz_list_root(&self, base: &GloasFinalized, len: usize) -> B256 {
        let acc = fold_progressive_spine(progressive_segments_for(len), |k| {
            self.segs[k].root(&base.segs[k])
        });
        mix_in_length(&acc, len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progressive::merkleize_progressive;

    fn leaf(v: u64) -> B256 {
        let mut h = [0xAB; 32];
        h[..8].copy_from_slice(&v.to_le_bytes());
        h
    }

    fn reference_root(leaves: &[B256]) -> B256 {
        mix_in_length(&merkleize_progressive(leaves), leaves.len())
    }

    #[test]
    fn base_root_across_counts() {
        for n in [0usize, 1, 2, 5, 6, 21, 22, 100, 341] {
            let leaves: Vec<_> = (0..n as u64).map(leaf).collect();
            let base = GloasFinalized::from_leaf_hashes(leaves.iter().copied(), n.max(1) + 20);
            let delta = GloasDeltaHashTree::new_at(&base);
            assert_eq!(delta.ssz_list_root(&base, n), reference_root(&leaves), "n={n}");
        }
    }

    #[test]
    fn delta_edits() {
        let mut leaves: Vec<_> = (0..150u64).map(leaf).collect();
        let base = GloasFinalized::from_leaf_hashes(leaves.iter().copied(), 200);
        let mut delta = GloasDeltaHashTree::new_at(&base);

        let edits = [(0u32, leaf(1000)), (4, leaf(1001)), (5, leaf(1002)), (149, leaf(1003))];
        delta.set_leaves(&base, &edits);
        for &(i, h) in &edits {
            leaves[i as usize] = h;
        }
        assert_eq!(delta.ssz_list_root(&base, 150), reference_root(&leaves));

        delta.set_leaf(&base, 30, leaf(2000));
        leaves[30] = leaf(2000);
        assert_eq!(delta.ssz_list_root(&base, 150), reference_root(&leaves));
    }

    #[test]
    fn append_past_populated() {
        let mut leaves: Vec<_> = (0..21u64).map(leaf).collect();
        let base = GloasFinalized::from_leaf_hashes(leaves.iter().copied(), 100);
        let mut delta = GloasDeltaHashTree::new_at(&base);

        // Appends land in the zero region of segment 3.
        delta.set_leaves(&base, &[(21, leaf(500)), (22, leaf(501))]);
        leaves.extend([leaf(500), leaf(501)]);
        assert_eq!(delta.ssz_list_root(&base, 23), reference_root(&leaves));
    }

    #[test]
    fn finalize_keeps_survivor_root() {
        let mut leaves: Vec<_> = (0..90u64).map(leaf).collect();
        let mut base = GloasFinalized::from_leaf_hashes(leaves.iter().copied(), 120);

        let mut winner = GloasDeltaHashTree::new_at(&base);
        winner.set_leaves(&base, &[(2, leaf(300)), (40, leaf(301)), (86, leaf(302))]);

        // Survivor edits overlap the winner at 40 and diverge at 3/70.
        let mut survivor = GloasDeltaHashTree::new_at(&base);
        survivor.set_leaves(&base, &[(3, leaf(400)), (40, leaf(401)), (70, leaf(402))]);
        let survivor_root_before = survivor.ssz_list_root(&base, 90);

        survivor.rebase(&base, &winner);
        base.prune_delta_against(&mut survivor, &winner);
        base.promote_delta(&winner);

        for (i, h) in [(2, leaf(300)), (40, leaf(301)), (86, leaf(302))] {
            leaves[i as usize] = h;
        }
        let fresh = GloasDeltaHashTree::new_at(&base);
        assert_eq!(fresh.ssz_list_root(&base, 90), reference_root(&leaves));
        assert_eq!(survivor.ssz_list_root(&base, 90), survivor_root_before);
    }

    #[test]
    fn fulu_edits_roundtrip() {
        let initial: Vec<B256> = (0..60u64).map(leaf).collect();
        let base = GloasFinalized::from_leaf_hashes(initial.iter().copied(), 80);
        let fulu_base = FinalizedHashTree::from_leaves(initial.iter().copied(), 80);

        let edits = [(1u32, leaf(900)), (17, leaf(901)), (44, leaf(902)), (59, leaf(903))];
        let mut fulu_delta = DeltaHashTree::default();
        fulu_delta.set_leaves(&fulu_base, &edits);

        let mut collected = Vec::new();
        fulu_delta.collect_leaf_edits(0, fulu_base.max_elements() as u32, &mut collected);
        assert_eq!(collected, edits);

        // Synthesized progressive delta reproduces the same list content.
        let mut delta = GloasDeltaHashTree::new_at(&base);
        delta.set_leaves(&base, &collected);
        let mut leaves: Vec<B256> = (0..60u64).map(leaf).collect();
        for &(i, h) in &edits {
            leaves[i as usize] = h;
        }
        assert_eq!(delta.ssz_list_root(&base, 60), reference_root(&leaves));
    }
}
