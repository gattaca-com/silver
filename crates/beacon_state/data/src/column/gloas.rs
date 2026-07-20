use silver_ssz::scalar::SszScalar;

use super::{
    format::{SEG_OFF, TreeFormat, gloas_last_seg_for_chunks},
    fulu::FuluTree,
    store::NodeStore,
    subtree::{build_subtree_hashes, rehash_subtree},
};
use crate::{
    merkle::ZERO_HASHES,
    progressive::{PROGRESSIVE_SEGMENT_START, progressive_segment_of_chunk},
    types::B256,
};

pub(super) struct GloasTree {
    pub(super) store: NodeStore,
    pub(super) last_seg: u32,
}

impl GloasTree {
    pub(super) fn from_leaves<V: SszScalar>(cap: usize, count: usize, ssz_bytes: &[u8]) -> Self {
        debug_assert_eq!(ssz_bytes.len(), count * size_of::<V>());
        let last_seg = gloas_last_seg_for_chunks(cap.div_ceil(V::VALS_PER_CHUNK).max(1));
        let format = TreeFormat::Gloas { last_seg };
        let store =
            NodeStore::with_leaves(format.num_nodes(), count, format.data_start(), ssz_bytes);
        let mut tree = Self { store, last_seg };
        tree.rebuild_segments(count.div_ceil(V::VALS_PER_CHUNK));
        tree
    }

    fn rebuild_segments(&mut self, non_zero_chunks: usize) {
        let data_start = self.format().data_start();
        let (internals, data) = self.store.nodes.split_at_mut(data_start);
        for k in 0..=self.last_seg as usize {
            build_segment(internals, data, k, non_zero_chunks);
        }
    }

    pub(super) fn from_fulu<V: SszScalar>(fulu: &FuluTree) -> Self {
        debug_assert!(fulu.store.dirty_chunks.is_empty(), "unhashed batch pending at migration",);
        let count = fulu.store.count;
        let leaf_bytes =
            &fulu.store.nodes[fulu.max_elements..].as_flattened()[..count * size_of::<V>()];
        let mut tree =
            Self::from_leaves::<V>(fulu.max_elements * V::VALS_PER_CHUNK, count, leaf_bytes);
        tree.store.mark_all_dirty();
        tree
    }

    #[inline]
    pub(super) fn format(&self) -> TreeFormat {
        TreeFormat::Gloas { last_seg: self.last_seg }
    }

    pub(super) fn rehash(&mut self) {
        let data_start = self.format().data_start();
        let NodeStore { nodes, dirty_chunks, .. } = &mut self.store;
        let (internals, data) = nodes.split_at_mut(data_start);
        let mut start = 0;
        while start < dirty_chunks.len() {
            let k = progressive_segment_of_chunk(dirty_chunks[start] as usize) as usize;
            let seg_start = PROGRESSIVE_SEGMENT_START[k];
            let end = start +
                dirty_chunks[start..]
                    .partition_point(|&c| (c as usize) < PROGRESSIVE_SEGMENT_START[k + 1]);

            for c in &mut dirty_chunks[start..end] {
                *c -= seg_start as u32;
            }
            rehash_subtree(
                &mut internals[SEG_OFF[k]..SEG_OFF[k] + (1 << (2 * k))],
                &data[seg_start..],
                &mut dirty_chunks[start..end],
            );
            start = end;
        }
        dirty_chunks.clear();
    }

    pub(super) fn fill_zero(&mut self) {
        let data_start = self.format().data_start();
        self.store.nodes[data_start..].fill(ZERO_HASHES[0]);
        self.rebuild_segments(0);
    }

    pub(super) fn append_progressive_segment(&mut self) {
        let old = self.format();
        self.last_seg += 1;
        let new = self.format();

        self.store.nodes.resize(new.num_nodes(), [0u8; 32]);
        self.store.nodes.copy_within(
            old.data_start()..old.data_start() + old.data_capacity(),
            new.data_start(),
        );

        let (internals, data) = self.store.nodes.split_at_mut(new.data_start());
        build_segment(internals, data, self.last_seg as usize, 0);
        self.store.mark_all_dirty();
    }
}

fn build_segment(internals: &mut [B256], data: &[B256], k: usize, non_zero_chunks: usize) {
    let seg_chunks = 1usize << (2 * k);
    let seg_start = PROGRESSIVE_SEGMENT_START[k];
    let non_zero = non_zero_chunks.saturating_sub(seg_start).min(seg_chunks);
    build_subtree_hashes(
        &mut internals[SEG_OFF[k]..SEG_OFF[k] + seg_chunks],
        &data[seg_start..],
        non_zero,
    );
}

#[cfg(test)]
mod tests {
    use silver_ssz::scalar::SszScalar;

    use super::super::{
        BalancesGroup, BalancesWriteView, ColumnGroup, Previous,
        tests::{group, le_bytes},
    };
    use crate::{
        merkle::{MerkleStack, hash_uint64_list, mix_in_length, pack_byte_chunks},
        progressive::ProgressiveHasher,
        types::{B256, HashFormat, VALIDATOR_REGISTRY_LIMIT},
    };

    fn progressive_u64_root(vals: &[u64]) -> B256 {
        hash_uint64_list(ProgressiveHasher::new(), &SszScalar::as_ssz_bytes(vals), vals.len())
    }

    fn fulu_u64_root(vals: &[u64]) -> B256 {
        hash_uint64_list(
            MerkleStack::new(VALIDATOR_REGISTRY_LIMIT.div_ceil(4)),
            &SszScalar::as_ssz_bytes(vals),
            vals.len(),
        )
    }

    fn progressive_u8_root(vals: &[u8]) -> B256 {
        let mut hasher = ProgressiveHasher::new();
        pack_byte_chunks(vals, |c| hasher.push_chunk(c));
        mix_in_length(&hasher.finalize(), vals.len())
    }

    fn assert_progressive(wv: &BalancesWriteView<'_>, expected: &[u64]) {
        assert_eq!(wv.iter().collect::<Vec<_>>(), expected);
        assert_eq!(wv.hash_root(), progressive_u64_root(expected));
    }

    #[test]
    fn migrate_across_counts() {
        // Segment boundaries (u64, 4 vals/chunk) fall at value indices 4, 20, 84;
        // migrate at each boundary and its neighbours, plus a partial-tail count.
        for n in [1usize, 4, 5, 20, 21, 84, 85, 333] {
            let values: Vec<u64> = (0..n as u64).map(|i| i * 7 + 1).collect();
            let mut g = group(&values);
            let mut wv = g.roll_fresh();

            assert_eq!(wv.hash_root(), fulu_u64_root(&values));
            wv.migrate_to_gloas();
            assert_progressive(&wv, &values);
            assert_eq!(wv.get(n - 1), values[n - 1]);
        }
    }

    #[test]
    fn rehash_matches_full_rebuild() {
        let mut values: Vec<u64> = (0..333).collect();
        let mut g = group(&values);
        let mut wv = g.roll_fresh();
        wv.migrate_to_gloas();

        // Sparse set_many landing in every segment: chunk-0 root-leaf (seg 0),
        // seg 1 (idx 17), seg 2 (idx 50), seg 3 (idx 100/332).
        let edits = [(0u32, 1_000u64), (3, 42), (17, 5), (50, 8), (100, 9), (332, 77)];
        wv.set_many(&edits);
        for &(i, v) in &edits {
            values[i as usize] = v;
        }
        assert_progressive(&wv, &values);

        // add_at deltas across segments need an explicit rehash.
        wv.add_at(2, 123);
        wv.add_at(2, -3);
        wv.add_at(200, 55);
        wv.rehash();
        values[2] += 123 - 3;
        values[200] += 55;
        assert_progressive(&wv, &values);
    }

    #[test]
    fn rehash_unsorted_scrambled_add_at() {
        let mut values: Vec<u64> = (0..333).collect();
        let mut g = group(&values);
        let mut wv = g.roll_fresh();
        wv.migrate_to_gloas();

        // Deltas out of index order across segments, with a repeated leaf (idx 3);
        // rehash_unsorted sorts the dirty ids before the per-segment rehash.
        wv.add_at(200, 5); // seg 3
        wv.add_at(3, 100); // seg 0
        wv.add_at(60, -1); // seg 2
        wv.add_at(3, 3); // second hit on the same leaf
        wv.add_at(17, 7); // seg 1
        wv.rehash_unsorted();

        values[200] += 5;
        values[3] += 103;
        values[60] -= 1;
        values[17] += 7;
        assert_progressive(&wv, &values);
    }

    #[test]
    fn random_batches_match_reference() {
        use rand::{Rng, SeedableRng, rngs::StdRng, seq::SliceRandom};

        // Random sparse batches over the migrated tree, spanning up to segment 4.
        let mut rng = StdRng::seed_from_u64(0x6104);
        for n in [7usize, 64, 500] {
            let mut values: Vec<u64> = (0..n).map(|_| rng.gen_range(0..=u64::MAX)).collect();
            let mut g = group(&values);
            let mut wv = g.roll_fresh();
            wv.migrate_to_gloas();
            assert_progressive(&wv, &values);

            for _ in 0..8 {
                let count = rng.gen_range(1..=n);
                let mut idxs: Vec<u32> = (0..n as u32).collect();
                idxs.shuffle(&mut rng);
                idxs.truncate(count);
                idxs.sort_unstable();
                let batch: Vec<(u32, u64)> =
                    idxs.iter().map(|&i| (i, rng.gen_range(0..=u64::MAX))).collect();
                for &(i, v) in &batch {
                    values[i as usize] = v;
                }
                wv.set_many(&batch);
                assert_progressive(&wv, &values);
            }
        }
    }

    #[test]
    fn append_grows_segments() {
        let values: Vec<u64> = (0..16).collect();
        let mut g = group(&values); // fulu cap 20 vals -> 5 chunks, seg 1
        let mut wv = g.roll_fresh();
        wv.migrate_to_gloas();

        // Append past the migrated capacity: seg 1 -> 2 -> 3, no rebuild of existing.
        for i in 16..120u64 {
            let idx = wv.append_empty();
            wv.set(idx, i);
        }
        assert_progressive(&wv, &(0..120).collect::<Vec<_>>());
    }

    #[test]
    fn direct_gloas_construction() {
        let values: Vec<u64> = (0..100).map(|i| i * 7 + 1).collect();
        let mut g = BalancesGroup::new(
            values.len() + 4,
            values.len(),
            &le_bytes(&values),
            HashFormat::Gloas,
        )
        .unwrap();

        let mut wv = g.roll_fresh();
        assert_progressive(&wv, &values);

        wv.set(3, 999);
        let id = wv.commit();
        let mut updated = values.clone();
        updated[3] = 999;
        assert_eq!(g.view(id).hash_root(), progressive_u64_root(&updated));
    }

    #[test]
    fn mixed_formats_coexist() {
        let values: Vec<u64> = (0..50).map(|i| i + 10).collect();
        let mut g = group(&values);

        let fulu_id = g.roll_fresh().commit();

        let mut wv = g.roll_from(fulu_id);
        wv.migrate_to_gloas();
        wv.set(7, 777);
        let gloas_id = wv.commit();

        let mut expected = values.clone();
        expected[7] = 777;
        assert_eq!(g.view(fulu_id).hash_root(), fulu_u64_root(&values));
        assert_eq!(g.view(gloas_id).hash_root(), progressive_u64_root(&expected));
        assert_eq!(g.view(gloas_id).get(7), 777);

        // A child of the gloas fork shares its clean pages.
        let mut wv = g.roll_from(gloas_id);
        wv.set(30, 1);
        let child_id = wv.commit();
        expected[30] = 1;
        assert_eq!(g.view(child_id).hash_root(), progressive_u64_root(&expected));

        // Finalizing the gloas winner flips the base format by data flow.
        g.finalize(child_id, &[child_id]);
        let mut ssz = Vec::new();
        g.write_ssz(&mut ssz).unwrap();
        assert_eq!(ssz, le_bytes(&expected));
    }

    #[test]
    fn clear_to_zero() {
        let values: Vec<u64> = (0..90).map(|i| i + 1).collect();
        let mut g = group(&values);
        let mut wv = g.roll_fresh();
        wv.migrate_to_gloas();
        wv.clear_to_zero();
        assert_progressive(&wv, &vec![0; values.len()]);
    }

    #[test]
    fn u8_column_migrate_and_rehash() {
        let values: Vec<u8> = (0..77u8).collect();
        let mut g =
            ColumnGroup::<Previous>::new(values.len() + 4, values.len(), &values, HashFormat::Fulu)
                .unwrap();
        let mut wv = g.roll_fresh();
        wv.migrate_to_gloas();
        assert_eq!(wv.hash_root(), progressive_u8_root(&values));

        wv.set_many(&[(0, 7u8), (40, 9)]);
        let mut updated = values.clone();
        updated[0] = 7;
        updated[40] = 9;
        assert_eq!(wv.iter().collect::<Vec<_>>(), updated);
        assert_eq!(wv.hash_root(), progressive_u8_root(&updated));
    }
}
