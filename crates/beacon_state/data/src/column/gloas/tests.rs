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
    let mut g =
        BalancesGroup::new(values.len() + 4, values.len(), &le_bytes(&values), HashFormat::Gloas)
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
    g.finalize(&child_id, &[child_id], |&id| id);
    let mut ssz = Vec::new();
    g.write_ssz(&mut ssz).unwrap();
    assert_eq!(ssz, le_bytes(&expected));
}

fn gloas_group(values: &[u64]) -> BalancesGroup {
    BalancesGroup::new(values.len() + 4, values.len(), &le_bytes(values), HashFormat::Gloas)
        .unwrap()
}

#[test]
fn reorg_rebuilds_scratch_from_pages_across_growth() {
    // Base 30 vals → last_seg 2 (84-value capacity). Fork A grows into
    // segment 3; fork B stays small. A roll whose parent isn't the
    // just-committed fork rebuilds the flat scratch from the parent's paged
    // snapshot — here including a segment-forest shrink (A → B, last_seg
    // 3 → 2) and a regrow (B → A).
    let base: Vec<u64> = (0..30).map(|i| i * 3 + 7).collect();
    let mut g = gloas_group(&base);

    let mut wv = g.roll_fresh();
    wv.set(2, 222);
    let mut b_vals = base.clone();
    b_vals[2] = 222;
    let b = wv.commit();

    // Fork A off the base: the scratch holds B, so this roll rebuilds too.
    let mut wv = g.roll_fresh();
    let mut a_vals = base.clone();
    for i in 30..90u64 {
        let idx = wv.append_empty();
        wv.set(idx, i * 11);
        a_vals.push(i * 11);
    }
    wv.set(0, 1_000);
    a_vals[0] = 1_000;
    assert_progressive(&wv, &a_vals);
    let a = wv.commit();

    // Reorg onto B's chain: shrink rebuild, then a child edit.
    let mut wv = g.roll_from(b);
    assert_progressive(&wv, &b_vals);
    wv.set(29, 9_999);
    let mut c_vals = b_vals.clone();
    c_vals[29] = 9_999;
    let c = wv.commit();

    // Reorg back onto A: regrow rebuild, then extend further.
    let mut wv = g.roll_from(a);
    assert_progressive(&wv, &a_vals);
    let idx = wv.append_empty();
    wv.set(idx, 555);
    let mut d_vals = a_vals.clone();
    d_vals.push(555);
    let d = wv.commit();

    // No committed snapshot was disturbed by the scratch rebuilds.
    assert_eq!(g.view(a).hash_root(), progressive_u64_root(&a_vals));
    assert_eq!(g.view(c).hash_root(), progressive_u64_root(&c_vals));
    assert_eq!(g.view(d).hash_root(), progressive_u64_root(&d_vals));

    // The grown side wins. Freeing the non-survivors (a shares most of its
    // pages with winner d) must not free pages d and c still reference.
    g.finalize(&d, &[d, c], |&id| id);
    let mut ssz = Vec::new();
    g.write_ssz(&mut ssz).unwrap();
    assert_eq!(ssz, le_bytes(&d_vals));
    assert_eq!(g.view(c).hash_root(), progressive_u64_root(&c_vals));
}

#[test]
fn abandoned_add_at_batch_does_not_leak_into_next_fork() {
    // A failed apply can drop the write view between add_at and rehash.
    // The stale dirty ids must not survive the next roll: after a reorg
    // onto a fork with a smaller segment forest they would index past it
    // in rehash.
    let base: Vec<u64> = (0..30).collect();
    let mut g = gloas_group(&base);

    let mut wv = g.roll_fresh();
    wv.set(1, 11);
    let mut b_vals = base.clone();
    b_vals[1] = 11;
    let b = wv.commit();

    // Grown fork abandoned mid-batch: add_at recorded, never rehashed.
    let mut wv = g.roll_fresh();
    for i in 30..90 {
        let idx = wv.append_empty();
        wv.set(idx, i);
    }
    wv.add_at(88, 5); // dirty chunk 22 — segment 3 of the grown forest
    drop(wv);

    // Reorg roll onto the small fork: the rebuilt scratch has no segment 3.
    let mut wv = g.roll_from(b);
    wv.add_at(0, 100);
    wv.rehash();
    b_vals[0] += 100;
    assert_progressive(&wv, &b_vals);
}

#[test]
fn abandoned_roll_slot_released_once() {
    use crate::types::SLOTS_RING_N;

    let base: Vec<u64> = (0..10).collect();
    let mut g = gloas_group(&base);

    // Go around the ring more than once so slots get reused.
    let mut head = g.roll_fresh().commit();
    for i in 0..SLOTS_RING_N + 8 {
        if i == SLOTS_RING_N + 4 {
            // An invalid block: the write view is dropped, never committed.
            drop(g.roll_from(head));
        }
        let mut wv = g.roll_from(head);
        wv.set(0, i as u64);
        let id = wv.commit();
        g.finalize(&id, &[id], |&id| id);
        head = id;
    }
    assert_eq!(g.view(head).get(0), (SLOTS_RING_N + 7) as u64);
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
