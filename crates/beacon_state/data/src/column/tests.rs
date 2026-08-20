use super::{
    BalancesGroup, BalancesWriteView, BlockRootsGroup, ColumnGroup, ColumnSpec, RandaoMixesGroup,
};
use crate::{
    merkle::{MerkleStack, hash_b256_vector, hash_uint64_list, hash_uint64_vector},
    types::{
        B256, EPOCHS_PER_HISTORICAL_VECTOR, HashFormat, SLOTS_PER_HISTORICAL_ROOT,
        VALIDATOR_REGISTRY_LIMIT,
    },
};

/// `Vector[uint64, 8192]` — covers the vector root path (fixed depth, no
/// length mix-in) independently of the production columns.
struct U64Vector;
impl ColumnSpec for U64Vector {
    type Val = u64;
    type Page = [B256; 32];
    const SSZ_LIMIT: usize = 8192;
    const IS_LIST: bool = false;
}

fn vector_group(values: &[u64]) -> ColumnGroup<U64Vector> {
    ColumnGroup::new(values.len(), values.len(), &le_bytes(values), HashFormat::Fixed).unwrap()
}

pub(super) fn le_bytes(values: &[u64]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}

pub(super) fn group(values: &[u64]) -> BalancesGroup {
    BalancesGroup::new(values.len().max(1) + 4, values.len(), &le_bytes(values), HashFormat::Fixed)
        .unwrap()
}

fn assert_root_matches(wv: &BalancesWriteView<'_>) {
    let vals: Vec<u64> = wv.iter().collect();
    let want = hash_uint64_list(
        MerkleStack::new(VALIDATOR_REGISTRY_LIMIT.div_ceil(4)),
        &le_bytes(&vals),
        vals.len(),
    );
    assert_eq!(wv.hash_root(), want);
}

#[test]
fn effective_balance_edit_then_base_then_default() {
    let mut g = group(&[1_000, 2_000]);
    let mut wv = g.roll_fresh();

    assert_eq!(wv.get(0), 1_000);
    assert_eq!(wv.get(5), 0);
    wv.set(0, 2_500);
    assert_eq!(wv.get(0), 2_500);
}

#[test]
fn iter_merges_edits_over_base() {
    let mut g = group(&[0, 100, 200, 300, 400]);
    let mut wv = g.roll_fresh();

    wv.set(1, 999);
    wv.set(3, 333);
    assert_eq!(wv.iter().collect::<Vec<_>>(), vec![0, 999, 200, 333, 400]);
}

#[test]
fn set_inserts_then_updates() {
    let mut g = group(&[1_000, 1_000, 1_000]);
    let mut wv = g.roll_fresh();

    wv.set(2, 2_500);
    assert_eq!(wv.get(2), 2_500);

    wv.set(0, 4_000);
    assert_eq!(wv.get(0), 4_000);

    wv.set(0, 5_000); // a second write to the same index replaces, not stacks
    assert_eq!(wv.get(0), 5_000);

    wv.set(0, 1_000); // back to the base value — reads as the base value
    assert_eq!(wv.get(0), 1_000);

    assert_root_matches(&wv);
}

#[test]
fn set_many_applies_sparse_changes() {
    let mut g = group(&[0, 10, 20, 30]);
    let mut wv = g.roll_fresh();

    wv.set_many(&[(1, 1010), (3, 1030)]);
    // only 1 and 3 change; 0 and 2 still read the base.
    assert_eq!(wv.iter().collect::<Vec<_>>(), vec![0, 1010, 20, 1030]);
    assert_root_matches(&wv);
}

#[test]
fn add_at_batch_then_rehash() {
    // 9 values spans 3 chunks (4 u64 lanes each), with a partial tail chunk.
    let mut g = group(&[0, 10, 20, 30, 40, 50, 60, 70, 80]);
    let mut wv = g.roll_fresh();

    wv.add_at(0, 5);
    wv.add_at(1, -3);
    wv.add_at(2, -25); // saturates at 0
    wv.add_at(4, 0); // no-op, must not dirty
    wv.add_at(5, 1);
    wv.add_at(8, i64::MAX); // tail chunk
    wv.rehash();

    assert_eq!(wv.iter().collect::<Vec<_>>(), vec![
        5,
        7,
        0,
        30,
        40,
        51,
        60,
        70,
        80 + i64::MAX as u64
    ],);
    assert_root_matches(&wv);

    // A later set_many batch on the rehashed tree stays consistent.
    wv.set_many(&[(3, 333)]);
    assert_eq!(wv.get(3), 333);
    assert_root_matches(&wv);
}

#[test]
fn add_at_unsorted_then_rehash_unsorted() {
    // Deltas applied out of index order, with a repeated index (7): the RMW is
    // sequential in call order, and rehash_unsorted sorts the dirty leaves.
    let mut g = group(&[0, 10, 20, 30, 40, 50, 60, 70, 80]);
    let mut wv = g.roll_fresh();

    wv.add_at(8, 1);
    wv.add_at(0, 100);
    wv.add_at(7, -5); // 65
    wv.add_at(3, 2);
    wv.add_at(7, 3); // 65 + 3 = 68, second hit on the same leaf
    wv.rehash_unsorted();

    assert_eq!(wv.iter().collect::<Vec<_>>(), vec![100, 10, 20, 32, 40, 50, 60, 68, 81],);
    assert_root_matches(&wv);
}

#[test]
fn set_many_keeps_prior_writes() {
    let mut g = group(&[10, 20, 30]);
    let mut wv = g.roll_fresh();

    // Three validators join (idx 3,4,5 at default 0), then writes land.
    wv.append_empty();
    wv.append_empty();
    wv.append_empty();
    wv.set(0, 111);
    wv.set_many(&[(1, 99), (5, 7)]);
    // idx 0's earlier write survives; 1 and 5 applied; 2 reads base, 3/4 default.
    assert_eq!(wv.iter().collect::<Vec<_>>(), vec![111, 99, 30, 0, 0, 7]);
    assert_root_matches(&wv);
}

#[test]
fn finalize_preserves_survivor_reads_and_root() {
    // Winner has two appended validators and a base-equal edit; finalizing it
    // copies its whole tree into the base. The survivor is a standalone tree —
    // its id and contents are unchanged.
    let mut g = group(&[1_000, 2_000]);

    let mut wv = g.roll_fresh();
    wv.append_empty(); // idx 2
    wv.append_empty(); // idx 3
    wv.set(0, 1_000); // equals base[0]
    wv.set(1, 5_000);
    wv.set(3, 7_000);
    let before = wv.hash_root();
    let winner = wv.commit();

    let survivor = g.roll_from(winner).commit(); // inherits the winner's state
    g.finalize(&winner, &[winner, survivor], |&id| id); // ids stay valid unchanged

    let wv = g.roll_from(survivor);
    assert_eq!(wv.iter().collect::<Vec<_>>(), vec![1_000, 5_000, 0, 7_000]);
    assert_eq!(wv.hash_root(), before);
}

#[test]
fn finalize_returns_survivor_ids_unchanged() {
    // Sibling forks can share a column slot, so the same survivor id can appear
    // more than once. finalize is a base copy + free with no re-anchor, so it
    // returns the survivor ids verbatim (duplicates preserved).
    let mut g = group(&[10, 20, 30]);

    let mut wv = g.roll_fresh();
    wv.set(0, 111);
    let winner = wv.commit();

    let shared = g.roll_from(winner).commit();
    let other = g.roll_from(winner).commit();

    g.finalize(&winner, &[winner, shared, shared, other], |&id| id);

    // Every survivor still reads the finalized state (through fresh forks).
    assert_eq!(g.roll_from(shared).iter().collect::<Vec<_>>(), vec![111, 20, 30]);
    assert_eq!(g.roll_from(other).iter().collect::<Vec<_>>(), vec![111, 20, 30]);
}

#[test]
fn new_decodes_le_u64s() {
    let mut g = BalancesGroup::new(4, 3, &le_bytes(&[7, 8, 9]), HashFormat::Fixed).unwrap();
    let wv = g.roll_fresh();

    assert_eq!([wv.get(0), wv.get(1), wv.get(2)], [7, 8, 9]);
    assert_root_matches(&wv);
}

#[test]
fn new_rejects_len_mismatch() {
    assert!(BalancesGroup::new(4, 2, &[0u8; 12], HashFormat::Fixed).is_err());
}

#[test]
fn root_matches_reference_across_counts() {
    // Empty, partial trailing chunk, exact multiple of 4, and beyond.
    for n in [0usize, 1, 3, 4, 5, 8, 13] {
        let values: Vec<u64> = (0..n as u64).map(|i| (i + 1) * 1_000).collect();
        let mut g = group(&values);
        assert_root_matches(&g.roll_fresh());
    }
}

#[test]
fn root_reflects_edits_and_appends() {
    let mut g = group(&[10, 20, 30, 40, 50]);
    let mut wv = g.roll_fresh();

    wv.set(1, 999); // base edit
    wv.append_empty(); // idx 5
    let idx = wv.append_empty(); // idx 6 — appended validator, balance set to 7
    wv.set(idx, 7);
    assert_root_matches(&wv);

    // Setting an appended balance back to 0 (its default) re-collapses the leaf.
    wv.set(6, 0);
    assert_root_matches(&wv);
}

#[test]
fn promote_reproduces_root_over_new_base() {
    let mut g = group(&[10, 20, 30, 40, 50]);

    let mut wv = g.roll_fresh();
    wv.set(1, 999);
    wv.set(4, 4_444);
    let pre = wv.hash_root();
    let s = wv.commit();

    // Finalize promotes the fork's overlay into the base.
    g.finalize(&s, &[s], |&id| id);

    // A fresh fork over the promoted base reproduces the same root with zero SHA
    // work (cached-hash promote) and reads the promoted values.
    let wv = g.roll_fresh();
    assert_eq!(wv.hash_root(), pre);
    assert_root_matches(&wv);
    assert_eq!(wv.get(1), 999);
    assert_eq!(wv.get(4), 4_444);
}

#[test]
fn aba_finalize_keeps_reverted_value() {
    // base[0]=C; D1(0=A) ← D2(0=B) ← D3(0=A reverted). Finalizing D1 then D2 must
    // leave D3's view of idx 0 at A across both base swaps (the classic ABA
    // hazard). Standalone per-fork trees read nothing through the base, so D3
    // keeps its own A with no rebase needed.
    const C: u64 = 1_000;
    const A: u64 = 2_000;
    const B: u64 = 3_000;
    let mut g = group(&[C, C, C, C]);

    let mut wv1 = g.roll_fresh();
    wv1.set(0, A);
    let s1 = wv1.commit(); // ends wv1's borrow, so the next roll can take `&mut g`
    let mut wv2 = g.roll_from(s1);
    wv2.set(0, B);
    let s2 = wv2.commit();
    let mut wv3 = g.roll_from(s2);
    wv3.set(0, A);
    let s3 = wv3.commit();

    // Finalize D1 (winner s1): base[0] → A. Ids are unchanged.
    g.finalize(&s1, &[s1, s2, s3], |&id| id);
    assert_eq!(g.roll_from(s3).get(0), A);

    // Finalize D2 (winner s2): base[0] → B; D3's own tree still holds A.
    g.finalize(&s2, &[s2, s3], |&id| id);
    let wv3 = g.roll_from(s3);
    assert_eq!(wv3.get(0), A, "D3 must not inherit B");
    assert_root_matches(&wv3);
}

#[test]
fn append_within_cap_headroom() {
    // Appends stay inside the leaf row sized from the headroomed cap; reads and
    // root track the appended values.
    let mut g = BalancesGroup::new(16, 1, &le_bytes(&[5]), HashFormat::Fixed).unwrap();
    let mut wv = g.roll_fresh();
    for v in [6, 7, 8, 9, 10] {
        let idx = wv.append_empty();
        wv.set(idx, v);
    }
    assert_eq!(wv.iter().collect::<Vec<_>>(), vec![5, 6, 7, 8, 9, 10]);
    assert_root_matches(&wv);
}

#[test]
fn edits_across_commits_under_shared_parent() {
    // Two sibling leaf chunks (0 and 1) share a parent one level up. Editing
    // them in separate set_many calls must recompute that parent from the tree's
    // current leaves, not from this call's dirty set alone — otherwise the
    // second call would rehash the shared parent against a stale first chunk.
    let values: Vec<u64> = (0..8u64).map(|i| (i + 1) * 10).collect();
    let mut g = group(&values);
    let mut wv = g.roll_fresh();

    wv.set_many(&[(0, 111)]); // chunk 0 only
    wv.set_many(&[(4, 555)]); // chunk 1 only (chunk 0's sibling)
    assert_eq!(wv.iter().collect::<Vec<_>>(), vec![111, 20, 30, 40, 555, 60, 70, 80]);
    assert_root_matches(&wv);
}

#[test]
fn root_matches_reference_random_batches() {
    use rand::{Rng, SeedableRng, rngs::StdRng, seq::SliceRandom};

    // Exercises the batched (contiguous-run) leaf rehash against the reference
    // hasher across dense, sparse, and single-index write batches.
    let mut rng = StdRng::seed_from_u64(0xB0BA);
    for n in [1usize, 7, 64, 500, 4096] {
        let values: Vec<u64> = (0..n as u64).map(|_| rng.gen_range(0..=u64::MAX)).collect();
        let mut g = BalancesGroup::new(n + 4, n, &le_bytes(&values), HashFormat::Fixed).unwrap();
        let mut wv = g.roll_fresh();

        for _ in 0..8 {
            let count = rng.gen_range(1..=n);
            let mut idxs: Vec<u32> = (0..n as u32).collect();
            idxs.shuffle(&mut rng);
            idxs.truncate(count);
            idxs.sort_unstable();
            let batch: Vec<(u32, u64)> =
                idxs.iter().map(|&i| (i, rng.gen_range(0..=u64::MAX))).collect();
            wv.set_many(&batch);
            assert_root_matches(&wv);
        }
    }
}

/// A rejected block abandons its rolled write view without committing. The
/// next roll must see none of it: dirtied pages (including an un-rehashed
/// deferred batch) reload from the new parent.
#[test]
fn rejected_writes_dont_leak() {
    let mut g = group(&[1, 2, 3, 4, 5]);
    let a = {
        let mut wv = g.roll_fresh();
        wv.set(0, 10);
        wv.commit()
    };

    // Rejected block: roll, write, drop without committing.
    {
        let mut wv = g.roll_from(a);
        wv.set(0, 777);
        wv.set(4, 888);
        wv.set_deferred(2, 999);
    }

    let wv = g.roll_from(a);
    assert_eq!(wv.iter().collect::<Vec<_>>(), vec![10, 2, 3, 4, 5]);
    assert_root_matches(&wv);
    assert_ne!(a, wv.commit());
}

#[test]
fn vector_root_omits_the_length_mix_in() {
    let values: Vec<u64> = (0..U64Vector::SSZ_LIMIT as u64).collect();
    let mut g = vector_group(&values);
    let mut wv = g.roll_fresh();

    assert_eq!(wv.hash_root(), hash_uint64_vector(&values));

    wv.set(4_095, 12_345);
    let mut edited = values.clone();
    edited[4_095] = 12_345;
    assert_eq!(wv.hash_root(), hash_uint64_vector(&edited));
}

#[test]
fn vector_root_pads_an_under_materialized_tree() {
    let values: Vec<u64> = (1..=1_024).collect();
    let g = &mut vector_group(&values);
    let wv = g.roll_fresh();

    let mut full = values.clone();
    full.resize(U64Vector::SSZ_LIMIT, 0);
    assert_eq!(wv.hash_root(), hash_uint64_vector(&full));
}

/// The `block_roots` ring is `Vector[Root, 8192]`: its root carries no length
/// mix-in, and `at_slot` wraps at the ring's own length.
#[test]
fn block_roots_ring_wraps_and_hashes_as_a_vector() {
    let mut g = BlockRootsGroup::zeroed_vector();
    let mut wv = g.roll_fresh();

    let tag = |slot: u64| {
        let mut r = [0u8; 32];
        r[..8].copy_from_slice(&slot.to_le_bytes());
        r
    };
    let wrapped = SLOTS_PER_HISTORICAL_ROOT as u64 + 3;
    wv.set(7, tag(7));
    wv.set((wrapped % SLOTS_PER_HISTORICAL_ROOT as u64) as u32, tag(wrapped));

    assert_eq!(wv.at_slot(7), tag(7));
    assert_eq!(wv.at_slot(wrapped), tag(wrapped));
    assert_eq!(wv.at_slot(3), tag(wrapped), "slot 3's bucket was overwritten by the wrap");

    let mut expected = vec![[0u8; 32]; SLOTS_PER_HISTORICAL_ROOT];
    expected[7] = tag(7);
    expected[3] = tag(wrapped);
    assert_eq!(wv.hash_root(), hash_b256_vector(&expected));
}

/// `contains` walks back from `from_slot`, so it sees every written bucket but
/// nothing written above the slot it is asked about.
#[test]
fn block_roots_contains_scans_back_from_the_given_slot() {
    let mut g = BlockRootsGroup::zeroed_vector();
    let id = {
        let mut wv = g.roll_fresh();
        wv.set(100, [0xAA; 32]);
        wv.set(101, [0xBB; 32]);
        wv.commit()
    };
    let reader = g.view(id);

    assert!(reader.contains(&[0xAA; 32], 101));
    assert!(reader.contains(&[0xBB; 32], 101));
    assert!(!reader.contains(&[0xCC; 32], 101));
}

/// A block's reveal accumulates into the current epoch's bucket; the boundary
/// copy seeds the next epoch from it, and the next epoch's reveals accumulate
/// on top without disturbing the finished epoch.
#[test]
fn randao_mixes_accumulate_then_carry_to_the_next_epoch() {
    let mut g = RandaoMixesGroup::zeroed_vector();
    let mut wv = g.roll_fresh();

    wv.mix_in_reveal(5, &[0b0011; 32]);
    wv.mix_in_reveal(5, &[0b0101; 32]);
    assert_eq!(wv.at_epoch(5), [0b0110; 32]);

    wv.copy_to_next_epoch(5);
    assert_eq!(wv.at_epoch(6), [0b0110; 32]);
    wv.mix_in_reveal(6, &[0b0010; 32]);
    assert_eq!(wv.at_epoch(6), [0b0100; 32]);
    assert_eq!(wv.at_epoch(5), [0b0110; 32], "the finished epoch's mix is frozen");

    let mut expected = vec![[0u8; 32]; EPOCHS_PER_HISTORICAL_VECTOR];
    expected[5] = [0b0110; 32];
    expected[6] = [0b0100; 32];
    assert_eq!(wv.hash_root(), hash_b256_vector(&expected));
}

/// The ring wraps at `EPOCHS_PER_HISTORICAL_VECTOR`, so an epoch a full period
/// on shares its bucket.
#[test]
fn randao_mixes_wrap_at_the_ring_length() {
    let mut g = RandaoMixesGroup::zeroed_vector();
    let mut wv = g.roll_fresh();

    wv.mix_in_reveal(2, &[0xAB; 32]);
    assert_eq!(wv.at_epoch(2 + EPOCHS_PER_HISTORICAL_VECTOR as u64), [0xAB; 32]);
}
