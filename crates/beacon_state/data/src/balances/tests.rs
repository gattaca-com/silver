use super::{BalancesGroup, BalancesWriteView};
use crate::{ssz_hash::hash_uint64_list, types::VALIDATOR_REGISTRY_LIMIT};

fn le_bytes(values: &[u64]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}

fn group(values: &[u64]) -> BalancesGroup {
    BalancesGroup::new(values.len().max(1) + 4, values.len(), &le_bytes(values)).unwrap()
}

fn assert_root_matches(wv: &BalancesWriteView<'_>) {
    let vals: Vec<u64> = wv.iter().collect();
    let want = hash_uint64_list(vals.iter().copied(), vals.len(), VALIDATOR_REGISTRY_LIMIT);
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
fn set_many_keeps_prior_writes() {
    let mut g = group(&[10, 20, 30]);
    let mut wv = g.roll_fresh();

    // Three validators join (idx 3,4,5 at default 0), then writes land.
    wv.append(0);
    wv.append(0);
    wv.append(0);
    wv.set(0, 111);
    wv.set_many(&[(1, 99), (5, 7)]);
    // idx 0's earlier write survives; 1 and 5 applied; 2 reads base, 3/4 default.
    assert_eq!(wv.iter().collect::<Vec<_>>(), vec![111, 99, 30, 0, 0, 7]);
    assert_root_matches(&wv);
}

#[test]
fn finalize_preserves_survivor_reads_and_root() {
    // Winner has two appended validators and a base-equal edit; finalizing it
    // promotes its values into the base and re-anchors the survivor, leaving the
    // survivor's reads and root untouched.
    let mut g = group(&[1_000, 2_000]);

    let mut wv = g.roll_fresh();
    wv.append(0); // idx 2
    wv.append(0); // idx 3
    wv.set(0, 1_000); // equals base[0]
    wv.set(1, 5_000);
    wv.set(3, 7_000);
    let before = wv.hash_root();
    let winner = wv.commit();

    let survivor = g.roll_from(winner).commit(); // inherits the winner's state
    let live = g.finalize(winner, &[winner, survivor]); // survivor re-anchored → new seq

    // Re-anchored slots are frozen; read them through a fresh fork.
    let wv = g.roll_from(live[1]);
    assert_eq!(wv.iter().collect::<Vec<_>>(), vec![1_000, 5_000, 0, 7_000]);
    assert_eq!(wv.hash_root(), before);
}

#[test]
fn finalize_dedupes_shared_survivor() {
    // Sibling forks can share a balances slot, so the same survivor id can
    // appear more than once. Each distinct source is derived once: the repeated
    // id gets the *same* new id back, and the lone distinct one a different slot.
    let mut g = group(&[10, 20, 30]);

    let mut wv = g.roll_fresh();
    wv.set(0, 111);
    let winner = wv.commit();

    let shared = g.roll_from(winner).commit();
    let other = g.roll_from(winner).commit();

    let live = g.finalize(winner, &[winner, shared, shared, other]);
    assert_eq!(live[1], live[2], "the repeated survivor id re-anchors to one slot");
    assert_ne!(live[1], live[3], "the distinct survivor gets its own slot");

    // Both ids still read the finalized state (through fresh forks).
    assert_eq!(g.roll_from(live[1]).iter().collect::<Vec<_>>(), vec![111, 20, 30]);
    assert_eq!(g.roll_from(live[3]).iter().collect::<Vec<_>>(), vec![111, 20, 30]);
}

#[test]
fn new_decodes_le_u64s() {
    let mut g = BalancesGroup::new(4, 3, &le_bytes(&[7, 8, 9])).unwrap();
    let wv = g.roll_fresh();

    assert_eq!([wv.get(0), wv.get(1), wv.get(2)], [7, 8, 9]);
    assert_root_matches(&wv);
}

#[test]
fn new_rejects_len_mismatch() {
    assert!(BalancesGroup::new(4, 2, &[0u8; 12]).is_err());
}

// ---- hash tree ----

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
    wv.append(0); // idx 5
    wv.append(7); // idx 6 — appended validator with balance 7
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
    g.finalize(s, &[s]);

    // A fresh fork over the promoted base reproduces the same root with zero SHA
    // work (cached-hash promote) and reads the promoted values.
    let wv = g.roll_fresh();
    assert_eq!(wv.hash_root(), pre);
    assert_root_matches(&wv);
    assert_eq!(wv.get(1), 999);
    assert_eq!(wv.get(4), 4_444);
}

#[test]
fn aba_finalize_pins_reverted_value() {
    // base[0]=C; D1(0=A) ← D2(0=B) ← D3(0=A reverted). Finalizing D1 then D2 must
    // leave D3's view of idx 0 at A across both base swaps (the ABA hazard).
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

    // Finalize D1 (winner s1): base[0] → A; survivors re-anchor into fresh
    // slots — finalize hands back their new seqs (old s2/s3 are now frozen).
    let live = g.finalize(s1, &[s1, s2, s3]); // [new D1, new D2, new D3]
    assert_eq!(g.roll_from(live[2]).get(0), A);

    // Finalize D2 (winner = new D2): base[0] → B; rebase pins D3's reverted A.
    let live = g.finalize(live[1], &[live[1], live[2]]); // [newest D2, newest D3]
    let wv3 = g.roll_from(live[1]);
    assert_eq!(wv3.get(0), A, "D3 must not inherit B");
    assert_root_matches(&wv3);
}
