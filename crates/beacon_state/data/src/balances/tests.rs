use super::{BalancesDelta, FinalizedBalances};
use crate::{ssz_hash::hash_uint64_list, types::VALIDATOR_REGISTRY_LIMIT};

fn base_with(values: &[u64]) -> FinalizedBalances {
    FinalizedBalances::with_seed_balances(values.len().max(1) + 4, values)
}

/// `list_root` must byte-match the reference `hash_uint64_list` over the same
/// merged values — this is the linchpin invariant of the overlay.
fn assert_root_matches(
    base: &FinalizedBalances,
    base_count: usize,
    d: &BalancesDelta,
    total: usize,
) {
    let want = hash_uint64_list(d.iter(base, base_count, total), total, VALIDATOR_REGISTRY_LIMIT);
    assert_eq!(d.list_root(base, total), want);
}

#[test]
fn effective_balance_edit_then_base_then_default() {
    let base = base_with(&[1_000, 2_000]);
    let base_count = 2;
    let mut d = BalancesDelta::default();

    assert_eq!(d.effective_balance(&base, base_count, 0), 1_000);
    assert_eq!(d.effective_balance(&base, base_count, 5), 0);
    d.set(&base, 0, 2_500);
    assert_eq!(d.effective_balance(&base, base_count, 0), 2_500);
}

#[test]
fn iter_merges_edits_over_base() {
    let base = base_with(&[0, 100, 200, 300, 400]);
    let base_count = 5;
    let mut d = BalancesDelta::default();
    d.set(&base, 1, 999);
    d.set(&base, 3, 333);
    let got: Vec<u64> = d.iter(&base, base_count, 5).collect();
    assert_eq!(got, vec![0, 999, 200, 333, 400]);
}

#[test]
fn set_inserts_then_updates() {
    let base = base_with(&[1_000, 1_000, 1_000]);
    let base_count = 3;
    let mut d = BalancesDelta::default();

    d.set(&base, 2, 2_500);
    assert_eq!(*d.edits, [(2, 2_500)]);

    d.set(&base, 0, 4_000);
    assert_eq!(*d.edits, [(0, 4_000), (2, 2_500)]);

    d.set(&base, 0, 5_000);
    assert_eq!(*d.edits, [(0, 5_000), (2, 2_500)]);

    // Setting back to the base value keeps the (now redundant) entry — base-equal
    // edits are cleaned by prune_to_base, not on write — and the root is
    // unaffected.
    d.set(&base, 0, 1_000);
    assert_eq!(*d.edits, [(0, 1_000), (2, 2_500)]);
    assert_root_matches(&base, base_count, &d, base_count);
}

#[test]
fn set_many_applies_sparse_changes() {
    let base = base_with(&[0, 10, 20, 30]);
    let base_count = 4;
    let mut d = BalancesDelta::default();
    d.set_many(&base, &[(1, 1010), (3, 1030)]);
    assert_eq!(*d.edits, [(1, 1010), (3, 1030)]);
    assert_root_matches(&base, base_count, &d, base_count);
}

#[test]
fn set_many_preserves_untouched_edits() {
    let base = base_with(&[10, 20, 30]);
    let base_count = 3;
    let mut d = BalancesDelta::default();
    d.set(&base, 0, 111); // pre-existing edit for untouched index

    d.set_many(&base, &[(1, 99), (5, 7)]);
    // idx 0 preserved, idx 1 and 5 updated.
    assert_eq!(*d.edits, [(0, 111), (1, 99), (5, 7)]);
    assert_root_matches(&base, base_count, &d, 6);
}

#[test]
fn prune_drops_edits_matching_new_base() {
    let base = base_with(&[1_000, 2_000]);
    let mut d = BalancesDelta::default();
    d.set(&base, 0, 1_000); // equals base → dropped by prune below
    d.set(&base, 1, 5_000);
    d.set(&base, 3, 7_000);
    d.prune_to_base(&base, 2);
    assert_eq!(*d.edits, [(1, 5_000), (3, 7_000)]);
}

#[test]
fn from_ssz_decodes_le_u64s() {
    let mut bytes = Vec::new();
    for v in [7u64, 8, 9] {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    let base = FinalizedBalances::from_ssz(4, &bytes, 3).unwrap();
    let d = BalancesDelta::default();
    assert_eq!(
        [
            d.effective_balance(&base, 3, 0),
            d.effective_balance(&base, 3, 1),
            d.effective_balance(&base, 3, 2)
        ],
        [7, 8, 9]
    );
    assert_root_matches(&base, 3, &d, 3);
}

#[test]
fn from_ssz_rejects_len_mismatch() {
    let bytes = [0u8; 8];
    assert!(FinalizedBalances::from_ssz(4, &bytes, 2).is_err());
}

// ---- hash tree ----

#[test]
fn root_matches_reference_across_counts() {
    // Empty, partial trailing chunk, exact multiple of 4, and beyond.
    for n in [0usize, 1, 3, 4, 5, 8, 13] {
        let values: Vec<u64> = (0..n as u64).map(|i| (i + 1) * 1_000).collect();
        let base = base_with(&values);
        assert_root_matches(&base, n, &BalancesDelta::default(), n);
    }
}

#[test]
fn root_reflects_edits_and_appends() {
    let base = base_with(&[10, 20, 30, 40, 50]);
    let base_count = 5;
    let mut d = BalancesDelta::default();

    d.set(&base, 1, 999); // base edit
    d.set(&base, 6, 7); // appended (idx ≥ base_count), grows total to 7
    assert_root_matches(&base, base_count, &d, 7);

    // Setting an appended balance back to 0 (its default) re-collapses the leaf.
    d.set(&base, 6, 0);
    assert_root_matches(&base, base_count, &d, 7);
}

#[test]
fn promote_folds_overlay_into_base() {
    let mut base = base_with(&[10, 20, 30, 40, 50]);
    let base_count = 5;
    let mut d = BalancesDelta::default();
    d.set(&base, 1, 999);
    d.set(&base, 4, 4_444);
    let pre = d.list_root(&base, base_count);

    d.promote_into_base(&mut base);

    // A fresh delta over the promoted base reproduces the same root with zero
    // SHA work (cached-hash promote), and matches the reference over the
    // promoted data.
    let fresh = BalancesDelta::default();
    assert_eq!(fresh.list_root(&base, base_count), pre);
    assert_root_matches(&base, base_count, &fresh, base_count);
    assert_eq!(fresh.effective_balance(&base, base_count, 1), 999);
    assert_eq!(fresh.effective_balance(&base, base_count, 4), 4_444);
}
