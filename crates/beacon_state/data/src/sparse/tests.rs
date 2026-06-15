use super::Edits;

/// Seed a sorted `Edits` through the real merge path (production has no
/// from-`Vec` constructor).
fn edits_of<V: Copy + Default>(items: &[(u32, V)]) -> Edits<V> {
    let mut edits = Edits::default();
    edits.merge_in_place(items);
    edits
}

#[test]
fn rebase_and_prune_pins_injects_overrides_and_drops_redundant() {
    // survivor overrides idx 1 and 2; (3, 103) will match the new base → pruned.
    let survivor = edits_of(&[(1, 77), (2, 50), (3, 103)]);
    // winner overrides 0, 1 (< valid_below → candidates to inject) and 5 (skipped).
    let winner = edits_of(&[(0, 0), (1, 0), (5, 0)]);
    let old_base = |idx: u32| 100 + idx as u64;

    let out = survivor
        .rebase_and_prune(&winner, /* valid_below */ 3, /* new_count */ 4, old_base);

    // New base = winner's override (0 at idx 0,1) else old base. 0 pinned at old
    // base 100 (≠ new base 0 → kept); 1 kept as the survivor's override 77 (wins
    // over the pin); 5 skipped (≥ valid_below); (2,50) kept (≠ new base 102);
    // (3,103) dropped (== new base 103).
    assert_eq!(out.iter().copied().collect::<Vec<_>>(), [(0, 100), (1, 77), (2, 50)]);
}

#[test]
fn get_finds_and_misses() {
    let edits = edits_of(&[(2, 20), (5, 50)]);
    assert_eq!(edits.get(2), Some(&20));
    assert_eq!(edits.get(5), Some(&50));
    assert!(edits.get(0).is_none());
    assert!(edits.get(3).is_none());
}

#[test]
fn merge_updates_in_place() {
    let mut edits = edits_of(&[(0, 10), (2, 20), (5, 50)]);
    edits.merge_in_place(&[(2, 22), (5, 55)]);
    assert_eq!(edits.iter().copied().collect::<Vec<_>>(), [(0, 10), (2, 22), (5, 55)]);
}

#[test]
fn merge_inserts_and_preserves_untouched() {
    let mut edits = edits_of(&[(0, 10), (4, 40)]);
    edits.merge_in_place(&[(1, 11), (3, 33), (6, 66)]);
    assert_eq!(edits.iter().copied().collect::<Vec<_>>(), [
        (0, 10),
        (1, 11),
        (3, 33),
        (4, 40),
        (6, 66)
    ]);
}

#[test]
fn merge_mixed_updates_and_insertions() {
    let mut edits = edits_of(&[(0, 111), (2, 200)]);
    edits.merge_in_place(&[(1, 99), (2, 222), (5, 7)]);
    assert_eq!(edits.iter().copied().collect::<Vec<_>>(), [(0, 111), (1, 99), (2, 222), (5, 7)]);
}

#[test]
fn merge_small_batch_at_high_indices() {
    let seed: Vec<_> = (0..10_000u32).map(|i| (i * 2, i as u64)).collect();
    let mut edits = edits_of(&seed);
    edits.merge_in_place(&[(19_996, 111), (19_999, 222)]);
    assert_eq!(edits.iter().count(), 10_001);
    let pairs: Vec<_> = edits.iter().copied().collect();
    assert_eq!(pairs[9998], (19_996, 111));
    assert_eq!(pairs[9999], (19_998, 9999));
    assert_eq!(pairs[10_000], (19_999, 222));
}

#[test]
fn merge_large_batch_uses_scan_path() {
    // Dense overlapping keys force the O(m + n) scan path (m·log n > m + n) and
    // exercise pure in-place updates (no insertions).
    let seed: Vec<_> = (0..100u32).map(|i| (i, i as u64)).collect();
    let mut edits = edits_of(&seed);
    let changes: Vec<_> = (0..100).map(|i| (i, i as u64 + 1000)).collect();
    edits.merge_in_place(&changes);
    assert_eq!(edits.iter().count(), 100);
    assert!(edits.iter().all(|&(k, v)| v == k as u64 + 1000));
}
