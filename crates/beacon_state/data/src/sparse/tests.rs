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
    // The new base updates only where `winner` overrides; everywhere else it
    // stays at the old base. survivor overrides 1, 3, 4 and 5.
    let survivor = edits_of(&[(1, 77), (3, 103), (4, 904), (5, 500)]);
    // winner promotes new base values at 0 and 4; its 102 at idx 2 already
    // equals the old base there; idx 6 sits past the survivor's last index.
    let winner = edits_of(&[(0, 900), (2, 102), (4, 904), (6, 600)]);
    let old_base = |idx: u32| 100 + idx as u64;

    let mut out = Edits::default();
    out.rebase_and_prune_from(&survivor, &winner, /* new_count */ 7, old_base);

    // idx 0: winner-only override (900) ≠ old base → old base 100 pinned (kept).
    // idx 1: survivor 77 ≠ old base 101 → kept.
    // idx 2: winner-only override equals old base 102 → no pin needed.
    // idx 3: survivor 103 == old base 103 → dropped (redundant).
    // idx 4: survivor 904 == winner's new base 904 → dropped (redundant).
    // idx 5: survivor 500 ≠ old base 105 → kept.
    // idx 6: winner-only override past survivor's last index (flushed at the
    //        end) ≠ old base → old base 106 pinned (kept).
    assert_eq!(out.iter().copied().collect::<Vec<_>>(), [(0, 100), (1, 77), (5, 500), (6, 106)]);
}

#[test]
fn rebase_and_prune_keeps_survivor_appended_indices() {
    // The survivor fork appended idx 6, which the winner's count (4) doesn't
    // cover — it has no base to compare against and is always kept.
    let survivor = edits_of(&[(2, 500), (3, 999), (6, 42)]);
    let winner = edits_of(&[(0, 9), (2, 500), (3, 501)]);
    let old_base = |idx: u32| 100 + idx as u64;

    let mut out = Edits::default();
    out.rebase_and_prune_from(&survivor, &winner, /* new_count */ 4, old_base);

    // idx 0: winner-only override 9 ≠ old base 100 → pinned 100. idx 2: winner's
    // new base 500 == survivor → pruned. idx 3: winner's new base 501 ≠ 999 →
    // kept. idx 6: appended (≥ new_count) → kept verbatim.
    assert_eq!(out.iter().copied().collect::<Vec<_>>(), [(0, 100), (3, 999), (6, 42)]);
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
fn merge_large_dense_batch_updates_in_place() {
    // Dense overlapping keys exercise pure in-place updates (no insertions).
    let seed: Vec<_> = (0..100u32).map(|i| (i, i as u64)).collect();
    let mut edits = edits_of(&seed);
    let changes: Vec<_> = (0..100).map(|i| (i, i as u64 + 1000)).collect();
    edits.merge_in_place(&changes);
    assert_eq!(edits.iter().count(), 100);
    assert!(edits.iter().all(|&(k, v)| v == k as u64 + 1000));
}
