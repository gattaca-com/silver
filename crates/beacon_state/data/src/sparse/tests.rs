use super::Edits;

/// Seed a sorted `Edits` through the real merge path (production has no
/// from-`Vec` constructor).
fn edits_of<V: Copy + Default>(items: &[(u32, V)]) -> Edits<V> {
    let mut edits = Edits::default();
    edits.merge_in_place(items);
    edits
}

#[test]
fn merge_updates_in_place() {
    let mut edits = edits_of(&[(0, 10), (2, 20), (5, 50)]);
    edits.merge_in_place(&[(2, 22), (5, 55)]);
    assert_eq!(*edits, [(0, 10), (2, 22), (5, 55)]);
}

#[test]
fn merge_inserts_and_preserves_untouched() {
    let mut edits = edits_of(&[(0, 10), (4, 40)]);
    edits.merge_in_place(&[(1, 11), (3, 33), (6, 66)]);
    assert_eq!(*edits, [(0, 10), (1, 11), (3, 33), (4, 40), (6, 66)]);
}

#[test]
fn merge_mixed_updates_and_insertions() {
    let mut edits = edits_of(&[(0, 111), (2, 200)]);
    edits.merge_in_place(&[(1, 99), (2, 222), (5, 7)]);
    assert_eq!(*edits, [(0, 111), (1, 99), (2, 222), (5, 7)]);
}

#[test]
fn merge_small_batch_at_high_indices() {
    let seed: Vec<_> = (0..10_000u32).map(|i| (i * 2, i as u64)).collect();
    let mut edits = edits_of(&seed);
    edits.merge_in_place(&[(19_996, 111), (19_999, 222)]);
    assert_eq!(edits.len(), 10_001);
    assert_eq!(edits[9998], (19_996, 111));
    assert_eq!(edits[9999], (19_998, 9999));
    assert_eq!(edits[10_000], (19_999, 222));
}

#[test]
fn merge_large_batch_uses_scan_path() {
    // Dense overlapping keys force the O(m + n) scan path (m·log n > m + n) and
    // exercise pure in-place updates (no insertions).
    let seed: Vec<_> = (0..100u32).map(|i| (i, i as u64)).collect();
    let mut edits = edits_of(&seed);
    let changes: Vec<_> = (0..100).map(|i| (i, i as u64 + 1000)).collect();
    edits.merge_in_place(&changes);
    assert_eq!(edits.len(), 100);
    assert!(edits.iter().all(|&(k, v)| v == k as u64 + 1000));
}
