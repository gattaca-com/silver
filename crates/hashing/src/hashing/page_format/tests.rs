use std::collections::HashSet;

use super::{PagePos, Subtree};
use crate::{B256, TreeSpec, hashing::format::TreeFormat, progressive::PROGRESSIVE_SEGMENT_START};

struct P4;
impl TreeSpec for P4 {
    type Val = u64;
    type Page = [B256; 4];
}

struct P32;
impl TreeSpec for P32 {
    type Val = u64;
    type Page = [B256; 32];
}

fn flat_nodes<C: TreeSpec>(format: TreeFormat) -> Vec<usize> {
    match format {
        TreeFormat::Fixed { max_elements } => (1..2 * max_elements).collect(),
        TreeFormat::Progressive { last_seg } => (0..=last_seg as usize)
            .flat_map(|k| {
                let internals = (1..1usize << (2 * k)).map(move |i| C::SEG_OFF[k] + i);
                let leaf0 = format.data_start::<C>() + PROGRESSIVE_SEGMENT_START[k];
                internals.chain(leaf0..leaf0 + (1 << (2 * k)))
            })
            .collect(),
    }
}

fn pages<C: TreeSpec>(sub: Subtree) -> impl Iterator<Item = PagePos> {
    (0..sub.page_levels::<C>()).flat_map(move |page_level| {
        (0..1usize << sub.top_level::<C>(page_level))
            .map(move |index| PagePos { page_level, index })
    })
}

/// Pages partition the flat tree nodes, descending from the root by `path_to`
/// lands on the page row and slot holding each node, and every page on a
/// leaf's path spans that leaf's chunk.
fn check<C: TreeSpec>(format: TreeFormat) {
    let mut seen = HashSet::new();
    for sub in format.subtrees::<C>() {
        for at in pages::<C>(sub) {
            for (node, len) in sub.rows_of::<C>(at) {
                assert!(2 * len <= C::PAGE_NODES, "{format:?}: row past the page");
                for n in node..node + len {
                    assert!(seen.insert(n), "{format:?}: node {n} in two pages");
                }
            }
        }
    }
    let expected = flat_nodes::<C>(format);
    assert_eq!(seen, expected.iter().copied().collect(), "{format:?}: nodes not covered");

    for &n in &expected {
        let (s, level, pos) = format.locate::<C>(n).unwrap();
        let sub = Subtree::of::<C>(format, s);
        let (children, slot) = sub.path_to::<C>(level, pos);
        let mut at = sub.root::<C>();
        for j in children {
            assert!(j < sub.child_count::<C>(at), "{format:?}: child {j} out of range");
            at = sub.child::<C>(at, j);
        }
        let row = sub.rows_of::<C>(at).find(|&(node, len)| (node..node + len).contains(&n));
        let (row_node, row_len) = row.unwrap_or_else(|| panic!("{format:?}: {n} not in {at:?}"));
        assert_eq!(slot, row_len + n - row_node, "{format:?}: node {n} slot");

        if level == sub.height {
            let chunk = sub.leaves_offset + pos;
            let mut up = sub.root::<C>();
            for j in sub.path_to::<C>(level, pos).0 {
                assert!(sub.chunks_under::<C>(up).contains(&chunk), "{format:?}: {up:?}");
                up = sub.child::<C>(up, j);
            }
            assert!(sub.chunks_under::<C>(at).contains(&chunk), "{format:?}: leaf {pos} page");
        }
    }
}

#[test]
fn fixed_pages_partition_the_heap() {
    for h in 0..9 {
        check::<P4>(TreeFormat::Fixed { max_elements: 1 << h });
        check::<P32>(TreeFormat::Fixed { max_elements: 1 << h });
    }
}

#[test]
fn progressive_pages_partition_every_segment() {
    for last_seg in 0..5 {
        check::<P4>(TreeFormat::Progressive { last_seg });
        check::<P32>(TreeFormat::Progressive { last_seg });
    }
}

/// A reader can pair a node id with another fork's format, so `locate` resolves
/// exactly the flat-tree nodes and refuses padding and ids past the tree.
fn check_locate_is_total<C: TreeSpec>(format: TreeFormat) {
    let nodes: HashSet<_> = flat_nodes::<C>(format).into_iter().collect();
    let end = nodes.iter().max().unwrap() + 2 * C::PAGE_NODES;
    for n in 0..end {
        assert_eq!(format.locate::<C>(n).is_some(), nodes.contains(&n), "{format:?}: node {n}");
    }
}

#[test]
fn locate_refuses_padding_and_ids_past_the_tree() {
    for h in 0..8 {
        check_locate_is_total::<P4>(TreeFormat::Fixed { max_elements: 1 << h });
        check_locate_is_total::<P32>(TreeFormat::Fixed { max_elements: 1 << h });
    }
    for last_seg in 0..5 {
        check_locate_is_total::<P4>(TreeFormat::Progressive { last_seg });
        check_locate_is_total::<P32>(TreeFormat::Progressive { last_seg });
    }
}
