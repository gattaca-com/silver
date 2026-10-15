use std::collections::HashSet;

use super::{PageId, PagePool};
use crate::{
    column::{
        ColumnSpec, format::TreeFormat, snapshot::PageSnapshot, store::NodeStore,
        subtree::build_subtree_hashes,
    },
    types::B256,
};

/// Sixteen leaves in pages of four nodes: a root page over two page-level-1
/// pages of four leaf pages each, two leaves per leaf page.
struct P4;
impl ColumnSpec for P4 {
    type Val = u64;
    type Page = [B256; 4];
}

const FORMAT: TreeFormat = TreeFormat::Fixed { max_elements: 16 };

/// `leaves` non-zero leaves, leaf `i` filled with `fill + i`.
fn nodes(leaves: usize, fill: u8) -> Vec<B256> {
    let mut nodes = vec![[0u8; 32]; 32];
    let (internal, leaf_nodes) = nodes.split_at_mut(16);
    for (i, leaf) in leaf_nodes[..leaves].iter_mut().enumerate() {
        *leaf = [fill.wrapping_add(i as u8); 32];
    }
    build_subtree_hashes(internal, leaf_nodes, leaves);
    nodes
}

fn commit(
    pool: &mut PagePool<[B256; 4]>,
    parent: Option<&PageSnapshot>,
    nodes: &[B256],
    written: &[u32],
    chunks: usize,
) -> PageSnapshot {
    let mut store = NodeStore::<P4>::default();
    store.nodes = nodes.to_vec();
    store.count = chunks * 4;
    store.writes.resize(16);
    match parent {
        None => store.writes.mark_all_hashed(),
        Some(_) => {
            written.iter().for_each(|&leaf| store.writes.mark(leaf as usize));
            store.writes.take_unhashed();
        }
    }
    let mut dst = PageSnapshot::default();
    store.commit(FORMAT, pool, &mut dst, parent);
    dst
}

/// Ids along the page path from the root to leaf page `leaf_page`.
fn path(pool: &PagePool<[B256; 4]>, snapshot: &PageSnapshot, leaf_page: usize) -> [PageId; 3] {
    let root = snapshot.roots[0];
    let page_level1 = pool.child(root, leaf_page / 4);
    [root, page_level1, pool.child(page_level1, leaf_page % 4)]
}

fn freed(pool: &PagePool<[B256; 4]>) -> Vec<PageId> {
    let mut ids: Vec<_> = pool.free.iter().flatten().copied().collect();
    ids.sort_unstable();
    ids
}

fn sorted(mut ids: Vec<PageId>) -> Vec<PageId> {
    ids.sort_unstable();
    ids
}

/// Finalize `w` over base ← a ← w with a dead sibling `d` of `a`: the base
/// frees what `w` replaced, `a` keeps what `w` holds, `d` frees everything.
#[test]
fn release_frees_allocated_pages_the_winner_does_not_hold() {
    let mut pool = PagePool::new();
    let mut base = commit(&mut pool, None, &nodes(16, 1), &[], 16);
    let b0 = path(&pool, &base, 0);
    let b7 = path(&pool, &base, 7);
    let b4 = path(&pool, &base, 4);
    let mut a = commit(&mut pool, Some(&base), &nodes(16, 2), &[0], 16);
    let mut w = commit(&mut pool, Some(&a), &nodes(16, 3), &[15], 16);
    let mut d = commit(&mut pool, Some(&base), &nodes(16, 4), &[8], 16);
    let (a0, d4) = (path(&pool, &a, 0), path(&pool, &d, 4));

    base.promote::<P4>(&mut pool, &w);
    assert_eq!(freed(&pool), sorted(vec![b0[0], b0[1], b0[2], b7[1], b7[2]]));

    a.release::<P4>(&mut pool, &base);
    d.release::<P4>(&mut pool, &base);
    w.release::<P4>(&mut pool, &base);
    let expected = vec![b0[0], b0[1], b0[2], b7[1], b7[2], a0[0], d4[0], d4[1], d4[2]];
    assert_eq!(freed(&pool), sorted(expected));
    assert!(!freed(&pool).contains(&b4[2]), "base leaf page under no write");
}

/// The winner, released right after its promote, frees nothing: the base holds
/// all its pages. The next promote frees exactly what the new winner replaced.
#[test]
fn released_winner_frees_nothing_and_promote_frees_its_replaced_pages() {
    let mut pool = PagePool::new();
    let mut base = commit(&mut pool, None, &nodes(16, 1), &[], 16);
    let mut w = commit(&mut pool, Some(&base), &nodes(16, 2), &[0], 16);
    base.promote::<P4>(&mut pool, &w);
    pool.free = [Vec::new(), Vec::new()];
    w.release::<P4>(&mut pool, &base);
    assert!(freed(&pool).is_empty(), "the base holds every page of the winner");

    let w0 = path(&pool, &w, 0);
    let w2 = commit(&mut pool, Some(&w), &nodes(16, 3), &[1], 16);
    base.promote::<P4>(&mut pool, &w2);

    assert_eq!(freed(&pool), sorted(w0.to_vec()));
}

#[test]
fn release_is_idempotent() {
    let mut pool = PagePool::new();
    let base = commit(&mut pool, None, &nodes(16, 1), &[], 16);
    let mut dead = commit(&mut pool, Some(&base), &nodes(16, 2), &[0], 16);
    let roots = dead.roots.clone();

    dead.release::<P4>(&mut pool, &base);
    dead.release::<P4>(&mut pool, &base);

    let unique: HashSet<_> = freed(&pool).into_iter().collect();
    assert_eq!(unique.len(), 3, "each allocated page freed once");
    assert_eq!(freed(&pool).len(), 3);
    assert_eq!(dead.roots, roots, "readers keep their roots");
}
