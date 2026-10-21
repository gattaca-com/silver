use crate::{
    B256, FlatTree, HashFormat, PagePool, PageSnapshot, PageTable, SszScalar, TreeReader, TreeSpec,
    merkle::byte_chunks,
};

/// Sixteen chunks in pages of four nodes: a root page over two page-level-1
/// pages of four leaf pages each, two chunks per leaf page.
struct P4;
impl TreeSpec for P4 {
    type Val = u64;
    type Page = [B256; 4];
}

const CAP: usize = 16 * 4;

type Pool = PagePool<[B256; 4]>;

/// `n` non-zero values, distinct per `fill`.
fn values(n: usize, fill: u64) -> Vec<u64> {
    (0..n as u64).map(|i| fill << 32 | (i + 1)).collect()
}

fn tree(vals: &[u64]) -> FlatTree<P4> {
    let bytes = u64::as_ssz_bytes(vals);
    FlatTree::from_leaves(CAP, vals.len(), byte_chunks(&bytes), HashFormat::Fixed)
}

fn base(pool: &mut Pool, vals: &[u64]) -> PageSnapshot {
    PageSnapshot::from_tree(&mut tree(vals), pool)
}

/// `parent` with `writes` applied, and `appended` values pushed after them.
fn fork(
    pool: &mut Pool,
    parent: &PageSnapshot,
    writes: &[(u32, u64)],
    appended: &[u64],
) -> PageSnapshot {
    let mut tree = FlatTree::<P4>::default();
    tree.load(pool, &PageTable::default(), parent.table());
    for &(ix, v) in writes {
        tree.set_val(ix, v);
    }
    for &v in appended {
        let ix = tree.append_empty();
        tree.set_val(ix, v);
    }
    tree.rehash();
    let mut snapshot = PageSnapshot::default();
    snapshot.commit(&mut tree, pool, parent);
    snapshot
}

fn with(vals: &[u64], writes: &[(u32, u64)], appended: &[u64]) -> Vec<u64> {
    let mut vals = vals.to_vec();
    writes.iter().for_each(|&(ix, v)| vals[ix as usize] = v);
    vals.extend_from_slice(appended);
    vals
}

/// The snapshot reads back `vals` and roots like a tree built from them.
fn assert_holds(pool: &Pool, snapshot: &PageSnapshot, vals: &[u64]) {
    let reader = TreeReader::<P4, Pool>::paged(pool, snapshot.table());
    let read: Vec<u64> = (0..vals.len()).map(|ix| reader.get(ix)).collect();
    assert_eq!(read, vals);
    let reference = tree(vals);
    assert_eq!(reader.hash_root(), TreeReader::<P4, Pool>::flat(&reference).hash_root());
}

/// What a pool holding only `vals` keeps live: no leak, no double free.
fn pages_of(vals: &[u64]) -> usize {
    let mut pool = Pool::default();
    base(&mut pool, vals);
    pool.live_pages()
}

/// Finalize `w` over base ← a ← w with a dead sibling `d` of `a`: once every
/// fork is released, the pool holds exactly the winner's pages.
#[test]
fn finalizing_a_lineage_keeps_exactly_the_winners_pages() {
    let mut pool = Pool::default();
    let vals = values(CAP, 1);
    let mut base = base(&mut pool, &vals);
    let mut a = fork(&mut pool, &base, &[(0, 7)], &[]);
    let a_vals = with(&vals, &[(0, 7)], &[]);
    let mut w = fork(&mut pool, &a, &[(60, 8)], &[]);
    let w_vals = with(&a_vals, &[(60, 8)], &[]);
    let mut d = fork(&mut pool, &base, &[(32, 9)], &[]);

    base.promote::<P4>(&mut pool, &w);
    for fork in [&mut a, &mut d, &mut w] {
        fork.release::<P4>(&mut pool, &base);
    }

    assert_holds(&pool, &base, &w_vals);
    assert_eq!(pool.live_pages(), pages_of(&w_vals));
}

/// A winner released right after its promote frees nothing the base holds;
/// the next promote frees exactly what the new winner replaced.
#[test]
fn a_released_winner_frees_nothing_the_base_holds() {
    let mut pool = Pool::default();
    let vals = values(CAP, 1);
    let mut base = base(&mut pool, &vals);
    let mut w = fork(&mut pool, &base, &[(0, 7)], &[]);
    let w_vals = with(&vals, &[(0, 7)], &[]);
    base.promote::<P4>(&mut pool, &w);
    w.release::<P4>(&mut pool, &base);
    assert_holds(&pool, &base, &w_vals);
    assert_eq!(pool.live_pages(), pages_of(&w_vals));

    let mut w2 = fork(&mut pool, &w, &[(4, 9)], &[]);
    let w2_vals = with(&w_vals, &[(4, 9)], &[]);
    base.promote::<P4>(&mut pool, &w2);
    w2.release::<P4>(&mut pool, &base);
    assert_holds(&pool, &base, &w2_vals);
    assert_eq!(pool.live_pages(), pages_of(&w2_vals));
}

/// A fork that grows into padding without writing it shares the zero page;
/// promoting past it, and past a later write there, keeps the zero page.
#[test]
fn promote_never_frees_a_zero_page() {
    let mut pool = Pool::default();
    let vals = values(8, 1);
    let mut base = base(&mut pool, &vals);

    let mut grown = fork(&mut pool, &base, &[(0, 7)], &[0; 4]);
    let grown_vals = with(&vals, &[(0, 7)], &[0; 4]);
    base.promote::<P4>(&mut pool, &grown);
    grown.release::<P4>(&mut pool, &base);
    assert_holds(&pool, &base, &grown_vals);

    let mut written = fork(&mut pool, &base, &[(8, 5), (0, 6)], &[]);
    let written_vals = with(&grown_vals, &[(8, 5), (0, 6)], &[]);
    base.promote::<P4>(&mut pool, &written);
    written.release::<P4>(&mut pool, &base);

    assert_holds(&pool, &base, &written_vals);
    assert_eq!(pool.live_pages(), pages_of(&written_vals));
}

#[test]
fn release_is_idempotent_and_keeps_the_dead_fork_readable() {
    let mut pool = Pool::default();
    let vals = values(CAP, 1);
    let base = base(&mut pool, &vals);
    let mut dead = fork(&mut pool, &base, &[(0, 7)], &[]);

    dead.release::<P4>(&mut pool, &base);
    let live = pool.live_pages();
    dead.release::<P4>(&mut pool, &base);

    assert_eq!(pool.live_pages(), live, "a second release frees nothing");
    assert_eq!(live, pages_of(&vals));
    let reader = TreeReader::<P4, Pool>::paged(&pool, dead.table());
    (0..vals.len()).for_each(|ix| _ = reader.get(ix));
}
