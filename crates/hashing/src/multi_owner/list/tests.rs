use std::{
    sync::{Arc, atomic::Ordering},
    thread,
};

use rand::{Rng, SeedableRng, rngs::StdRng};

use super::{ListPool, SharedList};
use crate::{
    B256, FlatTree, HashFormat, SszScalar, TreeReader, TreeSpec,
    merkle::{ZERO_HASHES, byte_chunks, hash_concat, mix_in_length},
    multi_owner::pool::SharedPool,
};

struct Balances;
impl TreeSpec for Balances {
    type Val = u64;
    type Page = [B256; 16];
    const SSZ_LIMIT: usize = 1 << 20;
}

/// Fixed-format root by plain recursion: pad the chunks to a power of two,
/// hash up, then climb the zero hashes to the limit's depth.
fn reference_root(vals: &[u64]) -> B256 {
    let bytes = u64::as_ssz_bytes(vals);
    let mut level: Vec<B256> = byte_chunks(&bytes).collect();
    let mut depth = 0;
    while level.len() > 1 || depth == 0 && level.is_empty() {
        level.resize(level.len().next_power_of_two().max(2), ZERO_HASHES[depth]);
        level = level.chunks(2).map(|pair| hash_concat(&pair[0], &pair[1])).collect();
        depth += 1;
    }
    let limit_depth = Balances::SSZ_LIMIT.div_ceil(4).trailing_zeros() as usize;
    let mut root = level.first().copied().unwrap_or(ZERO_HASHES[0]);
    for zero in &ZERO_HASHES[depth..limit_depth] {
        root = hash_concat(&root, zero);
    }
    mix_in_length(&root, vals.len())
}

fn progressive_reference(vals: &[u64]) -> B256 {
    let bytes = u64::as_ssz_bytes(vals);
    let mut tree = FlatTree::<Balances>::from_leaves(
        vals.len(),
        vals.len(),
        byte_chunks(&bytes),
        HashFormat::Progressive,
    );
    tree.rehash();
    TreeReader::<Balances, SharedPool<[B256; 16]>>::flat(&tree).hash_root()
}

fn root(list: &mut SharedList<Balances>) -> B256 {
    list.commit();
    list.hash_root()
}

fn list(vals: &[u64]) -> SharedList<Balances> {
    SharedList::new(vals, HashFormat::Fixed)
}

/// The pool's drop panics on a leaked page.
fn drop_last(pool: Arc<ListPool<Balances>>) {
    drop(Arc::into_inner(pool).expect("every list let go of the pool"));
}

fn forked(list: &mut SharedList<Balances>) -> SharedList<Balances> {
    list.commit();
    list.clone()
}

#[test]
fn reference_root_agrees_with_a_freshly_built_tree() {
    for n in [0, 1, 4, 5, 63, 64, 65, 1000] {
        let vals: Vec<u64> = (0..n).map(|i| i * 7 + 1).collect();
        assert_eq!(list(&vals).hash_root(), reference_root(&vals), "n={n}");
    }
}

#[test]
fn push_past_cap_doubles_and_keeps_the_root() {
    let mut vals = vec![3];
    let mut list = list(&vals);
    for v in 0..300 {
        list.push(v);
        vals.push(v);
        if v % 37 == 0 {
            assert_eq!(root(&mut list), reference_root(&vals), "len {}", vals.len());
        }
    }
    assert_eq!(root(&mut list), reference_root(&vals));
    assert_eq!(list.iter().collect::<Vec<_>>(), vals);
}

#[test]
fn a_fork_shares_until_written_and_never_sees_the_other_side() {
    let vals: Vec<u64> = (0..5000).collect();
    let mut a = list(&vals);
    root(&mut a);

    let mut b = forked(&mut a);
    assert_eq!(a.table.roots(), b.table.roots(), "a clean fork shares every root page");

    b.set(10, 99);
    b.push(7);
    a.set(4000, 1);
    let mut a_vals = vals.clone();
    a_vals[4000] = 1;
    let mut b_vals = vals.clone();
    b_vals[10] = 99;
    b_vals.push(7);
    assert_eq!(root(&mut a), reference_root(&a_vals));
    assert_eq!(root(&mut b), reference_root(&b_vals));
    assert_eq!(a.get(10), 10);
    assert_eq!(b.get(4000), 4000);
}

#[test]
fn dropping_every_list_frees_every_page() {
    let pool;
    {
        let vals: Vec<u64> = (0..3000).collect();
        let mut a = list(&vals);
        pool = a.pool.clone();
        let mut b = forked(&mut a);
        b.set(0, 1);
        root(&mut b);
        let mut c = forked(&mut b);
        c.migrate_to_progressive();
        c.push(5);
        root(&mut c);
        a.push(1);
        root(&mut a);
    }
    drop_last(pool);
}

#[test]
fn a_progressive_list_matches_its_rebuilt_tree() {
    let mut vals: Vec<u64> = (0..100).collect();
    let mut list = list(&vals);
    list.migrate_to_progressive();
    for v in 0..500 {
        list.push(v);
        vals.push(v);
    }
    list.set(3, 42);
    vals[3] = 42;
    assert_eq!(root(&mut list), progressive_reference(&vals));
    assert_eq!(forked(&mut list).hash_root(), progressive_reference(&vals));
}

/// Random forks, writes, pushes and drops against a `Vec` model; every root
/// must match the model's, and nothing may leak.
#[test]
fn random_lineages_match_the_model_and_leak_nothing() {
    let mut rng = StdRng::seed_from_u64(7);
    let start: Vec<u64> = (0..2000).map(|_| rng.r#gen()).collect();
    let mut lists = vec![(list(&start), start)];
    let pool = lists[0].0.pool.clone();

    for _ in 0..400 {
        let k = rng.gen_range(0..lists.len());
        match rng.gen_range(0..6) {
            0 if lists.len() < 12 => {
                let copy = (forked(&mut lists[k].0), lists[k].1.clone());
                lists.push(copy);
            }
            1 if lists.len() > 1 => drop(lists.swap_remove(k)),
            2 => {
                let (list, model) = &mut lists[k];
                let v = rng.r#gen();
                list.push(v);
                model.push(v);
            }
            3 => {
                let (list, model) = &mut lists[k];
                assert_eq!(root(list), reference_root(model));
            }
            _ => {
                let (list, model) = &mut lists[k];
                for _ in 0..rng.gen_range(1..50) {
                    let (ix, v) = (rng.gen_range(0..model.len()), rng.r#gen());
                    list.set(ix, v);
                    model[ix] = v;
                }
            }
        }
    }
    for (list, model) in &mut lists {
        assert_eq!(root(list), reference_root(model));
        assert_eq!(list.iter().collect::<Vec<_>>(), *model);
    }
    drop(lists);
    drop_last(pool);
}

/// Threads fork one base, write and commit their own forks and drop them;
/// pages freed on one thread are reused by another.
#[test]
fn threads_fork_write_and_drop_concurrently() {
    let vals: Vec<u64> = (0..20_000).collect();
    let mut base = list(&vals);
    let pool = base.pool.clone();
    root(&mut base);

    thread::scope(|s| {
        for t in 0..8u64 {
            let mut base = forked(&mut base);
            let vals = &vals;
            s.spawn(move || {
                let mut rng = StdRng::seed_from_u64(t);
                for round in 0..20 {
                    let mut fork = forked(&mut base);
                    let mut model = vals.clone();
                    for _ in 0..200 {
                        let (ix, v) = (rng.gen_range(0..model.len()), rng.r#gen());
                        fork.set(ix, v);
                        model[ix] = v;
                    }
                    if round % 5 == 0 {
                        assert_eq!(root(&mut fork), reference_root(&model));
                    } else {
                        root(&mut fork);
                    }
                    let child = forked(&mut fork);
                    drop(fork);
                    assert_eq!(child.iter().collect::<Vec<_>>(), model);
                }
            });
        }
    });

    assert_eq!(root(&mut base), reference_root(&vals));
    drop(base);
    drop_last(pool);
}

#[test]
fn a_clone_writes_into_the_parked_flat_tree() {
    let vals: Vec<u64> = (0..5000).collect();
    let mut parent = list(&vals);
    let mut child = forked(&mut parent);
    child.set(3, 9);
    child.commit();

    let mut sibling = parent.clone();
    sibling.set(4999, 5);
    assert!(parent.pool.spare.load(Ordering::Acquire).is_null(), "the write took the spare");
    let mut model = vals.clone();
    model[4999] = 5;
    assert_eq!(sibling.iter().collect::<Vec<_>>(), model);
    assert_eq!(root(&mut sibling), reference_root(&model));

    let mut child_model = vals.clone();
    child_model[3] = 9;
    assert_eq!(child.hash_root(), reference_root(&child_model));
    assert_eq!(parent.hash_root(), reference_root(&vals), "the parent saw no write");
}

#[test]
fn a_progressive_spare_reloads_into_a_fixed_list() {
    let vals: Vec<u64> = (0..3000).collect();
    let mut fixed = list(&vals);
    let mut progressive = forked(&mut fixed);
    progressive.migrate_to_progressive();
    progressive.push(1);
    assert_eq!(root(&mut progressive), progressive_reference(&[&vals[..], &[1]].concat()));

    fixed.set(0, 7);
    let mut model = vals;
    model[0] = 7;
    assert_eq!(root(&mut fixed), reference_root(&model));
    assert_eq!(fixed.iter().collect::<Vec<_>>(), model);
}

#[test]
fn pushing_zeros_commits_the_new_length() {
    let mut list = list(&[1]);
    list.push(0);
    list.push(0);
    assert_eq!(root(&mut list), reference_root(&[1, 0, 0]));
    assert_eq!(forked(&mut list).len(), 3);
}

#[test]
fn write_ssz_reads_the_flat_tree_and_the_pages_alike() {
    let vals: Vec<u64> = (0..3000).map(|i| i * 3).collect();
    let mut flat = list(&vals);
    flat.set(7, 1);
    flat.commit();
    let paged = forked(&mut flat);
    let (mut a, mut b) = (Vec::new(), Vec::new());
    flat.write_ssz(&mut a).unwrap();
    paged.write_ssz(&mut b).unwrap();
    let mut model = vals;
    model[7] = 1;
    assert_eq!(a, u64::as_ssz_bytes(&model).into_owned());
    assert_eq!(a, b);
}

#[test]
fn an_uncommitted_clone_carries_the_writes_and_diverges() {
    let mut vals: Vec<u64> = (0..5000).collect();
    let mut a = list(&vals);
    let pool = a.pool.clone();
    assert_eq!(root(&mut a), reference_root(&vals));

    for i in [3, 700, 4999] {
        a.set(i, 99);
        vals[i] = 99;
    }
    assert!(!a.is_committed());
    let mut b = a.clone();
    assert!(!b.is_committed());
    assert_eq!(b.iter().collect::<Vec<_>>(), vals);

    let mut vals_b = vals.clone();
    b.set(10, 7);
    vals_b[10] = 7;
    b.push(1);
    vals_b.push(1);
    assert_eq!(root(&mut b), reference_root(&vals_b));
    assert_eq!(root(&mut a), reference_root(&vals));
    assert_eq!(a.iter().collect::<Vec<_>>(), vals);

    let c = b.clone();
    assert!(c.is_committed());
    assert_eq!(c.hash_root(), reference_root(&vals_b));
    drop(c);
    drop(b);
    drop(a);
    drop_last(pool);
}
