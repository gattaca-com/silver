use std::collections::HashMap;

use rand::{RngCore, SeedableRng, rngs::StdRng};
use silver_common::ssz_hash::{
    MerkleStack, compute_zero_hashes, hash_concat, merkle_finalize, merkle_push, mix_in_length,
};

use super::{FinalizedHashTree, HashTreeState};
use crate::types::B256;

/// SSZ-spec list capacity exponent used across the tests; matches the
/// real `VALIDATOR_REGISTRY_LIMIT = 1 << 40`.
const SPEC_DEPTH: u8 = 40;

fn random_leaf(rng: &mut StdRng) -> B256 {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    b
}

/// Reference SSZ `List<B256, 1<<spec_depth>` root via the existing primitives.
fn reference_root(leaves: &[B256], spec_depth: u8) -> B256 {
    let zh = compute_zero_hashes();
    let mut stack = MerkleStack::new();
    for l in leaves {
        merkle_push(&mut stack, *l);
    }
    let root = merkle_finalize(stack, spec_depth, &zh);
    mix_in_length(&root, leaves.len())
}

/// Caller-side SSZ wrap of our tree's physical root: zero-pad from the
/// tree's physical depth up to `spec_depth`, then `mix_in_length(len)`.
/// Models the wrapping a real consumer (e.g. validators field) will do.
fn ssz_list_root(physical_root: &B256, max_elements: usize, spec_depth: u8, len: usize) -> B256 {
    let zh = compute_zero_hashes();
    let phys_depth = max_elements.trailing_zeros() as u8;
    debug_assert!(spec_depth >= phys_depth);
    let mut acc = *physical_root;
    for d in phys_depth..spec_depth {
        acc = hash_concat(&acc, &zh[d as usize]);
    }
    mix_in_length(&acc, len)
}

#[test]
fn test_finilized_hash_tree() {
    let mut rng = StdRng::seed_from_u64(0xF1);

    for &n in &[0_usize, 1, 7, 8, 9, 1024] {
        let leaves: Vec<B256> = (0..n).map(|_| random_leaf(&mut rng)).collect();
        let tree = FinalizedHashTree::new(leaves.clone());
        let got = ssz_list_root(tree.root_hash(), tree.max_elements(), SPEC_DEPTH, leaves.len());
        let want = reference_root(&leaves, SPEC_DEPTH);
        assert_eq!(got, want, "mismatch at n={n}");
    }
}

#[test]
fn test_deltas_hash_tree() {
    let n = 256_usize;
    let m = 200_usize; // number of updates

    let base = FinalizedHashTree::new(vec![[0u8; 32]; n]);
    let mut state = HashTreeState::with_empty_delta(&base);
    let mut real_data = vec![[0u8; 32]; n];

    let mut rng = StdRng::seed_from_u64(0xD2);
    for _ in 0..m {
        let i = (rng.next_u32() as usize) % n;
        let leaf = random_leaf(&mut rng);
        state.set_leaf(i, leaf);
        real_data[i] = leaf;
    }

    let got = ssz_list_root(&state.root_hash(), base.max_elements(), SPEC_DEPTH, real_data.len());
    let want = reference_root(&real_data, SPEC_DEPTH);
    assert_eq!(got, want);
}

#[test]
fn test_promote_and_prune() {
    let n = 256_usize;
    let writes_per_fork = 32_usize;

    let mut base = FinalizedHashTree::new(vec![[0u8; 32]; n]);
    let mut real_data = vec![[0u8; 32]; n];
    let mut rng = StdRng::seed_from_u64(0x9A);

    // Three sequential forks: each is a descendant of the previous.
    let mut fork_a = HashTreeState::with_empty_delta(&base);
    for _ in 0..writes_per_fork {
        let i = (rng.next_u32() as usize) % n;
        let leaf = random_leaf(&mut rng);
        fork_a.set_leaf(i, leaf);
        real_data[i] = leaf;
    }

    let mut fork_b = fork_a.clone();
    for _ in 0..writes_per_fork {
        let i = (rng.next_u32() as usize) % n;
        let leaf = random_leaf(&mut rng);
        fork_b.set_leaf(i, leaf);
        real_data[i] = leaf;
    }

    let mut fork_c = fork_b.clone();
    for _ in 0..writes_per_fork {
        let i = (rng.next_u32() as usize) % n;
        let leaf = random_leaf(&mut rng);
        fork_c.set_leaf(i, leaf);
        real_data[i] = leaf;
    }

    let pre_root = fork_c.root_hash();

    // Finalise on the middle fork. Ancestor fork_a is dropped (its history is
    // absorbed via fork_b); fork_b's delta is folded into base; both fork_b
    // and the surviving descendant fork_c re-anchor by pruning.
    drop(fork_a);
    fork_b.promote_into_base(&mut base);
    fork_b.prune_to_base(&base);
    fork_c.prune_to_base(&base);

    assert_eq!(fork_c.root_hash(), pre_root, "prune preserves descendant view");

    let got = ssz_list_root(&fork_c.root_hash(), base.max_elements(), SPEC_DEPTH, real_data.len());
    let want = reference_root(&real_data, SPEC_DEPTH);
    assert_eq!(got, want);
}

#[test]
fn fuzz_random_ops_hash_tree() {
    let seed: u64 =
        std::env::var("FUZZ_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or_else(|| {
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
                as u64
        });
    println!(
        "fuzz_random_ops_hash_tree seed = {seed} (set FUZZ_SEED environment variable to reproduce)"
    );

    let mut rng = StdRng::seed_from_u64(seed);
    let max_leafs = 1024_usize;

    struct Fork {
        state: HashTreeState,
        real_data: Vec<B256>,
        parent: Option<usize>,
    }

    let mut forks = HashMap::new();
    let mut base = FinalizedHashTree::new(vec![[0u8; 32]; max_leafs]);
    forks.insert(0, Fork {
        state: HashTreeState::with_empty_delta(&base),
        real_data: Vec::new(),
        parent: None,
    });

    let mut next_id: usize = 1;
    let mut alive: Vec<usize> = vec![0];

    let verify = |forks: &HashMap<usize, Fork>, base: &FinalizedHashTree, j: usize, ctx: &str| {
        let f = &forks[&j];
        let got =
            ssz_list_root(&f.state.root_hash(), base.max_elements(), SPEC_DEPTH, f.real_data.len());
        let want = reference_root(&f.real_data, SPEC_DEPTH);
        assert_eq!(got, want, "mismatch {ctx} fork={j}");
    };

    for step in 0..8000_u32 {
        let idx = alive[rng.next_u32() as usize % alive.len()];
        let op = rng.next_u32() % 100;

        if op < 80 {
            let parent = &forks[&idx];
            let mut new_state = parent.state.clone();
            let mut new_data = parent.real_data.clone();

            if new_data.is_empty() || (new_data.len() < max_leafs && rng.next_u32() % 2 == 0) {
                // Append a new leaf to the fork's real_data.
                let leaf = random_leaf(&mut rng);
                let i = new_data.len();
                new_state.set_leaf(i, leaf);
                new_data.push(leaf);
            } else {
                // Modify a random leaf.
                let i = (rng.next_u32() as usize) % new_data.len();
                let leaf = random_leaf(&mut rng);
                new_state.set_leaf(i, leaf);
                new_data[i] = leaf;
            }
            forks.insert(next_id, Fork {
                state: new_state,
                real_data: new_data,
                parent: Some(idx),
            });
            alive.push(next_id);

            // Only the new fork's view changed; nothing else needs re-checking.
            verify(&forks, &base, next_id, &format!("at step={step}, advance"));
            next_id += 1;
        } else {
            // Finalise the chosen fork.
            let mut survivors: Vec<usize> = vec![idx];
            for &j in &alive {
                if j == idx {
                    continue;
                }
                let mut cur = forks[&j].parent;
                let mut is_descendant = false;
                while let Some(c) = cur {
                    if c == idx {
                        is_descendant = true;
                        break;
                    }
                    cur = forks.get(&c).and_then(|f| f.parent);
                }
                if is_descendant {
                    survivors.push(j);
                } else {
                    forks.remove(&j);
                }
            }

            forks[&idx].state.promote_into_base(&mut base);
            for &j in &survivors {
                forks.get_mut(&j).unwrap().state.prune_to_base(&base);
                verify(&forks, &base, j, &format!("at step={step}, finalize"));
            }
            alive = survivors;
        }
    }
}
