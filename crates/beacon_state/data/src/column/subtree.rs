use crate::{
    merkle::{ZERO_HASHES, hash_concat_many},
    types::B256,
};

pub(super) fn build_subtree_hashes(internal: &mut [B256], leaves: &[B256], non_zero: usize) {
    let cap = internal.len();
    if cap <= 1 {
        return;
    }
    let mut level = cap >> 1;
    let mut non_zero = non_zero.min(cap).div_ceil(2);
    if non_zero > 0 {
        hash_concat_many(&mut internal[level..level + non_zero], &leaves[..2 * non_zero]);
    }
    internal[level + non_zero..cap].fill(ZERO_HASHES[1]);

    let mut zero_depth = 2;
    while level > 1 {
        let parent = level >> 1;
        let next_non_zero = non_zero.div_ceil(2);
        let (parents, children) = internal.split_at_mut(level);
        if next_non_zero > 0 {
            hash_concat_many(
                &mut parents[parent..parent + next_non_zero],
                &children[..2 * next_non_zero],
            );
        }
        parents[parent + next_non_zero..level].fill(ZERO_HASHES[zero_depth]);
        level = parent;
        non_zero = next_non_zero;
        zero_depth += 1;
    }
}

pub(super) fn rehash_subtree(internal: &mut [B256], leaves: &[B256], dirty: &mut [u32]) {
    let cap = internal.len();
    if cap <= 1 || dirty.is_empty() {
        return;
    }
    let bottom = cap >> 1;
    let mut len = dedup_parents(dirty, bottom as u32);
    hash_runs(internal, leaves, &dirty[..len], bottom);

    let mut level = bottom;
    while level > 1 {
        len = dedup_parents(&mut dirty[..len], 0);
        level >>= 1;
        let (parents, children) = internal.split_at_mut(2 * level);
        hash_runs(parents, children, &dirty[..len], level);
    }
}

fn hash_runs(parents: &mut [B256], children: &[B256], dirty: &[u32], child_base: usize) {
    let mut i = 0;
    while i < dirty.len() {
        let start = i;
        while i + 1 < dirty.len() && dirty[i + 1] == dirty[i] + 1 {
            i += 1;
        }
        i += 1;
        let (lo, hi) = (dirty[start] as usize, dirty[i - 1] as usize + 1);
        hash_concat_many(
            &mut parents[lo..hi],
            &children[2 * (lo - child_base)..2 * (hi - child_base)],
        );
    }
}

fn dedup_parents(dirty: &mut [u32], base: u32) -> usize {
    let mut n = 0;
    for j in 0..dirty.len() {
        let parent = base + (dirty[j] >> 1);
        if n == 0 || dirty[n - 1] != parent {
            dirty[n] = parent;
            n += 1;
        }
    }
    n
}
