use crate::{
    merkle::{ZERO_HASHES, hash_concat_many},
    types::B256,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NodeRange {
    pub(super) start: u32,
    pub(super) end: u32,
}

impl NodeRange {
    #[inline]
    pub(super) fn single(id: u32) -> Self {
        Self { start: id, end: id + 1 }
    }

    #[inline]
    pub(super) fn contains(self, id: u32) -> bool {
        (self.start..self.end).contains(&id)
    }

    #[inline]
    fn parent(self, base: u32) -> Self {
        Self { start: base + (self.start >> 1), end: base + ((self.end - 1) >> 1) + 1 }
    }

    #[inline]
    pub(super) fn try_merge(&mut self, later: Self) -> bool {
        if later.start > self.end {
            return false;
        }
        self.end = self.end.max(later.end);
        true
    }
}

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

pub(super) fn rehash_subtree(internal: &mut [B256], leaves: &[B256], dirty: &mut [NodeRange]) {
    let cap = internal.len();
    if cap <= 1 || dirty.is_empty() {
        return;
    }
    let bottom = cap >> 1;
    let mut dirty = dedup_parents(dirty, bottom as u32);
    hash_runs(internal, leaves, dirty, bottom);

    let mut level = bottom;
    while level > 1 {
        dirty = dedup_parents(dirty, 0);
        level >>= 1;
        let (parents, children) = internal.split_at_mut(2 * level);
        hash_runs(parents, children, dirty, level);
    }
}

fn hash_runs(parents: &mut [B256], children: &[B256], dirty: &[NodeRange], child_base: usize) {
    for r in dirty {
        let (lo, hi) = (r.start as usize, r.end as usize);
        hash_concat_many(
            &mut parents[lo..hi],
            &children[2 * (lo - child_base)..2 * (hi - child_base)],
        );
    }
}

fn dedup_parents(dirty: &mut [NodeRange], base: u32) -> &mut [NodeRange] {
    let mut n = 0;
    for j in 0..dirty.len() {
        let parent = dirty[j].parent(base);
        if n > 0 && dirty[n - 1].try_merge(parent) {
            continue;
        }
        dirty[n] = parent;
        n += 1;
    }
    &mut dirty[..n]
}
