use crate::{
    B256,
    merkle::{ZERO_HASHES, hash_concat_many},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NodeRange {
    pub(super) start: u32,
    pub(super) end: u32,
}

impl NodeRange {
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

pub(crate) fn build_subtree_hashes(internal: &mut [B256], leaves: &[B256], non_zero: usize) {
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

/// Short dirty runs share `hash_concat_many` calls, so scattered writes still
/// fill whole SIMD groups.
fn hash_runs(parents: &mut [B256], children: &[B256], dirty: &[NodeRange], child_base: usize) {
    let mut batch = RunBatch::default();
    for r in dirty {
        let (lo, hi) = (r.start as usize, r.end as usize);
        if hi - lo >= RUN_BATCH {
            hash_concat_many(
                &mut parents[lo..hi],
                &children[2 * (lo - child_base)..2 * (hi - child_base)],
            );
            continue;
        }
        for parent in lo..hi {
            let child = 2 * (parent - child_base);
            batch.push(parent, &children[child..child + 2], parents);
        }
    }
    batch.flush(parents);
}

const RUN_BATCH: usize = 16;

#[derive(Default)]
struct RunBatch {
    pairs: [[B256; 2]; RUN_BATCH],
    parents: [usize; RUN_BATCH],
    len: usize,
}

impl RunBatch {
    fn push(&mut self, parent: usize, pair: &[B256], parents: &mut [B256]) {
        self.pairs[self.len].copy_from_slice(pair);
        self.parents[self.len] = parent;
        self.len += 1;
        if self.len == RUN_BATCH {
            self.flush(parents);
        }
    }

    fn flush(&mut self, parents: &mut [B256]) {
        let mut hashed = [[0; 32]; RUN_BATCH];
        hash_concat_many(&mut hashed[..self.len], self.pairs[..self.len].as_flattened());
        for (&parent, hash) in self.parents[..self.len].iter().zip(hashed) {
            parents[parent] = hash;
        }
        self.len = 0;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rehash_of_scattered_leaves_matches_rebuild() {
        const CAP: usize = 1 << 10;
        let mut leaves: Vec<B256> = (0..CAP).map(|i| [i as u8; 32]).collect();
        let mut internal = vec![[0; 32]; CAP];
        build_subtree_hashes(&mut internal, &leaves, CAP);

        let mut dirty: Vec<_> =
            (0..CAP as u32 - 64).step_by(7).map(|i| NodeRange { start: i, end: i + 1 }).collect();
        dirty.push(NodeRange { start: CAP as u32 - 40, end: CAP as u32 });
        for r in &dirty {
            leaves[r.start as usize..r.end as usize].fill([0xFF; 32]);
        }
        rehash_subtree(&mut internal, &leaves, &mut dirty);

        let mut rebuilt = vec![[0; 32]; CAP];
        build_subtree_hashes(&mut rebuilt, &leaves, CAP);
        assert_eq!(internal, rebuilt);
    }
}
