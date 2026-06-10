use super::layer::{rebase_and_prune_sparse, sparse_merge_into};

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Edits<V> {
    inner: Vec<(u32, V)>,
}

// Manual Clone: `clone_from` must reuse the existing allocation (same
// rationale as `SlotState`'s impl in `types.rs`).
impl<V: Clone> Clone for Edits<V> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }

    fn clone_from(&mut self, other: &Self) {
        self.inner.clone_from(&other.inner);
    }
}

impl<V> Edits<V> {
    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    #[inline]
    pub fn iter(&self) -> std::slice::Iter<'_, (u32, V)> {
        self.inner.iter()
    }

    #[inline]
    pub fn partition_point(&self, pred: impl FnMut(&(u32, V)) -> bool) -> usize {
        self.inner.partition_point(pred)
    }

    #[inline]
    pub fn iter_from(&self, start: usize) -> std::slice::Iter<'_, (u32, V)> {
        self.inner[start..].iter()
    }

    #[inline]
    pub fn get(&self, idx: u32) -> Option<&V> {
        self.inner.binary_search_by_key(&idx, |(k, _)| *k).ok().map(|p| &self.inner[p].1)
    }

    #[inline]
    pub fn as_slice(&self) -> &[(u32, V)] {
        &self.inner
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[inline]
    pub fn retain(&mut self, f: impl FnMut(&(u32, V)) -> bool) {
        self.inner.retain(f);
    }
}

impl<V: PartialEq> Edits<V> {
    /// Drop edits below `new_base_count` that the (advanced) base already
    /// reflects — keep only entries diverging from `base_at`.
    pub fn retain_diverged(&mut self, new_base_count: usize, base_at: impl Fn(usize) -> V) {
        self.inner
            .retain(|(idx, v)| (*idx as usize) >= new_base_count || base_at(*idx as usize) != *v);
    }
}

impl<V: Copy + PartialEq> Edits<V> {
    /// Finalize a survivor's edits against a promoted `winner`; see
    /// [`rebase_and_prune_sparse`].
    pub fn rebase_and_prune(
        &self,
        winner: &Self,
        valid_below: u32,
        new_count: u32,
        old_base_at: impl Fn(u32) -> V,
        new_base_at: impl Fn(u32) -> V,
    ) -> Self {
        Self {
            inner: rebase_and_prune_sparse(
                &self.inner,
                &winner.inner,
                valid_below,
                new_count,
                old_base_at,
                new_base_at,
            ),
        }
    }
}

impl<V: Copy> Edits<V> {
    /// Merge an ascending distinct-key `changes` batch; see
    /// [`sparse_merge_into`].
    #[inline]
    pub fn merge_in_place(&mut self, changes: &[(u32, V)]) {
        sparse_merge_into(&mut self.inner, changes);
    }
}
