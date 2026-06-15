/// A column's sparse delta: a `Vec<(idx, value)>` kept sorted by `idx`,
/// overlaying a dense finalized base.
#[derive(Debug, PartialEq, Eq)]
pub struct Edits<V> {
    inner: Vec<(u32, V)>,
}

// Manual impl: the derive would spuriously bind `V: Default` (an empty vec
// needs no element default).
impl<V> Default for Edits<V> {
    fn default() -> Self {
        Self { inner: Vec::new() }
    }
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

    /// Iterate edits from the first whose key is `>= from` (a `partition_point`
    /// over the ascending keys, then the tail).
    #[inline]
    pub fn iter_from(&self, from: u32) -> std::slice::Iter<'_, (u32, V)> {
        self.inner[self.inner.partition_point(|(k, _)| *k < from)..].iter()
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
    /// Finalize these (a survivor's) edits against a promoted `winner` in one
    /// pass, returning a fresh `Edits`. Fuses:
    /// - **rebase**: every index `< valid_below` that `winner` overrides and
    ///   `self` does not is pinned to its *old* base value (`old_base_at`), so
    ///   the survivor keeps reading the pre-promote value (ABA hazard).
    /// - **prune**: any resulting entry `< new_count` that already equals the
    ///   *new* base — `winner`'s override there, else `old_base_at` — is
    ///   dropped as redundant.
    ///
    /// Output is the ascending merge (survivor's value wins on a shared index).
    pub fn rebase_and_prune(
        &self,
        winner: &Self,
        valid_below: u32,
        new_count: u32,
        old_base_at: impl Fn(u32) -> V,
    ) -> Self {
        let survivor = &self.inner;
        debug_assert!(
            survivor.windows(2).all(|w| w[0].0 < w[1].0),
            "survivor must be ascending with distinct indices",
        );
        debug_assert!(
            winner.inner.windows(2).all(|w| w[0].0 < w[1].0),
            "winner must be ascending with distinct indices",
        );
        let mut out: Vec<(u32, V)> = Vec::with_capacity(survivor.len() + winner.inner.len());
        let mut keep = |idx: u32, v: V| {
            // New base at `idx`: the winner's override there, else the old base.
            let new_base = winner.get(idx).copied().unwrap_or_else(|| old_base_at(idx));
            if idx >= new_count || new_base != v {
                out.push((idx, v));
            }
        };

        let (mut i, mut j) = (0, 0);
        while i < survivor.len() && j < winner.inner.len() {
            let (si, sv) = survivor[i];
            let wi = winner.inner[j].0;
            if wi >= valid_below {
                break; // no winner index from here injects
            }
            if si < wi {
                keep(si, sv);
                i += 1;
            } else if si == wi {
                keep(si, sv); // survivor overrides the winner's pin
                i += 1;
                j += 1;
            } else {
                keep(wi, old_base_at(wi)); // pin the old base value
                j += 1;
            }
        }
        while j < winner.inner.len() && winner.inner[j].0 < valid_below {
            let wi = winner.inner[j].0;
            keep(wi, old_base_at(wi));
            j += 1;
        }
        while i < survivor.len() {
            let (si, sv) = survivor[i];
            keep(si, sv);
            i += 1;
        }
        Self { inner: out }
    }
}

impl<V: Copy> Edits<V> {
    /// Merge an ascending, distinct-key `changes` batch in O(|edits| +
    /// |batch|), the batch value winning on a shared `idx`. Keeps
    /// base-equal entries (the read sweep / rebase tolerate redundant
    /// edits), so it runs in place with no auxiliary buffer — unlike
    /// per-element insert, which is O(|edits|) each (quadratic over an
    /// epoch's accumulated edits).
    #[inline]
    pub fn merge_in_place(&mut self, changes: &[(u32, V)]) {
        debug_assert!(
            changes.windows(2).all(|w| w[0].0 < w[1].0),
            "batch must be ascending with distinct indices",
        );
        let old_len = self.inner.len();
        let insert_count = self.override_existing(changes);
        if insert_count == 0 {
            return;
        }
        self.merge_insertions_phase(changes, old_len, insert_count);
    }

    /// Merged read over the base + these edits, for `i` in `0..total`: yields
    /// the edit at `i` if present, else `base_at(i)` for `i < base_count`, else
    /// `tail(i)` (indices past the base — e.g. validators appended in this
    /// fork, or a column's appended-default zero).
    #[inline]
    pub fn sweep<'b>(
        &'b self,
        base_count: usize,
        total: usize,
        base_at: impl Fn(usize) -> V + 'b,
        tail: impl Fn(usize) -> V + 'b,
    ) -> impl Iterator<Item = V> + 'b {
        let edits = &self.inner;
        let mut cursor = 0usize;
        (0..total).map(move |i| {
            if cursor < edits.len() && (edits[cursor].0 as usize) == i {
                let v = edits[cursor].1;
                cursor += 1;
                v
            } else if i < base_count {
                base_at(i)
            } else {
                tail(i)
            }
        })
    }
}

/// In-place sorted-merge internals for
/// [`merge_in_place`](Edits::merge_in_place).
impl<V: Copy> Edits<V> {
    /// Phase 1 — overwrite the override entries in place and count the
    /// genuinely new (non-matching) changes, returned for phase 2 to
    /// insert.
    ///
    /// Small batches use per-change binary search (O(m log n)); large batches
    /// use a linear merge (O(m + n)) seeded at the first change.
    fn override_existing(&mut self, changes: &[(u32, V)]) -> usize {
        let n = self.inner.len();
        let m = changes.len();
        if m == 0 {
            return 0;
        }
        let log_n = usize::BITS as usize - n.max(1).leading_zeros() as usize;
        if m.saturating_mul(log_n) <= m + n {
            self.override_by_search(changes)
        } else {
            self.override_by_scan(changes)
        }
    }

    /// O(m log n) — one binary search per change; best when `m ≪ n`.
    fn override_by_search(&mut self, changes: &[(u32, V)]) -> usize {
        let mut inserts = 0;
        for &(idx, val) in changes {
            match self.inner.binary_search_by_key(&idx, |(k, _)| *k) {
                Ok(p) => self.inner[p].1 = val,
                Err(_) => inserts += 1,
            }
        }
        inserts
    }

    /// O(m + n) merge, starting at the first edit ≥ `changes[0].0`.
    fn override_by_scan(&mut self, changes: &[(u32, V)]) -> usize {
        let old_len = self.inner.len();
        let changes_len = changes.len();

        let mut edit_idx = self.inner.partition_point(|(k, _)| *k < changes[0].0);
        let mut change_idx = 0;
        let mut inserts = 0;
        while edit_idx < old_len && change_idx < changes_len {
            let ek = self.inner[edit_idx].0;
            let ck = changes[change_idx].0;
            if ek < ck {
                edit_idx += 1;
            } else if ek == ck {
                self.inner[edit_idx].1 = changes[change_idx].1;
                edit_idx += 1;
                change_idx += 1;
            } else {
                inserts += 1;
                change_idx += 1;
            }
        }
        inserts + (changes_len - change_idx)
    }

    /// Phase 2 — right-to-left merge of the (already overridden) edits with the
    /// pure insertions from `changes`.
    #[allow(clippy::uninit_vec)]
    fn merge_insertions_phase(
        &mut self,
        changes: &[(u32, V)],
        old_len: usize,
        insert_count: usize,
    ) {
        self.inner.reserve(insert_count);
        // SAFETY: every slot in `old_len..old_len + insert_count` is written
        // before any read (the write ≥ ei invariant below); (u32, V) is Copy.
        unsafe { self.inner.set_len(old_len + insert_count) };

        let mut edit_idx = old_len;
        let mut change_idx = changes.len();
        let mut write = old_len + insert_count;
        while edit_idx > 0 && change_idx > 0 {
            debug_assert!(write >= edit_idx, "merge: write must converge to the unshifted prefix");

            let (ek, ev) = self.inner[edit_idx - 1];
            let (ck, cv) = changes[change_idx - 1];
            write -= 1;
            if ek > ck {
                self.inner[write] = (ek, ev);
                edit_idx -= 1;
            } else if ek == ck {
                self.inner[write] = (ek, ev);
                edit_idx -= 1;
                change_idx -= 1;
            } else {
                self.inner[write] = (ck, cv);
                change_idx -= 1;
            }
        }
        // Remaining `changes` are pure insertions; remaining `edits` entries are
        // already in their final slots (write == edit_idx).
        while change_idx > 0 {
            change_idx -= 1;
            write -= 1;
            self.inner[write] = changes[change_idx];
        }
        debug_assert_eq!(write, edit_idx, "merge: write must converge to the unshifted prefix");
    }
}
