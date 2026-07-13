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

    #[cfg(test)]
    pub fn iter(&self) -> std::slice::Iter<'_, (u32, V)> {
        self.inner.iter()
    }

    #[inline]
    pub fn get(&self, idx: u32) -> Option<&V> {
        self.inner.binary_search_by_key(&idx, |(k, _)| *k).ok().map(|p| &self.inner[p].1)
    }

    /// First position ≥ `from` whose index is ≥ `idx`, found by galloping.
    fn position_from(&self, from: usize, idx: u32) -> usize {
        let edits = &self.inner;
        let (mut lo, mut step) = (from, 1);
        while lo + step <= edits.len() && edits[lo + step - 1].0 < idx {
            lo += step;
            step *= 2;
        }
        let hi = (lo + step - 1).min(edits.len());
        lo + edits[lo..hi].partition_point(|&(k, _)| k < idx)
    }
}

impl<V: Copy + PartialEq> Edits<V> {
    pub fn rebase_and_prune_from(
        &mut self,
        survivor: &Self,
        winner: &Self,
        new_count: u32,
        old_base_at: impl Fn(u32) -> V,
    ) {
        let survivor = &survivor.inner;
        debug_assert!(
            survivor.windows(2).all(|w| w[0].0 < w[1].0),
            "survivor must be ascending with distinct indices",
        );
        debug_assert!(
            winner.inner.windows(2).all(|w| w[0].0 < w[1].0),
            "winner must be ascending with distinct indices",
        );
        let winner = &winner.inner;
        let out = &mut self.inner;
        out.clear();
        out.reserve(survivor.len() + winner.len());

        let mut j = 0;
        for k in 0..=survivor.len() {
            let entry = survivor.get(k);
            let si = entry.map_or(u32::MAX, |&(i, _)| i);

            while j < winner.len() && winner[j].0 < si {
                let (wi, wv) = winner[j];
                let old = old_base_at(wi);
                if old != wv {
                    out.push((wi, old));
                }
                j += 1;
            }

            let Some(&(_, sv)) = entry else { break };

            let new_base = if j < winner.len() && winner[j].0 == si {
                let wv = winner[j].1;
                j += 1; // survivor's value wins over the winner's pin at `si`
                Some(wv)
            } else if si < new_count {
                Some(old_base_at(si))
            } else {
                None
            };
            if new_base != Some(sv) {
                out.push((si, sv));
            }
        }
    }
}

impl Edits<bool> {
    /// Scatter these boolean edits into a packed bitset `col`, where logical
    /// index `i` is bit `i % 8` of byte `i / 8`.
    #[inline]
    pub fn scatter_bits(&self, col: &mut [u8]) {
        for &(idx, v) in &self.inner {
            let (byte, mask) = (idx as usize / 8, 1u8 << (idx % 8));
            if v {
                col[byte] |= mask;
            } else {
                col[byte] &= !mask;
            }
        }
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

    /// Scatter these edits into `col`, writing each value at its absolute
    /// index. Used to fold a fork's edits into the finalized base column.
    #[inline]
    pub fn scatter(&self, col: &mut [V]) {
        for &(idx, v) in &self.inner {
            col[idx as usize] = v;
        }
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
    /// genuinely new (non-matching) changes, returned for phase 2 to insert.
    /// Gallops through the ascending batch: O(log gap) per change, so ~O(m +
    /// n) when dense and O(m log n) when sparse.
    fn override_existing(&mut self, changes: &[(u32, V)]) -> usize {
        let mut inserts = 0;
        let mut cursor = 0;
        for &(idx, val) in changes {
            cursor = self.position_from(cursor, idx);
            match self.inner.get_mut(cursor) {
                Some(entry) if entry.0 == idx => entry.1 = val,
                _ => inserts += 1,
            }
        }
        inserts
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
