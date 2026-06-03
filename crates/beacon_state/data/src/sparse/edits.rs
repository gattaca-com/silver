use std::ops::Deref;

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct Edits<V> {
    inner: Vec<(u32, V)>,
}

impl<V> Edits<V> {
    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    #[inline]
    pub fn retain(&mut self, keep: impl FnMut(&(u32, V)) -> bool) {
        self.inner.retain(keep);
    }
}

impl<V: Copy> Edits<V> {
    #[inline]
    pub fn merge_in_place(&mut self, changes: &[(u32, V)]) {
        let old_len = self.inner.len();
        let insert_count = self.override_existing(changes);
        if insert_count == 0 {
            return;
        }
        self.merge_insertions_phase(changes, old_len, insert_count);
    }

    /// Phase 1 — overwrite override entries in `self` in place and count the
    /// genuinely new (non-matching) changes, returned for phase 2 to insert.
    ///
    /// Small batches use per-change binary search (O(m log n)); large batches
    /// use a linear merge (O(m + n)) seeded at the first change via
    /// `partition_point`.
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

    /// Phase 2 — right-to-left merge of the(already overridden values
    #[allow(clippy::uninit_vec)]
    fn merge_insertions_phase(
        &mut self,
        changes: &[(u32, V)],
        old_len: usize,
        insert_count: usize,
    ) {
        self.inner.reserve(insert_count);
        // SAFETY: every slot in `old_len..old_len + insert_count` is written
        // before any read (write ≥ ei invariant below); (u32, V) is Copy.
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
        // Remaining `changes` are pure insertions; remaining `self` entries are
        // already in their final slots (write == edit_idx).
        while change_idx > 0 {
            change_idx -= 1;
            write -= 1;
            self.inner[write] = changes[change_idx];
        }
        debug_assert_eq!(write, edit_idx, "merge: write must converge to the unshifted prefix");
    }
}

impl<V> Deref for Edits<V> {
    type Target = [(u32, V)];

    #[inline]
    fn deref(&self) -> &[(u32, V)] {
        &self.inner
    }
}
