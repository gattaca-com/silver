//! Shared substrate for sibling sparse columns (`participation`,
//! `inactivity_scores`, …): a sorted `Vec<(idx, value)>` delta over a dense
//! finalized base. The free fns here are the read sweep and the write
//! primitives; [`SparseLayer`] lets the `set`/`replace`/`install` helpers run
//! against any column with a single substitution point.

/// Merged per-validator column sweep: yields `edits[i]` if present, else
/// `base[i]`, else `appended_default` (for appended validators past the base).
/// Shared by both views' `iter_*` reads.
pub(crate) fn sweep<'b, T>(
    edits: &'b [(u32, T)],
    base: &'b [T],
    appended_default: T,
    total: usize,
) -> impl Iterator<Item = T> + 'b
where
    T: Copy,
{
    let mut cursor = 0usize;
    (0..total).map(move |i| {
        if cursor < edits.len() && (edits[cursor].0 as usize) == i {
            let v = edits[cursor].1;
            cursor += 1;
            v
        } else if i < base.len() {
            base[i]
        } else {
            appended_default
        }
    })
}

#[inline]
pub(crate) fn lookup_sparse<T: Copy>(edits: &[(u32, T)], idx: u32) -> Option<T> {
    edits.binary_search_by_key(&idx, |(k, _)| *k).ok().map(|p| edits[p].1)
}

/// Sparse-vec setter — maintains the sorted-by-idx invariant. Elides
/// entries that match the base (and removes any stale edit at that idx),
/// so `sparse_set(i, base_val, base_val)` removes any prior edit at i.
#[inline]
pub(crate) fn sparse_set<T>(edits: &mut Vec<(u32, T)>, idx: u32, v: T, base_val: T)
where
    T: Copy + PartialEq,
{
    match edits.binary_search_by_key(&idx, |(k, _)| *k) {
        Ok(p) => {
            if v == base_val {
                edits.remove(p);
            } else {
                edits[p].1 = v;
            }
        }
        Err(p) => {
            if v != base_val {
                edits.insert(p, (idx, v));
            }
        }
    }
}

/// Merge `changes` (ascending, distinct `idx`) into the sorted `edits` vec,
/// batch value winning on a shared `idx`.
///
/// Per-element `sparse_set` is O(|edits|) each (binary-search insert shifts the
/// tail), so applying a committee's worth of edits one at a time is quadratic
/// over an epoch's accumulated participation edits. Unlike `sparse_set` this
/// keeps base-equal entries — the read sweep and `prune_to_base` both tolerate
/// redundant edits, which lets the merge run in place with no auxiliary buffer.
#[inline]
pub(crate) fn sparse_merge_into<T: Copy>(edits: &mut Vec<(u32, T)>, changes: &[(u32, T)]) {
    debug_assert!(
        changes.windows(2).all(|w| w[0].0 < w[1].0),
        "batch must be ascending with distinct indices",
    );
    let old_len = edits.len();
    let insert_count = override_existing(edits, changes);
    if insert_count == 0 {
        return;
    }
    merge_insertions_phase(edits, changes, old_len, insert_count);
}

/// Phase 1 — overwrite override entries in `edits` in place and count the
/// genuinely new (non-matching) changes, returned for phase 2 to insert.
///
/// Small batches use per-change binary search (O(m log n)); large batches
/// use a linear merge (O(m + n)) seeded at the first change via
/// `partition_point`.
fn override_existing<T: Copy>(edits: &mut [(u32, T)], changes: &[(u32, T)]) -> usize {
    let n = edits.len();
    let m = changes.len();
    if m == 0 {
        return 0;
    }
    let log_n = usize::BITS as usize - n.max(1).leading_zeros() as usize;
    if m.saturating_mul(log_n) <= m + n {
        override_by_search(edits, changes)
    } else {
        override_by_scan(edits, changes)
    }
}

/// O(m log n) — one binary search per change; best when `m ≪ n`.
fn override_by_search<T: Copy>(edits: &mut [(u32, T)], changes: &[(u32, T)]) -> usize {
    let mut inserts = 0;
    for &(idx, val) in changes {
        match edits.binary_search_by_key(&idx, |(k, _)| *k) {
            Ok(p) => edits[p].1 = val,
            Err(_) => inserts += 1,
        }
    }
    inserts
}

/// O(m + n) merge, starting at the first edit ≥ `changes[0].0`.
fn override_by_scan<T: Copy>(edits: &mut [(u32, T)], changes: &[(u32, T)]) -> usize {
    let old_len = edits.len();
    let changes_len = changes.len();

    let mut edit_idx = edits.partition_point(|(k, _)| *k < changes[0].0);
    let mut change_idx = 0;
    let mut inserts = 0;
    while edit_idx < old_len && change_idx < changes_len {
        let ek = edits[edit_idx].0;
        let ck = changes[change_idx].0;
        if ek < ck {
            edit_idx += 1;
        } else if ek == ck {
            edits[edit_idx].1 = changes[change_idx].1;
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
fn merge_insertions_phase<T: Copy>(
    edits: &mut Vec<(u32, T)>,
    changes: &[(u32, T)],
    old_len: usize,
    insert_count: usize,
) {
    edits.reserve(insert_count);
    // SAFETY: every slot in `old_len..old_len + insert_count` is written
    // before any read (write ≥ ei invariant below); (u32, T) is Copy.
    unsafe { edits.set_len(old_len + insert_count) };

    let mut edit_idx = old_len;
    let mut change_idx = changes.len();
    let mut write = old_len + insert_count;
    while edit_idx > 0 && change_idx > 0 {
        debug_assert!(write >= edit_idx, "merge: write must converge to the unshifted prefix");

        let (ek, ev) = edits[edit_idx - 1];
        let (ck, cv) = changes[change_idx - 1];
        write -= 1;
        if ek > ck {
            edits[write] = (ek, ev);
            edit_idx -= 1;
        } else if ek == ck {
            edits[write] = (ek, ev);
            edit_idx -= 1;
            change_idx -= 1;
        } else {
            edits[write] = (ck, cv);
            change_idx -= 1;
        }
    }
    // Remaining `changes` are pure insertions; remaining `edits` entries are
    // already in their final slots (write == edit_idx).
    while change_idx > 0 {
        change_idx -= 1;
        write -= 1;
        edits[write] = changes[change_idx];
    }
    debug_assert_eq!(write, edit_idx, "merge: write must converge to the unshifted prefix");
}

/// Bulk overwrite — single forward sweep that rebuilds a sparse edit vec
/// using a caller-supplied scratch (reused across calls; no allocation
/// after warmup). For dense epoch-boundary passes
/// (process_rewards_and_penalties, process_inactivity_updates,
/// process_participation_flag_updates). Naive per-i `sparse_set` would
/// be O(N log N) due to binary-search inserts; the sweep is
/// O(N + |edits_old|).
pub(crate) fn sparse_replace_with_scratch<T, F>(
    edits: &mut Vec<(u32, T)>,
    scratch: &mut Vec<(u32, T)>,
    base_slice: &[T],
    appended_default: T,
    total: usize,
    mut f: F,
) where
    T: Copy + PartialEq,
    F: FnMut(usize, T) -> T,
{
    scratch.clear();
    for (i, cur) in sweep(edits, base_slice, appended_default, total).enumerate() {
        let new = f(i, cur);
        let base_val = if i < base_slice.len() { base_slice[i] } else { appended_default };
        if new != base_val {
            scratch.push((i as u32, new));
        }
    }
    std::mem::swap(edits, scratch);
}

/// Finalize a survivor's sparse `edits` against a promoted `winner` in one
/// pass, returning a fresh vec. Fuses:
/// - **rebase**: every index `< valid_below` that `winner` overrides and
///   `survivor` does not is pinned to its *old* base value (`old_base_at`), so
///   the survivor keeps reading the pre-promote value (ABA hazard).
/// - **prune**: any resulting entry `< new_count` that already equals the *new*
///   base (`new_base_at`) is dropped as redundant.
///
/// The output is the ascending merge (survivor's value wins on a shared index
/// — it overrides the base).
pub(crate) fn rebase_and_prune_sparse<V: Copy + PartialEq>(
    survivor: &[(u32, V)],
    winner: &[(u32, V)],
    valid_below: u32,
    new_count: u32,
    old_base_at: impl Fn(u32) -> V,
    new_base_at: impl Fn(u32) -> V,
) -> Vec<(u32, V)> {
    debug_assert!(
        survivor.windows(2).all(|w| w[0].0 < w[1].0),
        "survivor must be ascending with distinct indices",
    );
    debug_assert!(
        winner.windows(2).all(|w| w[0].0 < w[1].0),
        "winner must be ascending with distinct indices",
    );
    let mut out: Vec<(u32, V)> = Vec::with_capacity(survivor.len() + winner.len());
    let mut keep = |idx: u32, v: V| {
        if idx >= new_count || new_base_at(idx) != v {
            out.push((idx, v));
        }
    };

    let (mut i, mut j) = (0, 0);
    while i < survivor.len() && j < winner.len() {
        let (si, sv) = survivor[i];
        let wi = winner[j].0;
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
    while j < winner.len() && winner[j].0 < valid_below {
        let wi = winner[j].0;
        keep(wi, old_base_at(wi));
        j += 1;
    }
    while i < survivor.len() {
        let (si, sv) = survivor[i];
        keep(si, sv);
        i += 1;
    }
    out
}

/// One sibling sparse layer (delta + its finalized base) viewed uniformly,
/// so `set_against`/`replace_against` need only one substitution point.
pub(crate) trait SparseLayer {
    type Base;
    type Val: Copy + PartialEq;
    const APPENDED_DEFAULT: Self::Val;
    fn edits_mut(&mut self) -> &mut Vec<(u32, Self::Val)>;
    fn base_get(base: &Self::Base, i: usize) -> Self::Val;
    fn base_data(base: &Self::Base) -> &[Self::Val];
    fn base_count(base: &Self::Base) -> usize;
    fn total(&self) -> usize;
}

#[inline]
pub(crate) fn set_against<L: SparseLayer>(delta: &mut L, base: &L::Base, idx: u32, v: L::Val) {
    let base_val = if (idx as usize) < L::base_count(base) {
        L::base_get(base, idx as usize)
    } else {
        L::APPENDED_DEFAULT
    };
    sparse_set(delta.edits_mut(), idx, v, base_val);
}

#[inline]
pub(crate) fn replace_against<L: SparseLayer, F>(
    delta: &mut L,
    base: &L::Base,
    scratch: &mut Vec<(u32, L::Val)>,
    f: F,
) where
    F: FnMut(usize, L::Val) -> L::Val,
{
    let total = delta.total();
    sparse_replace_with_scratch(
        delta.edits_mut(),
        scratch,
        &L::base_data(base)[..L::base_count(base)],
        L::APPENDED_DEFAULT,
        total,
        f,
    );
}

/// Install a caller-computed dense `(idx, new)` list (ascending `idx`) as the
/// layer's edit vec: elide entries equal to the finalized base, then swap.
/// Reuses `dense` (returns the prior edits in it).
#[inline]
pub(crate) fn install_against<L: SparseLayer>(
    delta: &mut L,
    base: &L::Base,
    dense: &mut Vec<(u32, L::Val)>,
) {
    dense.retain(|(idx, v)| {
        let base_val = if (*idx as usize) < L::base_count(base) {
            L::base_get(base, *idx as usize)
        } else {
            L::APPENDED_DEFAULT
        };
        *v != base_val
    });
    std::mem::swap(delta.edits_mut(), dense);
}
