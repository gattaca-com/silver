//! Finalize-path helpers for the log-style delta groups: fold a promoted
//! winner's log into the finalized base and reanchor the survivors that still
//! read through it. The paged column groups don't use these — they promote by
//! adopting a page table with no rebase.

use flux_profiler::timed;

/// Overlay a fork's append `log` onto a circular `ring`, entry `i` landing at
/// position `(start + i) % ring.len()` (wrapping).
pub(crate) fn write_ring_window<T: Copy>(ring: &mut [T], start: usize, log: &[T]) {
    let cap = ring.len();
    debug_assert!(log.len() <= cap, "delta log exceeds ring cap");
    for (i, x) in log.iter().enumerate() {
        ring[(start + i) % cap] = *x;
    }
}

/// Drop the prefix of a per-fork append log that a promoted winner already
/// folded into the base — the reanchor invariant for log-style deltas.
pub(crate) fn drain_promoted_prefix<T>(log: &mut Vec<T>, promoted_len: usize) {
    let drop = promoted_len.min(log.len());
    log.drain(..drop);
}

/// Reanchor each distinct survivor exactly once: duplicate ids map to the id
/// minted for their first occurrence, fresh ids come from `reanchor`.
#[timed]
pub(crate) fn reanchor_survivors<I: Copy + PartialEq>(
    survivors: &[I],
    mut reanchor: impl FnMut(I) -> I,
) -> Vec<I> {
    let mut fresh = Vec::with_capacity(survivors.len());
    for (i, &s) in survivors.iter().enumerate() {
        let new_id = match survivors[..i].iter().position(|&p| p == s) {
            Some(seen) => fresh[seen],
            None => reanchor(s),
        };
        fresh.push(new_id);
    }
    fresh
}
