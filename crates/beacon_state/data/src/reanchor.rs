//! Finalize-path helpers for the log-style delta groups: fold a promoted
//! winner's log into the finalized base and reanchor the survivors that still
//! read through it. The paged column groups don't use these — they promote by
//! adopting a page table with no rebase.

use flux_profiler::timed;

use crate::ring::{Id, Reset, Ring, RingGroup};

/// Finalize a full-working-copy group: copy each survivor into a fresh slot
/// (the delta shadows the whole base, so nothing rebases), promote the winner
/// into the base, and free the vacated slots.
pub(crate) fn finalize_full_copies<G: RingGroup>(
    deltas: &mut Ring<G>,
    winner: Id<G>,
    survivors: &[Id<G>],
    promote: impl FnOnce(&G::Entry),
) -> Vec<Id<G>>
where
    G::Entry: Reset + Default,
{
    debug_assert!(survivors.contains(&winner), "winner must be among the survivors");
    deltas.free_outdated(survivors);

    let fresh = reanchor_survivors(survivors, |s| deltas.roll_from(s).commit());
    promote(deltas.get(winner));

    deltas.free_outdated(&fresh);
    fresh
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
