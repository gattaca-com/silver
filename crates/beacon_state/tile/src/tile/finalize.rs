use flux::utils::ArrayVec;
use silver_beacon_state_data::{
    EPOCHS_RING_N, EpochId, LONGTAILS_RING_N, LongtailId, SLOTS_PER_EPOCH, StateId,
};
use silver_common::metrics::timed;

use super::BeaconStateTile;
use crate::fork_choice::MAX_FORK_CHOICE_NODES;

/// Re-anchor one always-rolled tier: collect each survivor's id for the tier
/// (`proj`), run the group's `finalize`, and write the fresh ids back 1:1.
fn rebase_tier<I: Copy>(
    survivors: &mut [StateId],
    proj: impl Fn(&mut StateId) -> &mut I,
    finalize: impl FnOnce(&ArrayVec<I, MAX_SURVIVORS>) -> Vec<I>,
) {
    let ids: ArrayVec<I, MAX_SURVIVORS> = survivors.iter_mut().map(|s| *proj(s)).collect();
    let new = finalize(&ids);
    for (sid, &n) in survivors.iter_mut().zip(&new) {
        *proj(sid) = n;
    }
}

/// Re-anchor a lazily-rolled tier: `old_idxs` is the pre-deduped set of live
/// entries (one cumulative log re-based once when siblings share it); the
/// group's `finalize` returns the fresh ids 1:1, mapped old→new onto every
/// bundle referencing an old entry.
fn rebase_lazy_tier<I: Copy + PartialEq>(
    survivors: &mut [StateId],
    old_idxs: &[I],
    proj: impl Fn(&mut StateId) -> &mut Option<I>,
    finalize: impl FnOnce() -> Vec<I>,
) {
    let new = finalize();
    for sid in survivors.iter_mut() {
        if let Some(old) = *proj(sid) &&
            let Some(pos) = old_idxs.iter().position(|&e| e == old)
        {
            *proj(sid) = Some(new[pos]);
        }
    }
}

/// Survivor set re-anchored at finalization: every fork-choice node's bundle
/// plus the (possibly node-less) slot-advanced head.
const MAX_SURVIVORS: usize = MAX_FORK_CHOICE_NODES + 1;

impl BeaconStateTile {
    /// Promote the fork-choice-finalized node's `StateId` tiers into the
    /// per-tier finalized bases, re-base every surviving descendant delta
    /// against the new base, and refresh the survivors' (and the published
    /// head's) bundles with the re-anchored ids. No-op until finality
    /// advances past the current base (fork-choice node 0).
    ///
    /// The epoch state-transition itself runs inside `process_slots`; this is
    /// purely the finalization / promotion step.
    pub(super) fn maybe_finalize(&mut self) {
        // Lift fork-choice finality from the head post-state (monotone, only
        // to a block we actually hold).
        let hf = self.head_finalized_checkpoint();
        if hf.epoch > self.fork_choice.finalized_checkpoint.epoch &&
            self.fork_choice.find_node_idx(&hf.root).is_some()
        {
            self.fork_choice.finalized_checkpoint = hf;
        }

        let fin_root = self.fork_choice.finalized_checkpoint.root;
        let Some(fin_idx) = self.fork_choice.find_node_idx(&fin_root) else {
            return;
        };
        if fin_idx == 0 {
            return; // already the base
        }
        let promoted = self.fork_choice.node(fin_idx).state_id;
        self.finalize(promoted);
    }

    /// Promote `promoted` into the per-tier bases and re-anchor the survivors.
    /// Split out of `maybe_finalize` so the perf harness sees a `finalize`
    /// frame that fires only when finality actually advances (the early-out
    /// checks above run every block and would dilute the timing).
    #[timed]
    fn finalize(&mut self, promoted: StateId) {
        // Drop non-descendants of the finalized block; the survivors (node 0
        // is now the finalized block) are exactly the deltas to re-base.
        self.fork_choice.prune();
        let mut survivors: ArrayVec<StateId, MAX_SURVIVORS> = ArrayVec::new();
        survivors.extend(self.fork_choice.live_state_ids());

        // `on_slot_start` advances the head onto a fresh bundle that is never
        // registered as a fork-choice node. It is still a live descendant of
        // the finalized base, so it must be re-based too — otherwise its
        // `base_count` goes stale and the next `apply_block_view` on it (or a
        // roll from it) trips the base-mirror assert. `MAX_SURVIVORS` covers
        // every node plus this extra head bundle.
        let head_pos = match survivors.iter().position(|&s| s == self.last_applied) {
            Some(p) => p,
            None => {
                survivors.push(self.last_applied);
                survivors.len() - 1
            }
        };

        // Unique epoch / longtail ring entries referenced by survivors, so
        // each cumulative log is re-based exactly once when siblings share it.
        let mut epoch_idxs: ArrayVec<EpochId, EPOCHS_RING_N> = ArrayVec::new();
        let mut longtail_idxs: ArrayVec<LongtailId, LONGTAILS_RING_N> = ArrayVec::new();
        for sid in survivors.iter() {
            if let Some(e) = sid.epoch_idx &&
                !epoch_idxs.as_slice().contains(&e)
            {
                epoch_idxs.push(e);
            }
            if let Some(l) = sid.longtail_idx &&
                !longtail_idxs.as_slice().contains(&l)
            {
                longtail_idxs.push(l);
            }
        }

        self.promote_and_rebase(
            promoted,
            survivors.as_mut_slice(),
            head_pos,
            epoch_idxs.as_slice(),
            longtail_idxs.as_slice(),
        );

        // Hand the re-anchored bundles back to their holders: fork-choice
        // nodes 1:1 (prune kept node order), then the head.
        let node_count = self.fork_choice.nodes.len();
        for (node, &sid) in
            self.fork_choice.nodes.iter_mut().zip(&survivors.as_slice()[..node_count])
        {
            node.state_id = sid;
        }
        self.last_applied = survivors.as_slice()[head_pos];

        let fin_slot = self.fork_choice.finalized_checkpoint.epoch * SLOTS_PER_EPOCH;
        self.clear_pending_blocks(fin_slot);
    }

    /// Rewrites each survivor bundle's per-tier ids to the re-anchored ones,
    /// then stages `survivors[head_pos]` as the published bundle — it lands
    /// with the guard drop, in the same seqlock window as the tier rewrites,
    /// so readers never observe a bundle whose ids were already re-anchored.
    fn promote_and_rebase(
        &mut self,
        promoted: StateId,
        survivors: &mut [StateId],
        head_pos: usize,
        epoch_idxs: &[EpochId],
        longtail_idxs: &[LongtailId],
    ) {
        let mut guard = self.state.write();
        let bs = &mut *guard;

        // Old finalized epoch — the epoch tier overlays its ring at
        // `(old_fin_epoch + k) % …`. Read from the (still-old) slot-group
        // base before its finalize.
        let old_fin_epoch =
            (bs.slot_states.finalized_view().slot_number() / SLOTS_PER_EPOCH) as usize;

        // The always-rolled tiers finalize in their own groups — re-anchor
        // each survivor against the winner (pin pre-promote values + prune
        // redundancy), then promote the winner into the base. Each base is
        // untouched until its own group's finalize, so it still holds the old
        // count its rebase bounds read. Pending's drain-offset rebase
        // snapshots `old_base_lens` internally from the still-old base; the
        // slot tier prunes survivors' root tails of the promoted prefix.
        rebase_tier(
            survivors,
            |s| &mut s.validators_idx,
            |ids| bs.validators.finalize(promoted.validators_idx, ids),
        );
        rebase_tier(
            survivors,
            |s| &mut s.balances_idx,
            |ids| bs.balances.finalize(promoted.balances_idx, ids),
        );
        rebase_tier(survivors, |s| &mut s.eth1_idx, |ids| bs.eth1.finalize(promoted.eth1_idx, ids));
        rebase_tier(
            survivors,
            |s| &mut s.previous_participation_idx,
            |ids| bs.previous_participation.finalize(promoted.previous_participation_idx, ids),
        );
        rebase_tier(
            survivors,
            |s| &mut s.current_participation_idx,
            |ids| bs.current_participation.finalize(promoted.current_participation_idx, ids),
        );
        rebase_tier(
            survivors,
            |s| &mut s.inactivity_idx,
            |ids| bs.inactivity.finalize(promoted.inactivity_idx, ids),
        );
        rebase_tier(
            survivors,
            |s| &mut s.pending_idx,
            |ids| bs.pending.finalize(promoted.pending_idx, ids),
        );
        rebase_tier(
            survivors,
            |s| &mut s.slot_idx,
            |ids| bs.slot_states.finalize(promoted.slot_idx, ids),
        );

        // Epoch + longtail finalize in their own groups, but — unlike the
        // always-rolled tiers above — forks roll these lazily, so finalize only
        // when the promoted winner actually owns a delta. The survivor idx sets
        // are pre-deduped (one cumulative log re-based once when siblings share
        // it); the group returns the fresh ids 1:1, which we map old→new and
        // write back onto every bundle referencing the old entry.
        if let Some(winner_epoch) = promoted.epoch_idx {
            rebase_lazy_tier(
                survivors,
                epoch_idxs,
                |s| &mut s.epoch_idx,
                || bs.epoch.finalize(winner_epoch, epoch_idxs, old_fin_epoch),
            );
        }
        if let Some(winner_longtail) = promoted.longtail_idx {
            rebase_lazy_tier(
                survivors,
                longtail_idxs,
                |s| &mut s.longtail_idx,
                || bs.longtail.finalize(winner_longtail, longtail_idxs),
            );
        }

        // Publish-with-the-guard: the head's rewritten bundle replaces the
        // stale published one atomically at guard drop.
        guard.set_state_id(survivors[head_pos]);
    }
}
