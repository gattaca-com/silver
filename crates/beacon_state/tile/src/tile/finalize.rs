use flux_profiler::timed;
use silver_beacon_state_data::{EpochId, LongtailId, SLOTS_PER_EPOCH, StateId};

use super::BeaconStateTile;

/// Re-anchor one always-rolled tier: collect each survivor's id for the tier
/// (`proj`), run the group's `finalize`, and write the fresh ids back 1:1.
fn rebase_tier<I: Copy>(
    mut promoted: StateId,
    survivors: &mut [StateId],
    proj: impl Fn(&mut StateId) -> &mut I,
    finalize: impl FnOnce(I, &[I]) -> Vec<I>,
) {
    let winner = *proj(&mut promoted);
    let ids: Vec<I> = survivors.iter_mut().map(|s| *proj(s)).collect();
    let new = finalize(winner, &ids);
    for (sid, &n) in survivors.iter_mut().zip(&new) {
        *proj(sid) = n;
    }
}

/// Re-anchor a lazily-rolled tier: `old_idxs` is the pre-deduped set of live
/// entries (one cumulative log re-based once when siblings share it); the
/// group's `finalize` returns the fresh ids 1:1, mapped old→new onto every
/// bundle referencing an old entry.
fn rebase_lazy_tier<I: Copy + PartialEq>(
    mut promoted: StateId,
    survivors: &mut [StateId],
    old_idxs: &[I],
    proj: impl Fn(&mut StateId) -> &mut Option<I>,
    finalize: impl FnOnce(I) -> Vec<I>,
) {
    // Forks roll this tier lazily: no delta on the winner means nothing to
    // promote or re-anchor.
    let Some(winner) = *proj(&mut promoted) else {
        return;
    };
    let new = finalize(winner);
    for sid in survivors.iter_mut() {
        if let Some(old) = *proj(sid) &&
            let Some(pos) = old_idxs.iter().position(|&e| e == old)
        {
            *proj(sid) = Some(new[pos]);
        }
    }
}

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
        self.fork_choice.lift_finalized(hf);

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
        let mut survivors: Vec<StateId> = self.fork_choice.live_state_ids().collect();

        // `on_slot_start` advances the head onto a fresh bundle that is never
        // registered as a fork-choice node. It is still a live descendant of
        // the finalized base, so it must be re-based too — otherwise its
        // `base_count` goes stale and the next `apply_block_view` on it (or a
        // roll from it) trips the base-mirror assert.
        let head_pos = match survivors.iter().position(|&s| s == self.last_applied) {
            Some(p) => p,
            None => {
                survivors.push(self.last_applied);
                survivors.len() - 1
            }
        };

        // Unique epoch / longtail ring entries referenced by survivors, so
        // each cumulative log is re-based exactly once when siblings share it.
        let mut epoch_idxs: Vec<EpochId> = Vec::new();
        let mut longtail_idxs: Vec<LongtailId> = Vec::new();
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

        // The always-rolled tiers finalize in their own groups — re-anchor
        // each survivor against the winner (pin pre-promote values + prune
        // redundancy), then promote the winner into the base. Each base is
        // untouched until its own group's finalize, so it still holds the old
        // count its rebase bounds read. Pending's drain-offset rebase
        // snapshots `old_base_lens` internally from the still-old base.
        rebase_tier(
            promoted,
            survivors,
            |s| &mut s.validators_idx,
            |winner, ids| bs.validators.finalize(winner, ids),
        );
        bs.balances.finalize(&promoted, survivors, |s| s.balances_idx);
        rebase_tier(
            promoted,
            survivors,
            |s| &mut s.eth1_idx,
            |winner, ids| bs.eth1.finalize(winner, ids),
        );
        bs.previous_participation.finalize(&promoted, survivors, |s| s.previous_participation_idx);
        bs.current_participation.finalize(&promoted, survivors, |s| s.current_participation_idx);
        bs.inactivity.finalize(&promoted, survivors, |s| s.inactivity_idx);
        bs.block_roots.finalize(&promoted, survivors, |s| s.block_roots_idx);
        bs.state_roots.finalize(&promoted, survivors, |s| s.state_roots_idx);
        bs.randao_mixes.finalize(&promoted, survivors, |s| s.randao_idx);
        rebase_tier(
            promoted,
            survivors,
            |s| &mut s.pending_idx,
            |winner, ids| bs.pending.finalize(winner, ids),
        );
        rebase_tier(
            promoted,
            survivors,
            |s| &mut s.slot_idx,
            |winner, ids| bs.slot_states.finalize(winner, ids),
        );
        rebase_tier(
            promoted,
            survivors,
            |s| &mut s.builders_idx,
            |winner, ids| bs.builders.finalize(winner, ids),
        );

        // Epoch + longtail finalize in their own groups, but — unlike the
        // always-rolled tiers above — forks roll these lazily, so finalize only
        // when the promoted winner actually owns a delta. The survivor idx sets
        // are pre-deduped (one cumulative log re-based once when siblings share
        // it); the group returns the fresh ids 1:1, which we map old→new and
        // write back onto every bundle referencing the old entry.
        rebase_lazy_tier(
            promoted,
            survivors,
            epoch_idxs,
            |s| &mut s.epoch_idx,
            |winner| bs.epoch.finalize(winner, epoch_idxs),
        );
        rebase_lazy_tier(
            promoted,
            survivors,
            longtail_idxs,
            |s| &mut s.longtail_idx,
            |winner| bs.longtail.finalize(winner, longtail_idxs),
        );

        // Publish-with-the-guard: the head's rewritten bundle replaces the
        // stale published one atomically at guard drop.
        guard.set_state_id(survivors[head_pos]);
    }
}
