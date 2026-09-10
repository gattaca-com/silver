use std::iter;

use flux_profiler::timed;
use silver_beacon_state_data::{SLOTS_PER_EPOCH, StateId};

use super::BeaconStateTile;

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
        let winner = self.fork_choice.node(fin_idx).state_id;
        self.finalize(winner);
    }

    /// Promote the winner into the per-tier bases and re-anchor the survivors.
    /// Split out of `maybe_finalize` so the perf harness sees a `finalize`
    /// frame that fires only when finality actually advances (the early-out
    /// checks above run every block and would dilute the timing).
    #[timed]
    fn finalize(&mut self, winner: StateId) {
        // Drop non-descendants of the finalized block; the survivors (node 0
        // is now the finalized block) are exactly the deltas to re-base.
        self.fork_choice.prune();
        let fork_choice = &self.fork_choice;
        self.held.drop_outdated(|parent| fork_choice.find_node_idx(parent).is_some());

        {
            // The head's rebased bundle must publish in the same seqlock
            // window as the tier rewrites.
            let mut guard = self.state.write();

            // `on_slot_start` may have rolled the head past the last node, and
            // staged blocks hold committed ids of their own: neither is a
            // fork-choice node, both go stale without a re-base.
            guard.finalize(
                winner,
                self.fork_choice
                    .live_state_ids_mut()
                    .chain(iter::once(&mut self.last_applied))
                    .chain(self.held.state_ids_mut()),
            );
            guard.set_state_id(self.last_applied);
        }

        let fin_slot = self.fork_choice.finalized_checkpoint.epoch * SLOTS_PER_EPOCH;
        self.clear_finalized_held(fin_slot);
    }
}
