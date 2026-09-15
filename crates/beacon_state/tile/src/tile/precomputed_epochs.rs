use silver_beacon_state_data::{B256, Epoch, StateId};

use crate::fork_choice::ForkChoice;

// Steady state holds the head's next epoch plus reorg/precompute transients.
const MAX_PRECOMPUTED_EPOCHS: usize = 8;

struct Entry {
    root: B256,
    epoch: Epoch,
    state: StateId,
}

/// A block's post-state at a later epoch's first slot, shared by the tick,
/// the block path and the precompute. The spec's `store.checkpoint_states`.
#[derive(Default)]
pub(super) struct PrecomputedEpochs([Option<Entry>; MAX_PRECOMPUTED_EPOCHS]);

impl PrecomputedEpochs {
    pub(super) fn get_or_insert(
        &mut self,
        root: B256,
        epoch: Epoch,
        compute: impl FnOnce() -> StateId,
    ) -> StateId {
        if let Some(e) = self.0.iter().flatten().find(|e| e.root == root && e.epoch == epoch) {
            return e.state;
        }

        let state = compute();
        let slot = self.find_slot();
        self.0[slot] = Some(Entry { root, epoch, state });
        state
    }

    /// Empty slot first, otherwise the lowest-epoch entry.
    fn find_slot(&self) -> usize {
        if let Some(empty) = self.0.iter().position(Option::is_none) {
            return empty;
        }
        self.0
            .iter()
            .enumerate()
            .filter_map(|(slot, e)| e.as_ref().map(|e| (slot, e.epoch)))
            .min_by_key(|&(_, epoch)| epoch)
            .map_or(0, |(slot, _)| slot)
    }

    /// Entries off pruned blocks, or at or before the finalized epoch, can no
    /// longer be asked for.
    pub(super) fn drop_outdated(&mut self, fork_choice: &ForkChoice) {
        let finalized_epoch = fork_choice.finalized_checkpoint.epoch;
        for slot in &mut self.0 {
            slot.take_if(|e| {
                e.epoch <= finalized_epoch || fork_choice.find_node_idx(&e.root).is_none()
            });
        }
    }

    pub(super) fn state_ids_mut(&mut self) -> impl Iterator<Item = &mut StateId> {
        self.0.iter_mut().flatten().map(|e| &mut e.state)
    }
}
