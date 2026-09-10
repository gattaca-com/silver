use rustc_hash::FxHashMap;
use silver_beacon_state_data::{B256, Epoch, SLOTS_PER_EPOCH, Slot, StateId};

use crate::fork_choice::ForkChoice;

/// A block's post-state at each later epoch's first slot, shared by the tick,
/// the block path and the precompute. The spec's `store.checkpoint_states`.
#[derive(Default)]
pub(super) struct PrecomputedEpochs(FxHashMap<(B256, Epoch), StateId>);

impl PrecomputedEpochs {
    /// Advances from the latest cached epoch, else `from`, caching every
    /// boundary crossed. Spec `store_target_checkpoint_state`.
    pub(super) fn get_or_advance(
        &mut self,
        root: B256,
        mut from: StateId,
        from_slot: Slot,
        epoch: Epoch,
        mut advance: impl FnMut(StateId, Slot) -> StateId,
    ) -> StateId {
        let mut next = from_slot / SLOTS_PER_EPOCH + 1;
        for cached in (next..=epoch).rev() {
            if let Some(id) = self.get(root, cached) {
                (from, next) = (id, cached + 1);
                break;
            }
        }
        for crossed in next..=epoch {
            from = advance(from, crossed * SLOTS_PER_EPOCH);
            self.0.insert((root, crossed), from);
        }
        from
    }

    fn get(&self, root: B256, epoch: Epoch) -> Option<StateId> {
        self.0.get(&(root, epoch)).copied()
    }

    /// Entries off pruned blocks, or at or before the finalized epoch, can no
    /// longer be asked for.
    pub(super) fn drop_outdated(&mut self, fork_choice: &ForkChoice) {
        let finalized_epoch = fork_choice.finalized_checkpoint.epoch;
        self.0.retain(|(root, epoch), _| {
            *epoch > finalized_epoch && fork_choice.find_node_idx(root).is_some()
        });
    }

    pub(super) fn state_ids_mut(&mut self) -> impl Iterator<Item = &mut StateId> {
        self.0.values_mut()
    }
}
