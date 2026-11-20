use silver_beacon_state_data::{
    B256, BeaconStateReader, Epoch, SLOTS_PER_HISTORICAL_ROOT, StateReadView,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FinalizedCheckpointEvent {
    pub(crate) block: B256,
    /// The finalized block's post-state root, not the epoch-boundary state's.
    pub(crate) state: B256,
    pub(crate) epoch: Epoch,
}

/// Publishes each advance of the head state's finalized checkpoint once.
#[derive(Debug)]
pub(crate) struct FinalizedCheckpoints {
    epoch: Epoch,
}

impl FinalizedCheckpoints {
    /// The anchor's own checkpoint predates the node and is not an event.
    pub(crate) fn at_anchor(view: &StateReadView<'_>) -> Self {
        Self { epoch: view.epoch.state().finalized_checkpoint.epoch }
    }

    pub(crate) fn advance(
        &mut self,
        state: &BeaconStateReader,
    ) -> Option<FinalizedCheckpointEvent> {
        let last = self.epoch;
        let (epoch, event) = state.read(|view| Self::read(last, &view))??;
        self.epoch = epoch;
        if event.is_none() {
            silver_log::warn!(epoch, "finalized block not in the block roots ring");
        }
        event
    }

    /// Runs under the state seqlock, which may retry it, so it mutates nothing.
    fn read(
        last: Epoch,
        view: &StateReadView<'_>,
    ) -> Option<(Epoch, Option<FinalizedCheckpointEvent>)> {
        let checkpoint = view.epoch.state().finalized_checkpoint;
        if checkpoint.epoch <= last {
            return None;
        }
        // Finality trails the head by far less than the rings, so a miss
        // means a state this view cannot explain.
        let below = view.slot.state().slot.checked_sub(1)?;
        let event = view.block_roots.slot_of(&checkpoint.root, below).map(|slot| {
            FinalizedCheckpointEvent {
                block: checkpoint.root,
                state: view.state_roots.get(slot as usize % SLOTS_PER_HISTORICAL_ROOT),
                epoch: checkpoint.epoch,
            }
        });
        Some((checkpoint.epoch, event))
    }
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::{
        BeaconState, BeaconStateOwner, BlockRootsGroup, Checkpoint, EpochState,
        EpochStateFinalized, StateRootsGroup,
    };

    use super::*;

    const STATE_SLOT: u64 = 100;
    const BLOCK_SLOT: u64 = 64;

    /// `BLOCK_SLOT + 1` is empty, so the ring repeats the block's root there.
    fn owner(finalized: Checkpoint) -> BeaconStateOwner {
        let epoch = EpochState { finalized_checkpoint: finalized, ..Default::default() };
        let mut state =
            BeaconState::for_test(EpochStateFinalized::from_state(epoch), &[], STATE_SLOT);
        let mut block_roots = vec![[0u8; 32]; SLOTS_PER_HISTORICAL_ROOT];
        let mut state_roots = vec![[0u8; 32]; SLOTS_PER_HISTORICAL_ROOT];
        block_roots[BLOCK_SLOT as usize] = [0xb1; 32];
        block_roots[BLOCK_SLOT as usize + 1] = [0xb1; 32];
        state_roots[BLOCK_SLOT as usize] = [0x51; 32];
        state_roots[BLOCK_SLOT as usize + 1] = [0x52; 32];
        state.block_roots = BlockRootsGroup::vector(block_roots.as_flattened()).unwrap();
        state.state_roots = StateRootsGroup::vector(state_roots.as_flattened()).unwrap();
        let mut owner = BeaconStateOwner::new(state);
        let anchor = owner.roll_fresh();
        owner.publish_state_id(anchor);
        owner
    }

    #[test]
    fn an_advance_is_published_once_with_the_block_post_state_root() {
        let anchor = owner(Checkpoint { epoch: 0, root: [0; 32] });
        let mut checkpoints =
            anchor.reader().read(|view| FinalizedCheckpoints::at_anchor(&view)).unwrap();
        assert_eq!(checkpoints.advance(&anchor.reader()), None);

        let finalized = owner(Checkpoint { epoch: 2, root: [0xb1; 32] }).reader();
        let event = FinalizedCheckpointEvent { block: [0xb1; 32], state: [0x51; 32], epoch: 2 };
        assert_eq!(checkpoints.advance(&finalized), Some(event));
        assert_eq!(checkpoints.advance(&finalized), None);
    }

    #[test]
    fn a_root_outside_the_ring_moves_the_epoch_without_an_event() {
        let anchor = owner(Checkpoint { epoch: 0, root: [0; 32] });
        let mut checkpoints =
            anchor.reader().read(|view| FinalizedCheckpoints::at_anchor(&view)).unwrap();
        let unknown = owner(Checkpoint { epoch: 2, root: [0xee; 32] }).reader();
        assert_eq!(checkpoints.advance(&unknown), None);
        assert_eq!(checkpoints.epoch, 2);
    }
}
