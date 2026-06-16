//! Shared unit-test harness: a `BeaconState` plus its working index bundle,
//! rolled like production `apply_block_view` (which isn't reusable here: it
//! asserts a non-empty validator set).

use silver_beacon_state_data::{
    BeaconState, EpochGroup, EpochStateFinalized, LongtailGroup, SLOTS_PER_EPOCH, StateId,
    StateWriterView, ValSeed,
};

/// `BeaconState` + its working bundle; mutations persist only through
/// `commit` + `state_id` writeback.
pub(crate) struct TestState {
    pub(crate) bs: BeaconState,
    pub(crate) state_id: StateId,
}

impl TestState {
    /// State with the registry seeded from `seeds`, the balances column from
    /// each seed's `balance`, the other per-validator columns zeroed, and the
    /// slot tier anchored at `epoch_base`'s finalized epoch boundary.
    pub(crate) fn new(epoch_base: EpochStateFinalized, seeds: &[ValSeed]) -> Self {
        // Anchor slot = the finalized epoch boundary.
        let anchor_slot = epoch_base.state().finalized_checkpoint.epoch * SLOTS_PER_EPOCH;
        let mut bs = BeaconState::for_test(epoch_base, seeds, anchor_slot);
        let state_id = bs.roll_fresh();
        Self { bs, state_id }
    }

    /// Roll a fresh fork off the bundle and hand back its writer view — the
    /// production `apply_block_view` shape.
    pub(crate) fn view(&mut self) -> (StateWriterView<'_>, &mut EpochGroup, &mut LongtailGroup) {
        let sid = self.state_id;
        let bs = &mut self.bs;
        let view = StateWriterView {
            imm: &bs.immutable,
            balances: bs.balances.roll_from(sid.balances_idx),
            eth1: bs.eth1.roll_from(sid.eth1_idx),
            pending: bs.pending.roll_from(sid.pending_idx),
            previous_participation: bs
                .previous_participation
                .roll_from(sid.previous_participation_idx),
            current_participation: bs
                .current_participation
                .roll_from(sid.current_participation_idx),
            inactivity: bs.inactivity.roll_from(sid.inactivity_idx),
            slot: bs.slot_states.roll_from(sid.slot_idx),
            validators: bs.validators.roll_from(sid.validators_idx),
        };
        (view, &mut bs.epoch, &mut bs.longtail)
    }
}
