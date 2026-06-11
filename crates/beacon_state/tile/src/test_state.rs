//! Shared unit-test harness: a `BeaconState` plus its working index bundle,
//! rolled like production `apply_block_view` (which isn't reusable here: it
//! asserts a non-empty validator set).

use silver_beacon_state_data::{
    BalancesGroup, BeaconState, CurrentParticipationGroup, EpochGroup, EpochStateFinalized,
    Eth1Group, Eth1Votes, FinalizedValidators, Immutable, InactivityScoresGroup, LongtailGroup,
    LongtailState, PendingGroup, PendingQueues, PreviousParticipationGroup, SLOTS_PER_EPOCH,
    SLOTS_PER_HISTORICAL_ROOT, SlotState, SlotStateFinalized, SlotStateGroup, StateId,
    StateWriterView, ValSeed, ValidatorsGroup,
};

/// `BeaconState` + its working bundle; mutations persist only through
/// `commit` + `state_id` writeback.
pub(crate) struct TestState {
    pub(crate) bs: BeaconState,
    pub(crate) state_id: StateId,
}

impl TestState {
    /// State with the registry seeded from `seeds`, the sibling per-validator
    /// columns zeroed (balances from `seed_balances`), and the slot tier
    /// anchored at `epoch_base`'s finalized epoch boundary.
    pub(crate) fn new(
        epoch_base: EpochStateFinalized,
        seeds: &[ValSeed],
        seed_balances: &[u64],
    ) -> Self {
        let validators = ValidatorsGroup::new(FinalizedValidators::with_validators(seeds));
        let cap = validators.finalized().capacity();
        let n = validators.finalized().validator_count();
        // Anchor slot = the finalized epoch boundary.
        let anchor_slot = epoch_base.state().finalized_checkpoint.epoch * SLOTS_PER_EPOCH;
        let balance_bytes: Vec<u8> = seed_balances.iter().flat_map(|v| v.to_le_bytes()).collect();
        // Sibling lists stay lockstep with the registry: n zero entries.
        let zero_flags = vec![0u8; n];
        let zero_scores = vec![0u8; n * 8];
        let zero_roots = || vec![[0u8; 32]; SLOTS_PER_HISTORICAL_ROOT].into_boxed_slice();
        let mut bs = BeaconState {
            immutable: Immutable::default(),
            validators,
            balances: BalancesGroup::new(cap, n, &balance_bytes).unwrap(),
            eth1: Eth1Group::new(Eth1Votes::default()),
            pending: PendingGroup::new(PendingQueues::default()),
            previous_participation: PreviousParticipationGroup::new(cap, n, &zero_flags).unwrap(),
            current_participation: CurrentParticipationGroup::new(cap, n, &zero_flags).unwrap(),
            inactivity: InactivityScoresGroup::new(cap, n, &zero_scores).unwrap(),
            slot_states: SlotStateGroup::new(SlotStateFinalized::from_parts(
                SlotState { slot: anchor_slot, ..Default::default() },
                zero_roots(),
                zero_roots(),
            )),
            epoch: EpochGroup::new(epoch_base),
            longtail: LongtailGroup::new(LongtailState::default()),
        };
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
