pub use balances::{
    BalancesGroup, BalancesId, BalancesReader, BalancesView, BalancesWriteView, FinalizedBalances,
};
pub use buffer::{Id, Reset, Ring};
pub use decompose::DecomposeError;
pub use delta_view::{
    StateReadView, StateWriterView, ValidatorRow, append_validator, effective_block_roots_into,
    effective_randao_mixes_into, effective_slashings_into, effective_state_roots_into,
    iter_validator_rows, randao_mix_at_epoch,
};
pub use encode::{CHECKPOINT_SECTIONS, PubkeysDecodeError, decode_checkpoint_pubkeys};
pub use epoch::{EpochGroup, EpochId, EpochStateFinalized, EpochView, EpochWriteView};
pub use hash_tree::{DeltaHashTree, FinalizedHashTree};
pub use inactivity::{
    FinalizedInactivityScores, InactivityId, InactivityScoresGroup, InactivityView,
    InactivityWriteView,
};
pub use longtail::{LongtailGroup, LongtailId, LongtailState, LongtailView, LongtailWriteView};
pub use participation::{
    Current, CurrentParticipationGroup, CurrentParticipationId, FinalizedParticipation,
    ParticipationGroup, ParticipationView, ParticipationWriteView, Previous,
    PreviousParticipationGroup, PreviousParticipationId,
};
pub use pending::{PendingGroup, PendingId, PendingQueues, PendingView, PendingWriteView};
pub use silver_chain_spec::{BlobParameters, SpecConfig};
pub(crate) use silver_ssz::ssz_hash;
pub use slot_state::{
    SlotStateFinalized, SlotStateGroup, SlotStateId, SlotStateView, SlotStateWriteView,
};
pub use types::*;
pub use validators::{
    AppendedValidator, FinalizedValidators, ValSeed, ValidatorsDecodeError, ValidatorsDelta,
    ValidatorsGroup, ValidatorsId, ValidatorsView, ValidatorsWriteView, validator_hash,
};
pub use view::{BeaconStateOwner, BeaconStateReader, CheckpointChunk, CheckpointCursor};

mod balances;
pub mod buffer;
mod decompose;
mod delta_view;
mod encode;
mod epoch;
mod hash_tree;
mod inactivity;
mod longtail;
mod participation;
mod pending;
mod slot_state;
pub(crate) mod sparse;
pub mod types;
mod validators;
mod view;

pub struct BeaconState {
    /// Chain constants fixed at genesis/fork boundaries (fork versions,
    /// genesis roots) — never touched by the per-fork delta machinery.
    pub immutable: Immutable,
    /// Validator registry (columns + pubkey index + hash tree) — own ring,
    /// rolled every slot; read by both views.
    pub validators: ValidatorsGroup,
    /// Rolled every slot; one isolated unit.
    pub balances: BalancesGroup,
    /// Pending queues + participation + inactivity — own rings, rolled every
    /// slot.
    pub pending: PendingGroup,
    pub previous_participation: PreviousParticipationGroup,
    pub current_participation: CurrentParticipationGroup,
    pub inactivity: InactivityScoresGroup,
    /// Slot tier (the heavy `SlotState` + root rings) — own ring, rolled every
    /// slot; its base holds the canonical finalized slot.
    pub slot_states: SlotStateGroup,
    /// Epoch tier (`EpochState` + randao/slashings rings) and longtail tier
    /// (sync committees + historical summaries) — own rings, rolled lazily at
    /// epoch / rotation boundaries; their bases hold the canonical finalized
    /// state.
    pub epoch: EpochGroup,
    pub longtail: LongtailGroup,
}

impl BeaconState {
    /// Writer-private placeholder for the pre-snapshot owner — unobservable
    /// by readers (nothing is published until a real state is installed);
    /// [`Self::decompose`] is the public constructor.
    pub(crate) fn pre_bootstrap() -> Self {
        let cap = validator_capacity(0);
        Self {
            immutable: Immutable::default(),
            validators: ValidatorsGroup::new(
                FinalizedValidators::try_new(&[]).expect("empty registry decodes"),
            ),
            balances: BalancesGroup::new(cap, 0, &[]).expect("empty column"),
            pending: PendingGroup::new(PendingQueues::default()),
            previous_participation: PreviousParticipationGroup::new(cap, 0, &[])
                .expect("empty column"),
            current_participation: CurrentParticipationGroup::new(cap, 0, &[])
                .expect("empty column"),
            inactivity: InactivityScoresGroup::new(cap, 0, &[]).expect("empty column"),
            slot_states: SlotStateGroup::new(SlotStateFinalized::default()),
            epoch: EpochGroup::new(EpochStateFinalized::default()),
            longtail: LongtailGroup::new(LongtailState::default()),
        }
    }

    /// Anchor a fresh per-fork delta on every always-rolled tier (epoch/
    /// longtail stay lazy: `None` reads their bases) and assemble the anchor
    /// bundle — the bootstrap / pre-bootstrap head.
    pub fn roll_fresh(&mut self) -> StateId {
        StateId {
            epoch_idx: None,
            longtail_idx: None,
            balances_idx: self.balances.roll_fresh().commit(),
            pending_idx: self.pending.roll_fresh().commit(),
            previous_participation_idx: self.previous_participation.roll_fresh().commit(),
            current_participation_idx: self.current_participation.roll_fresh().commit(),
            inactivity_idx: self.inactivity.roll_fresh().commit(),
            slot_idx: self.slot_states.roll_fresh().commit(),
            validators_idx: self.validators.roll_fresh().commit(),
        }
    }

    /// Resolve a fork's read view from its index bundle — the ONE resolver
    /// behind both the writer thread's `read_view` and the cross-thread
    /// optimistic reader.
    pub fn read_view(&self, state_id: StateId) -> StateReadView<'_> {
        StateReadView::new(
            &self.immutable,
            self.balances.view(state_id.balances_idx),
            self.epoch.view_opt(state_id.epoch_idx),
            self.longtail.view_opt(state_id.longtail_idx),
            self.pending.view(state_id.pending_idx),
            self.previous_participation.view(state_id.previous_participation_idx),
            self.current_participation.view(state_id.current_participation_idx),
            self.inactivity.view(state_id.inactivity_idx),
            self.slot_states.view(state_id.slot_idx),
            self.validators.view(state_id.validators_idx),
        )
    }
}
