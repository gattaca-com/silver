pub use beacon_block_body::{BlockBodyError, BodyFork, BodyOffsets, OperationKind};
pub use builders::{BuildersGroup, BuildersId, BuildersView, BuildersWriteView, FinalizedBuilders};
pub use column::{
    Balances, BalancesGroup, BalancesId, BalancesReader, BalancesWriteView, BlockRoots,
    BlockRootsGroup, BlockRootsId, ColumnGroup, ColumnReader, ColumnSpec, ColumnWriteView, Current,
    CurrentParticipationGroup, CurrentParticipationId, Inactivity, InactivityId,
    InactivityScoresGroup, InactivityView, InactivityWriteView, ParticipationView,
    ParticipationWriteView, Previous, PreviousParticipationGroup, PreviousParticipationId,
    RandaoMixes, RandaoMixesGroup, RandaoMixesId, RandaoMixesView, RandaoMixesWriteView, RootsView,
    RootsWriteView, Slashings, SlashingsGroup, SlashingsId, SlashingsView, SlashingsWriteView,
    StateRoots, StateRootsGroup, StateRootsId,
};
pub use decompose::DecomposeError;
pub use delta_view::{StateReadView, StateWriterView};
pub use encode::{FULU_CHECKPOINT_SECTIONS, PubkeysDecodeError, decode_checkpoint_pubkeys};
pub use epoch::{EpochGroup, EpochId, EpochStateFinalized, EpochView, EpochWriteView};
pub use eth1::{Eth1Group, Eth1Id, Eth1View, Eth1Votes, Eth1WriteView};
pub use gloas::{
    Builder, BuilderPendingPayment, BuilderPendingWithdrawal, ExecutionPayloadBid, PtcCommittee,
    Withdrawal,
};
pub use longtail::{LongtailGroup, LongtailId, LongtailState, LongtailView, LongtailWriteView};
pub use parsed::ParsedAggregateAndProof;
pub use pending::{
    PendingGroup, PendingId, PendingView, PendingWriteView, QueueItem, QueueView, QueueWriteView,
};
pub use ring::{Id, Reset};
pub use silver_chain_spec::{BlobParameters, SpecConfig};
pub(crate) use silver_ssz::{merkle, progressive};
pub use slot_state::{
    EpochBalances, EpochBalancesRow, SlotStateFinalized, SlotStateGroup, SlotStateId,
    SlotStateView, SlotStateWriteView,
};
pub use types::*;
pub use validators::{
    FinalizedValidators, ValSeed, ValidatorsDecodeError, ValidatorsGroup, ValidatorsId,
    ValidatorsView, ValidatorsWriteView, validator_hash,
};
pub use view::{BeaconStateOwner, BeaconStateReader, CheckpointChunk, CheckpointCursor};

mod beacon_block_body;
mod builders;
mod column;
mod decompose;
mod delta_view;
mod encode;
mod epoch;
mod eth1;
pub mod gloas;
mod longtail;
mod parsed;
mod pending;
mod reanchor;
pub mod ring;
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
    /// Eth1 vote list — own ring, rolled every slot; forks carry only their
    /// appends since finalization.
    pub eth1: Eth1Group,
    /// Pending queues + participation + inactivity — own rings, rolled every
    /// slot.
    pub pending: PendingGroup,
    pub previous_participation: PreviousParticipationGroup,
    pub current_participation: CurrentParticipationGroup,
    pub inactivity: InactivityScoresGroup,
    /// `slashings` — `Vector[Gwei, 8192]` at slot cadence: the effective ring
    /// changes at one bucket per epoch (and again as slashings land within it),
    /// which is the dirty-leaf write shape.
    pub slashings: SlashingsGroup,
    /// `block_roots` / `state_roots` — `Vector[Root, 8192]` at slot cadence:
    /// `process_slot` overwrites one bucket in each per slot.
    pub block_roots: BlockRootsGroup,
    pub state_roots: StateRootsGroup,
    /// `randao_mixes` — `Vector[Bytes32, 65536]` at slot cadence: the current
    /// epoch's bucket absorbs one reveal per block.
    pub randao_mixes: RandaoMixesGroup,
    /// Slot tier (`SlotState` scalars) — own ring, rolled every slot; its base
    /// holds the canonical finalized slot.
    pub slot_states: SlotStateGroup,
    /// Epoch tier (`EpochState` + Gloas' PTC window) and longtail tier
    /// (sync committees + historical summaries) — own rings, rolled lazily at
    /// epoch / rotation boundaries; their bases hold the canonical finalized
    /// state.
    pub epoch: EpochGroup,
    pub longtail: LongtailGroup,
    /// Gloas builder registry — own ring, rolled every slot.
    pub builders: BuildersGroup,
}

impl BeaconState {
    pub fn is_finalized_post_gloas(&self) -> bool {
        self.epoch.finalized().state().fork.current_version == self.immutable.gloas_fork_version
    }

    /// Anchor a fresh per-fork delta on every always-rolled tier (epoch/
    /// longtail stay lazy: `None` reads their bases) and assemble the anchor
    /// bundle — the bootstrap / pre-bootstrap head.
    pub fn roll_fresh(&mut self) -> StateId {
        StateId {
            epoch_idx: None,
            longtail_idx: None,
            balances_idx: self.balances.roll_fresh().commit(),
            eth1_idx: self.eth1.roll_fresh().commit(),
            pending_idx: self.pending.roll_fresh().commit(),
            previous_participation_idx: self.previous_participation.roll_fresh().commit(),
            current_participation_idx: self.current_participation.roll_fresh().commit(),
            inactivity_idx: self.inactivity.roll_fresh().commit(),
            slashings_idx: self.slashings.roll_fresh().commit(),
            block_roots_idx: self.block_roots.roll_fresh().commit(),
            state_roots_idx: self.state_roots.roll_fresh().commit(),
            randao_idx: self.randao_mixes.roll_fresh().commit(),
            slot_idx: self.slot_states.roll_fresh().commit(),
            validators_idx: self.validators.roll_fresh().commit(),
            builders_idx: self.builders.roll_fresh().commit(),
        }
    }

    /// Roll a child fork off `parent` and hold every tier's writer — ids
    /// surface only at the view's `commit`. Epoch/longtail roll only at
    /// boundaries, so they ride alongside unrolled.
    pub fn roll_from(
        &mut self,
        parent: StateId,
    ) -> (StateWriterView<'_>, &mut EpochGroup, &mut LongtailGroup) {
        let view = StateWriterView {
            imm: &self.immutable,
            balances: self.balances.roll_from(parent.balances_idx),
            eth1: self.eth1.roll_from(parent.eth1_idx),
            pending: self.pending.roll_from(parent.pending_idx),
            previous_participation: self
                .previous_participation
                .roll_from(parent.previous_participation_idx),
            current_participation: self
                .current_participation
                .roll_from(parent.current_participation_idx),
            inactivity: self.inactivity.roll_from(parent.inactivity_idx),
            slashings: self.slashings.roll_from(parent.slashings_idx),
            block_roots: self.block_roots.roll_from(parent.block_roots_idx),
            state_roots: self.state_roots.roll_from(parent.state_roots_idx),
            randao_mixes: self.randao_mixes.roll_from(parent.randao_idx),
            slot: self.slot_states.roll_from(parent.slot_idx),
            validators: self.validators.roll_from(parent.validators_idx),
            builders: self.builders.roll_from(parent.builders_idx),
        };
        (view, &mut self.epoch, &mut self.longtail)
    }

    /// Resolve a fork's read view from its index bundle — the ONE resolver
    /// behind both the writer thread's `read_view` and the cross-thread
    /// optimistic reader.
    pub fn read_view(&self, state_id: StateId) -> StateReadView<'_> {
        StateReadView {
            imm: &self.immutable,
            balances: self.balances.view(state_id.balances_idx),
            eth1: self.eth1.view(state_id.eth1_idx),
            epoch: self.epoch.view_opt(state_id.epoch_idx),
            longtail: self.longtail.view_opt(state_id.longtail_idx),
            pending: self.pending.view(state_id.pending_idx),
            previous_participation: self
                .previous_participation
                .view(state_id.previous_participation_idx),
            current_participation: self
                .current_participation
                .view(state_id.current_participation_idx),
            slashings: self.slashings.view(state_id.slashings_idx),
            block_roots: self.block_roots.view(state_id.block_roots_idx),
            state_roots: self.state_roots.view(state_id.state_roots_idx),
            randao_mixes: self.randao_mixes.view(state_id.randao_idx),
            inactivity: self.inactivity.view(state_id.inactivity_idx),
            slot: self.slot_states.view(state_id.slot_idx),
            validators: self.validators.view(state_id.validators_idx),
            builders: self.builders.view(state_id.builders_idx),
        }
    }
}

/// Test-only constructors. `#[doc(hidden)]` + dev-dependency-only use keeps
/// them out of the public API and the production binary.
impl BeaconState {
    #[doc(hidden)]
    pub fn for_test(epoch_base: EpochStateFinalized, seeds: &[ValSeed], slot: u64) -> Self {
        let validators =
            ValidatorsGroup::new(FinalizedValidators::with_validators(seeds), HashFormat::Fixed);
        let cap = validators.finalized().capacity();
        let n = validators.finalized().validator_count();
        let balances: Vec<u8> = seeds.iter().flat_map(|s| s.balance.to_le_bytes()).collect();
        // Sibling columns are zeroed lockstep with the registry: `n` entries of
        // the column's element width (participation flags 1 B, scores 8 B).
        let zeros = |width: usize| vec![0u8; n * width];
        let epoch_balances = validators.finalized().sweep_epoch_balances(
            &zeros(1),
            &zeros(1),
            slot / SLOTS_PER_EPOCH,
        );
        Self {
            immutable: Immutable::default(),
            validators,
            balances: BalancesGroup::new(cap, n, &balances, HashFormat::Fixed).unwrap(),
            eth1: Eth1Group::new(Eth1Votes::default()),
            pending: PendingGroup::from_ssz(&[], &[], &[], &[]),
            previous_participation: PreviousParticipationGroup::new(
                cap,
                n,
                &zeros(1),
                HashFormat::Fixed,
            )
            .unwrap(),
            current_participation: CurrentParticipationGroup::new(
                cap,
                n,
                &zeros(1),
                HashFormat::Fixed,
            )
            .unwrap(),
            inactivity: InactivityScoresGroup::new(cap, n, &zeros(8), HashFormat::Fixed).unwrap(),
            slashings: SlashingsGroup::zeroed_vector(),
            block_roots: BlockRootsGroup::zeroed_vector(),
            state_roots: StateRootsGroup::zeroed_vector(),
            randao_mixes: RandaoMixesGroup::zeroed_vector(),
            slot_states: SlotStateGroup::new(
                SlotStateFinalized::new(SlotState { slot, ..Default::default() })
                    .with_epoch_balances(epoch_balances),
            ),
            epoch: EpochGroup::new(epoch_base),
            longtail: LongtailGroup::new(LongtailState::default()),
            builders: BuildersGroup::new(FinalizedBuilders::default()),
        }
    }

    #[doc(hidden)]
    pub fn empty_test(slot: u64) -> Self {
        Self::for_test(EpochStateFinalized::default(), &[], slot)
    }
}
