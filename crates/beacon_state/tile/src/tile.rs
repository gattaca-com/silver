use std::{fmt::Debug, sync::Arc};

use flux::{
    spine::{FluxSpine, SpineAdapter, SpineProducers},
    tile::Tile,
};
use flux_profiler::timed;
use rustc_hash::FxHashMap;
use silver_beacon_state_data::{
    B256, BeaconBlockHeader, BeaconState, BeaconStateOwner, BeaconStateReader, Checkpoint, Epoch,
    SLOTS_PER_EPOCH, Slot, SlotState, SpecConfig, StateId,
};
use silver_common::{
    BeaconStateEvent, BlockSource, DataColumnsEvent, DataKind, EngineResp, GossipTopic, HeadChange,
    HeadRoots, LocalAttestationFailure, LocalAttestationResult, NewGossipMsg, Origin,
    PayloadResolution, ReplayBlock, RequestId, RpcInbound, RpcResponse, RpcResponseInbound,
    SilverSpine, SyncUpdate, TCacheError, TCacheId, TCacheProducer, TCacheReader, TCacheTable,
    TProducer, TRead, TReadMode, hex32,
    ssz_view::STATUS_V2_SIZE,
    ticker::{MAXIMUM_GOSSIP_CLOCK_DISPARITY, SlotTicker, TickEvent},
};
use silver_config::{PendingBounds, SyncingConfig};

use crate::{
    bls,
    fork_choice::{ExecutionStatus, FORK_CHOICE_NODES_HINT, ForkChoice},
    ssz_hash, stf,
    tile::{
        attestation_pool::AttestationPool,
        attestation_root_memo::AttestationRootMemo,
        fork_data_roots::ForkDataRoots,
        held_blocks::{HeldBlocks, StagedVerdict},
        precomputed_epochs::PrecomputedEpochs,
        seen_aggregates::SeenAggregates,
        seen_validators::{SeenIndices, SeenValidators},
        shuffling_cache::ShufflingCache,
        sync_contribution_pool::SyncContributionPool,
    },
    weak_subjectivity::{weak_subjectivity_period_fulu, weak_subjectivity_period_gloas},
};

mod attestation_pool;
mod precomputed_epochs;
// `pub` for the crate's `attestation_root_memo` criterion bench.
pub mod attestation_root_memo;
mod block;
mod finalize;
mod fork_choice;
mod fork_data_roots;
mod gossip;
mod held_blocks;
mod orphan_pool;
mod seen_aggregates;
mod seen_validators;
mod shuffling_cache;
mod sync_contribution_pool;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Feedback {
    /// The message was accepted; the caller publishes the status.
    Accept,
    /// The block was added to fork choice and its status is published.
    BlockImported(B256),
    Ignore,
    /// An ignore for a vote whose validator already has one committed for the
    /// same epoch or slot.
    DuplicateVote,
    /// Carries the failed `block_root` (only) when the reject came from a
    /// post-`body_root`/STF path in block validation, so PM can blacklist
    /// the chain. All other reject paths (attestation, exit, slashing,
    /// pre-hash block fails) use `Reject(None)`.
    Reject(Option<B256>),
    RequestParent {
        parent_root: B256,
        block_root: B256,
    },
    /// State transition committed; fork-choice import waits on the block's
    /// data columns.
    AwaitData(B256),
    AwaitParentPayload {
        parent_root: B256,
        block_root: B256,
    },
    RequestEnvelope {
        block_root: B256,
        att_slot: Slot,
    },
    AlreadyKnown(B256),
}

// Manual Debug to hex-encode the `B256` roots (`B256 = [u8; 32]`, whose
// derived Debug prints a raw byte array).
impl Debug for Feedback {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Accept => f.write_str("Accept"),
            Self::BlockImported(r) => write!(f, "BlockImported(0x{})", hex32(r)),
            Self::Ignore => f.write_str("Ignore"),
            Self::DuplicateVote => f.write_str("DuplicateVote"),
            Self::Reject(Some(r)) => write!(f, "Reject(Some(0x{}))", hex32(r)),
            Self::Reject(None) => f.write_str("Reject(None)"),
            Self::RequestParent { parent_root, block_root } => write!(
                f,
                "RequestParent(parent=0x{}, block=0x{})",
                hex32(parent_root),
                hex32(block_root)
            ),
            Self::AwaitData(r) => write!(f, "AwaitData(0x{})", hex32(r)),
            Self::AwaitParentPayload { parent_root, block_root } => write!(
                f,
                "AwaitPayload(parent=0x{}, block=0x{})",
                hex32(parent_root),
                hex32(block_root)
            ),
            Self::RequestEnvelope { block_root, att_slot } => {
                write!(f, "RequestEnvelope(0x{}, att_slot={att_slot})", hex32(block_root))
            }
            Self::AlreadyKnown(r) => write!(f, "AlreadyKnown(0x{})", hex32(r)),
        }
    }
}

/// Resolved once so each Status uses one fork's head metadata.
#[derive(Clone, Copy)]
struct SelectedHead {
    observation: HeadObservation,
    idx: usize,
}

/// Head changes that require a Status even without an import or slot tick.
#[derive(Clone, Copy, PartialEq, Eq)]
struct HeadObservation {
    root: B256,
    optimistic: bool,
    payload: PayloadResolution,
}

pub struct BeaconStateTile {
    sync_target: SyncUpdate,
    ticker: SlotTicker,

    spec: Arc<SpecConfig>,

    fork_choice: ForkChoice,
    shuffling_cache: Box<ShufflingCache>,
    events_producer: TProducer,
    seen_attesters: SeenValidators,
    seen_aggregators: SeenValidators,
    seen_aggregates: SeenAggregates,
    attestation_pool: AttestationPool,
    attestation_root_memo: AttestationRootMemo,
    vote_batch: Vec<NewGossipMsg>,
    vote_pending: Vec<(NewGossipMsg, gossip::PreparedVote)>,
    seen_sync_msgs: [SeenValidators; silver_common::SYNC_COMMITTEE_SUBNETS],
    sync_contribution_pool: SyncContributionPool,
    seen_contribution_aggregators: [SeenValidators; silver_common::SYNC_COMMITTEE_SUBNETS],
    seen_ptc: SeenValidators,
    seen_exits: SeenIndices,
    seen_bls_changes: SeenIndices,
    seen_proposer_slashings: SeenIndices,
    seen_attester_slashed: SeenIndices,
    fork_data_roots: ForkDataRoots,

    /// Canonical in-process state: finalized base + per-fork per-tier rings.
    /// Other tiles read via `state.reader()` (raw-ptr + seqlock).
    state: BeaconStateOwner,

    /// Index bundle of the canonical head's post-state.
    last_applied: StateId,

    precomputed_epochs: PrecomputedEpochs,

    last_seen_head_root: B256,
    /// Kept separate from the reorg marker: an early Status must not hide a
    /// reorg that the end-of-loop check has yet to report.
    emitted_head: Option<HeadObservation>,

    initial_status_emitted: bool,
    cached_fork_digest: Option<(Epoch, [u8; 4])>,

    stf_scratch: stf::StfScratch,
    /// Every BLS verification the tile runs, for blocks and for gossip alike.
    ///
    /// A block's pre-validation pass collects its signatures here, then
    /// `verify_all` runs once before pass 2 mutates state. Each gossip handler
    /// builds its own batch the same way. They share one instance for two
    /// reasons: no two of them are ever live at once, and sharing lets them
    /// reuse each other's cache of hashed signing roots.
    sig_batch: bls::SigBatch,
    held: HeldBlocks,
    /// Gloas: payload envelopes seen before their block entered fork choice.
    pending_envelopes: FxHashMap<B256, TRead>,
    /// Resolved pending-buffer admission / eviction / fallback bounds.
    pending_bounds: PendingBounds,

    verify_weak_subjectivity: bool,

    // Last: acquired reads above point into it.
    reader: TCacheReader,
}

type Producers = <SilverSpine as FluxSpine>::Producers;

fn root_map<V>() -> FxHashMap<B256, V> {
    FxHashMap::with_capacity_and_hasher(FORK_CHOICE_NODES_HINT, Default::default())
}

impl BeaconStateTile {
    /// Builds the tile owning the checkpoint `state` (from
    /// [`BeaconState::from_checkpoint`]), seeds the anchor + fork choice, and
    /// publishes. Boots Syncing; PM flips it to `Following` once
    /// caught up to head. Wire other tiles' read handles afterwards with
    /// [`reader`](Self::reader) (valid across the publish — same allocation).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ticker: SlotTicker,
        spec: Arc<SpecConfig>,
        syncing: &SyncingConfig,
        tcaches: TCacheTable,
        events_producer: TProducer,
        verify_weak_subjectivity: bool,
        state: BeaconState,
    ) -> Self {
        let mut owner = BeaconStateOwner::new(state);
        let val_cap = owner.state().validators.finalized().capacity();
        let (anchor, anchor_header) = Self::roll_anchor(&mut owner);
        let mut tile = Self {
            sync_target: SyncUpdate::default(),
            ticker,
            spec,
            state: owner,
            fork_choice: ForkChoice::default(),
            shuffling_cache: ShufflingCache::with_capacity(val_cap),
            events_producer,
            seen_attesters: SeenValidators::new(val_cap),
            seen_aggregators: SeenValidators::new(val_cap),
            seen_aggregates: SeenAggregates::new(),
            attestation_pool: AttestationPool::new(),
            vote_batch: Vec::with_capacity(gossip::VOTE_BATCH_CAP),
            vote_pending: Vec::with_capacity(gossip::VOTE_BATCH_CAP),
            seen_sync_msgs: std::array::from_fn(|_| SeenValidators::new(val_cap)),
            sync_contribution_pool: SyncContributionPool::new(),
            seen_contribution_aggregators: std::array::from_fn(|_| SeenValidators::new(val_cap)),
            seen_ptc: SeenValidators::new(val_cap),
            seen_exits: SeenIndices::new(val_cap),
            seen_bls_changes: SeenIndices::new(val_cap),
            seen_proposer_slashings: SeenIndices::new(val_cap),
            seen_attester_slashed: SeenIndices::new(val_cap),
            attestation_root_memo: AttestationRootMemo::default(),
            fork_data_roots: ForkDataRoots::default(),
            last_applied: anchor,
            precomputed_epochs: PrecomputedEpochs::default(),
            last_seen_head_root: [0u8; 32],
            emitted_head: None,
            initial_status_emitted: false,
            cached_fork_digest: None,
            stf_scratch: stf::StfScratch::new(val_cap),
            sig_batch: bls::SigBatch::new(),
            held: HeldBlocks::new(&syncing.pending),
            pending_envelopes: root_map(),
            pending_bounds: syncing.pending,
            verify_weak_subjectivity,
            reader: TCacheReader::new(tcaches),
        };
        tile.seed_anchor(anchor, anchor_header, val_cap);
        tracing::info!("created BeaconStateTile: head_state_slot is {}", tile.head_state_slot());
        tile
    }

    pub fn open_tcaches(&mut self) -> Result<(), TCacheError> {
        self.reader.open(
            TCacheId::ControlProcessing,
            "bs_control_processing",
            TReadMode::Sliding,
        )?;
        self.reader.open(
            TCacheId::NetworkProcessing,
            "bs_network_processing",
            TReadMode::Sliding,
        )?;
        self.reader.open(
            TCacheId::BoundaryProcessing,
            "bs_boundary_processing",
            TReadMode::Sliding,
        )?;
        self.reader.open(TCacheId::StorageDelivery, "bs_storage_delivery", TReadMode::Sliding)?;
        self.reader.open(TCacheId::ControlSlot, "bs_control_slot", TReadMode::Sliding)
    }

    /// A read handle on the owned state, for wiring other tiles (lock-free
    /// seqlock reads). Valid across the anchor publish — same allocation.
    pub fn reader(&self) -> BeaconStateReader {
        self.state.reader()
    }

    pub fn head_block_root(&self) -> B256 {
        self.slot_state_at(self.last_applied).latest_block_root
    }

    pub fn fork_choice_head(&self) -> B256 {
        self.fork_choice.find_head()
    }

    /// Effective `SlotState` for a state bundle, resolved through its
    /// slot-group view (the slot tier lives in `slot_states`, keyed by
    /// `slot_idx`).
    fn slot_state_at(&self, state_id: StateId) -> &SlotState {
        self.state.state().slot_states.view(state_id.slot_idx).state()
    }

    pub fn head_state_slot(&self) -> Slot {
        self.slot_state_at(self.last_applied).slot
    }

    pub fn head_validator_count(&self) -> usize {
        self.state.state().validators.view(self.last_applied.validators_idx).count()
    }

    /// Fork-choice finalized epoch — advances only when `finalize` promotes a
    /// new base. The perf harness asserts this moved past the anchor so the
    /// replay actually exercises finalization.
    pub fn fork_choice_finalized_epoch(&self) -> u64 {
        self.fork_choice.finalized_checkpoint.epoch
    }

    /// Fork-choice finalized block root — what a restart's `seed_anchor`
    /// re-derives from the persisted checkpoint. Test/harness surface.
    pub fn fork_choice_finalized_root(&self) -> B256 {
        self.fork_choice.finalized_checkpoint.root
    }

    /// `(current_justified, finalized)` as seen by the canonical head's
    /// post-state. Reads the epoch delta if the head fork owns one; otherwise
    /// falls back to the finalized base epoch state.
    fn head_checkpoints(&self) -> (Checkpoint, Checkpoint) {
        let es = self.state.state().epoch.view_opt(self.last_applied.epoch_idx).state();
        (es.current_justified_checkpoint, es.finalized_checkpoint)
    }

    fn head_finalized_checkpoint(&self) -> Checkpoint {
        self.head_checkpoints().1
    }

    /// SSZ `hash_tree_root` of the most-recently-applied block's full
    /// BeaconState. Used by integration tests to cross-check tile-applied
    /// STF output against EF post-state vectors.
    pub fn head_state_root(&mut self) -> B256 {
        let rv = self.state.read_view(self.last_applied);
        ssz_hash::hash_tree_root_state(&rv)
    }

    /// Anchor block root. Compute on a local header copy so the state's
    /// `latest_block_header.state_root` stays `[0;32]` — the first
    /// post-bootstrap `process_slot` hashes that canonical state and a
    /// patched value would shift the result.
    fn roll_anchor(owner: &mut BeaconStateOwner) -> (StateId, BeaconBlockHeader) {
        let mut writer = owner.fresh_fork_writer();
        let rv = writer.read();
        let mut header = rv.slot.state().latest_block_header;
        if header.state_root == [0u8; 32] {
            header.state_root = ssz_hash::hash_tree_root_state(&rv);
        }
        writer.view.slot.state_mut().latest_block_root =
            ssz_hash::hash_tree_root_block_header(&header);
        (writer.commit(), header)
    }

    /// Seed fork choice from the freshly-anchored real state and publish the
    /// `anchor` — the second half of `new` for a non-stub state. (Caches are
    /// already sized for the real validator count in `new`.)
    fn seed_anchor(
        &mut self,
        anchor: StateId,
        header: BeaconBlockHeader,
        validators_capacity: usize,
    ) {
        let slot = self.state.state().slot_states.finalized_view().slot_number();

        let (anchor_is_gloas, block_root, execution_block_hash) = {
            let rv = self.state.read_view(anchor);
            let slot_state = rv.slot.state();
            let execution_block_hash = if rv.is_gloas() {
                slot_state.latest_execution_payload_bid.block_hash
            } else {
                slot_state.latest_execution_payload_header.block_hash
            };
            (rv.is_gloas(), slot_state.latest_block_root, execution_block_hash)
        };

        let trusted = Checkpoint { epoch: slot.div_ceil(SLOTS_PER_EPOCH), root: block_root };
        self.last_seen_head_root = block_root;

        // A checkpoint state can be ahead of its latest block. Peers need
        // the block's slot in Status.
        self.fork_choice = ForkChoice::init(
            trusted,
            trusted,
            header.slot,
            block_root,
            header.state_root,
            execution_block_hash,
            anchor_is_gloas,
            anchor,
            validators_capacity,
        );

        self.state.publish_state_id(anchor);

        self.assert_within_weak_subjectivity();

        // Warm {E-1, E, E+1} shufflings and aggregates before the first
        // message, so no block or attestation pays a shuffle inline.
        let anchor_epoch = slot / SLOTS_PER_EPOCH;
        let view = self.state.read_view(anchor);
        self.shuffling_cache.ensure_window(&view, anchor_epoch + 1);
        self.shuffling_cache.ensure_window(&view, anchor_epoch);
        self.shuffling_cache.try_cache_committee_aggs(&view, anchor_epoch + 1);
        self.shuffling_cache.try_cache_committee_aggs(&view, anchor_epoch);
        self.fork_choice.justified.precompute(trusted, view.validators);
    }

    fn fork_digest(&mut self) -> [u8; 4] {
        let epoch = self.ticker.current_slot() / SLOTS_PER_EPOCH;
        if let Some((cached_epoch, d)) = self.cached_fork_digest &&
            cached_epoch == epoch
        {
            return d;
        }

        let gvr = self.state.state().immutable.genesis_validators_root;
        let d = self.spec.fork_digest_at(epoch, &gvr);
        self.cached_fork_digest = Some((epoch, d));
        d
    }

    fn enr_fork_id(&mut self) -> [u8; 16] {
        let digest = self.fork_digest();
        let epoch = self.ticker.current_slot() / SLOTS_PER_EPOCH;
        let (next_version, next_epoch) = self.spec.next_fork(epoch);

        let mut eth2 = [0u8; 16];
        eth2[..4].copy_from_slice(&digest);
        eth2[4..8].copy_from_slice(&next_version);
        eth2[8..].copy_from_slice(&next_epoch.to_le_bytes());
        eth2
    }

    pub fn assert_within_weak_subjectivity(&mut self) {
        if !self.verify_weak_subjectivity {
            return;
        }

        let ws_period = {
            let view = self.state.read_view(self.last_applied);
            if view.is_gloas() {
                weak_subjectivity_period_gloas(&self.spec, &view, &mut self.stf_scratch.active)
            } else {
                weak_subjectivity_period_fulu(&view, &mut self.stf_scratch.active)
            }
        };

        let checkpoint_epoch = self.head_state_slot() / SLOTS_PER_EPOCH;
        let current_epoch = self.ticker.current_slot() / SLOTS_PER_EPOCH;
        assert!(
            current_epoch <= checkpoint_epoch + ws_period,
            "checkpoint epoch {checkpoint_epoch} is outside the weak-subjectivity period \
             ({ws_period} epochs); wall epoch {current_epoch} — refusing stale anchor \
             (override with --disable-weak-subjectivity)",
        );
    }

    fn status_payload(&mut self, head_root: B256, head_idx: usize) -> [u8; STATUS_V2_SIZE] {
        let fork_digest = self.fork_digest();
        let node = self.fork_choice.node(head_idx);
        let slot = node.slot;
        let mut finalized = node.checkpoints.finalized;

        if finalized.root == [0u8; 32] {
            // Genesis placeholder: the head state's finalized root is zero until
            // the first finalization, but peers (lighthouse/prysm) report the
            // genesis *block* root from fork choice and reject a zero finalized
            // root in Status validation. Mirror them — fork choice holds the
            // trusted anchor root set at bootstrap.
            finalized.root = self.fork_choice.finalized_checkpoint.root;
        }

        let earliest = finalized.epoch * SLOTS_PER_EPOCH;

        let mut buf = [0u8; STATUS_V2_SIZE];
        buf[0..4].copy_from_slice(&fork_digest);
        buf[4..36].copy_from_slice(&finalized.root);
        buf[36..44].copy_from_slice(&finalized.epoch.to_le_bytes());
        buf[44..76].copy_from_slice(&head_root);
        buf[76..84].copy_from_slice(&slot.to_le_bytes());
        buf[84..92].copy_from_slice(&earliest.to_le_bytes());
        buf
    }

    /// Slot of the highest block we've imported (`last_applied`), excluding
    /// empty slots. Sync's request watermark keys off this.
    fn last_applied_block_slot(&self) -> Slot {
        self.slot_state_at(self.last_applied).latest_block_header.slot
    }

    fn selected_head(&self) -> SelectedHead {
        let root = self.fork_choice.find_head();
        let idx =
            self.fork_choice.find_node_idx(&root).expect("find_head returns a node-resident root");
        let optimistic = self.fork_choice.node(idx).execution_status != ExecutionStatus::Valid;
        let payload = self.fork_choice.payload_resolution(idx);
        SelectedHead { observation: HeadObservation { root, optimistic, payload }, idx }
    }

    /// Overwritten checkpoint history makes the whole root bundle unavailable;
    /// partial metadata cannot describe the head.
    fn head_roots(&self, head: SelectedHead) -> HeadRoots {
        let node = self.fork_choice.node(head.idx);
        let epoch = node.slot / SLOTS_PER_EPOCH;
        let view = self.state.read_view(node.state_id);
        let state_slot = view.slot.state().slot;
        let dependent =
            |epoch| view.block_roots.duty_dependent_root(epoch, head.observation.root, state_slot);
        match (dependent(epoch.saturating_sub(1)), dependent(epoch)) {
            (Some(previous), Some(current)) => HeadRoots {
                state_root: node.state_root,
                previous_duty_dependent_root: previous,
                current_duty_dependent_root: current,
            },
            _ => HeadRoots::default(),
        }
    }

    fn status_event(&mut self, head: SelectedHead) -> BeaconStateEvent {
        let curr = head.observation;
        let roots = self.head_roots(head);
        let prev = self.emitted_head.filter(|_| roots.is_complete());
        let head_change = match prev {
            Some(prev) if prev.root != curr.root || prev.optimistic != curr.optimistic => {
                HeadChange::Head
            }
            Some(prev) if prev.payload != curr.payload => HeadChange::Payload,
            _ => HeadChange::None,
        };

        let node = self.fork_choice.node(head.idx);
        let epoch = node.slot / SLOTS_PER_EPOCH;
        let epoch_transition = self
            .fork_choice
            .parent(head.idx)
            .is_some_and(|parent| epoch > parent.slot / SLOTS_PER_EPOCH);

        BeaconStateEvent::Status {
            ssz: self.status_payload(curr.root, head.idx),
            latest_block_slot: self.last_applied_block_slot(),
            wall_slot: self.ticker.current_slot(),
            head_optimistic: curr.optimistic,
            enr_fork_id: self.enr_fork_id(),
            head_roots: roots,
            head_payload: curr.payload,
            head_change,
            epoch_transition,
        }
    }

    pub(super) fn publish_status(&mut self, producers: &mut Producers) {
        self.publish_selected_head(self.selected_head(), producers);
    }

    fn publish_selected_head(&mut self, head: SelectedHead, producers: &mut Producers) {
        debug_assert!(
            !self.pending_envelopes.contains_key(&head.observation.root),
            "Status would describe a head whose envelope is still pending"
        );
        let event = self.status_event(head);
        self.emitted_head = Some(head.observation);
        producers.produce(event);
    }

    fn post_shufflings(&mut self, producers: &mut Producers) {
        let head_epoch = self.slot_state_at(self.last_applied).slot / SLOTS_PER_EPOCH;
        let producer = &mut self.events_producer;
        let posted =
            self.shuffling_cache.post_fresh(head_epoch, producer, |event| producers.produce(event));
        if posted {
            producer.publish_head();
        }
    }

    /// Covers changes since the last Status, including execution verdicts.
    fn publish_status_on_head_change(&mut self, producers: &mut Producers) {
        let head = self.selected_head();
        if Some(head.observation) != self.emitted_head {
            self.publish_selected_head(head, producers);
        }
    }

    /// Returns `true` iff at least one slot was processed (so head_slot
    /// definitely advanced, and finalized may have advanced via an epoch
    /// transition along the way).
    fn on_slot_start(&mut self, target_slot: Slot) -> bool {
        let curr_slot = self.slot_state_at(self.last_applied).slot;
        if target_slot <= curr_slot {
            return false;
        }

        let new_id = self.state_at(self.last_applied, target_slot);
        self.last_applied = new_id;
        self.state.publish_state_id(new_id);
        // Empty-slot epoch transitions can advance justified/finalized in the
        // head post-state; reflect that in fork choice before finalizing.
        self.lift_checkpoints();
        self.maybe_finalize();
        true
    }

    fn state_at(&mut self, from: StateId, slot: Slot) -> StateId {
        let from = self.epoch_start_state(from, slot);
        if self.slot_state_at(from).slot == slot {
            return from;
        }
        Self::process_slots_advance(&mut self.state, &self.spec, &mut self.stf_scratch, from, slot)
    }

    /// `from` advanced to the first slot of `slot`'s epoch when `slot` is in a
    /// later one, else `from`.
    #[timed]
    fn epoch_start_state(&mut self, from: StateId, slot: Slot) -> StateId {
        let epoch = slot / SLOTS_PER_EPOCH;
        let from_state = self.slot_state_at(from);
        if epoch <= from_state.slot / SLOTS_PER_EPOCH {
            return from;
        }
        let root = from_state.latest_block_root;
        let (state, spec, scratch) = (&mut self.state, &self.spec, &mut self.stf_scratch);
        self.precomputed_epochs.get_or_insert(root, epoch, || {
            Self::process_slots_advance(state, spec, scratch, from, epoch * SLOTS_PER_EPOCH)
        })
    }

    /// Always a child fork: `process_epoch` shifts `proposer_lookahead` in the
    /// shared epoch entry, and sibling blocks still build on `from`.
    fn process_slots_advance(
        state: &mut BeaconStateOwner,
        spec: &SpecConfig,
        scratch: &mut stf::StfScratch,
        from: StateId,
        to: Slot,
    ) -> StateId {
        let mut fork = state.apply_block_view(from);
        stf::process_slots(spec, &mut fork, to, scratch);
        fork.commit()
    }

    fn on_state_advance(&mut self, _slot: Slot) {
        // Pre-compute state for next slot (optimization).
        // Copy current SlotData + advance one slot on the copy.
        // TODO: implement pre-computation
    }

    fn on_fc_lookahead(&mut self, _slot: Slot) {
        // Pre-emptive get_head for next slot.
        // TODO: self.get_head() and cache result
    }

    /// Per-slot fork-choice tick (spec `on_tick_per_slot`): advance the head
    /// state across empty slots, then run the fork-choice tick. Returns whether
    /// a state advance occurred.
    fn slot_tick(&mut self, slot: Slot) -> bool {
        let advanced = self.on_slot_start(slot);
        if advanced {
            // Head-derived epoch, never the wall clock (wall-clock epochs
            // diverge from the head during sync and poison the cache).
            // Covers epochs with no blocks, where no post-apply hook fired.
            let state_epoch = self.slot_state_at(self.last_applied).slot / SLOTS_PER_EPOCH;
            self.precompute_next_epoch_shuffling(state_epoch);
        }
        self.fork_choice_tick();
        let floor = slot.saturating_sub(1);
        self.attestation_pool.prune_before(floor);
        self.sync_contribution_pool.prune_before(floor);
        self.seen_aggregates.prune_before(floor);
        self.attestation_root_memo.prune_before(floor);
        advanced
    }

    fn handle_engine_response(&mut self, eng_resp: EngineResp, producers: &mut Producers) {
        match eng_resp {
            EngineResp::NewPayload(r) => {
                match self.held.on_payload_verdict(&r.block_root, r.status) {
                    StagedVerdict::Rejected(source) => {
                        tracing::warn!(
                            block = hex32(&r.block_root),
                            "EL rejected a staged block; dropped"
                        );
                        producers.produce(BeaconStateEvent::BlockRejected {
                            block_root: r.block_root,
                            source,
                        });
                    }
                    StagedVerdict::Kept => {}
                    StagedVerdict::NotStaged => {
                        self.on_payload_verdict(&r.block_root, &r.latest_valid_hash, r.status);
                    }
                }
            }
            EngineResp::Fcu(r) => {
                self.on_payload_verdict(&r.block_root, &r.latest_valid_hash, r.status);
            }
            // Proposal flow — silver doesn't propose yet, nothing requests
            // payloads.
            EngineResp::GetPayload(_) => {}
            // EL-mempool blob fetch. Belongs to the storage tile (it owns
            // column validation/availability), not here; see the TODO at its
            // column-request path.
            EngineResp::GetBlobs(_) => {}
        }
    }

    fn syncing_loop(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        self.consume_shared(adapter);

        adapter.consume(|m: NewGossipMsg, producers| {
            tracing::trace!(
                topic = ?m.topic,
                p2p_peer = m.stream_id.peer(),
                staged_len = self.held.staged_len(),
                head_slot = self.head_state_slot(),
                "gossip dropped: BeaconState in Syncing mode"
            );
            Self::local_verdict(
                &m,
                LocalAttestationResult::Failure(LocalAttestationFailure::Unverifiable),
                producers,
            );
        });
        self.reader.free();
    }

    fn following_loop(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        self.consume_shared(adapter);

        match self.ticker.tick() {
            TickEvent::SlotStart(slot) => {
                let prev_head = self.fork_choice.find_head();
                let advanced = self.slot_tick(slot);
                if advanced || self.fork_choice.find_head() != prev_head {
                    self.publish_status(&mut adapter.producers);
                }
            }
            TickEvent::StateAdvance(slot) => self.on_state_advance(slot),
            TickEvent::ForkChoiceLookahead(slot) => self.on_fc_lookahead(slot),
            // TODO(EL): send engine_forkchoiceUpdatedV3 with payload
            // attributes to start EL block building for this slot.
            TickEvent::PreparePayload(_) => {}
            TickEvent::None => {}
        }

        adapter.consume(|m: NewGossipMsg, producers| self.on_gossip(m, producers));
        self.flush_votes(&mut adapter.producers);
        self.reader.free();

        self.post_shufflings(&mut adapter.producers);
    }

    /// Per-validator votes (attestations, sync committee messages, PTC
    /// attestations) are deferred into the shared batch; anything else
    /// flushes it first, so the queue order the batch reorders is restored
    /// here.
    fn on_gossip(&mut self, m: NewGossipMsg, producers: &mut Producers) {
        if matches!(
            m.topic,
            GossipTopic::BeaconAttestation(_) |
                GossipTopic::SyncCommittee(_) |
                GossipTopic::PayloadAttestationMessage
        ) {
            self.defer_vote(m, producers);
            return;
        }
        self.flush_votes(producers);
        self.handle_gossip(m.ssz, m, true, false, producers);
    }

    fn consume_shared(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        adapter.consume(|target: SyncUpdate, _producers| self.on_sync_update(target));

        adapter.consume(|m: RpcInbound, producers| self.on_rpc_inbound(m, producers));

        adapter.consume(|m: DataColumnsEvent, producers| {
            if let DataColumnsEvent::Available { block_root, slot } = m {
                self.handle_data_columns_available(block_root, slot, producers);
            }
        });

        adapter.consume(|eng_resp: EngineResp, producers| {
            self.handle_engine_response(eng_resp, producers);
        });

        adapter.consume(|m: ReplayBlock, producers| self.on_replay(m, producers));
    }

    fn on_sync_update(&mut self, target: SyncUpdate) {
        if target.is_syncing() != self.sync_target.is_syncing() {
            tracing::info!(from = ?self.sync_target, to = ?target, "BeaconState mode transition");
        }
        self.sync_target = target;
        if !self.da_required() {
            let dropped = self.held.drop_all_staged();
            if dropped > 0 {
                tracing::warn!(dropped, "staged blocks dropped: chasing a finalized target");
            }
        }
    }

    fn on_rpc_inbound(&mut self, m: RpcInbound, producers: &mut Producers) {
        let RpcInbound::Response(RpcResponseInbound { application_id, stream_id, response }) = m
        else {
            return;
        };

        let id = RequestId::from(application_id);

        match response {
            RpcResponse::BeaconBlock { fork_digest: _, ssz }
                if id.is(DataKind::Block, Origin::Live) =>
            {
                tracing::debug!(?stream_id, "received beacon block over rpc");
                self.handle_rpc_block(stream_id, ssz, false, producers);
            }
            RpcResponse::ExecutionPayloadEnvelope { fork_digest: _, ssz }
                if id.is(DataKind::Envelope, Origin::Live) =>
            {
                let acquired = self.reader.acquire(ssz);
                match acquired.buffer() {
                    Ok((data, _)) => {
                        self.handle_execution_payload_envelope(
                            acquired.clone(),
                            data,
                            BlockSource::Rpc,
                            producers,
                        );
                    }
                    Err(e) => tracing::error!(
                        ?e,
                        seq = acquired.seq(),
                        "rpc envelope buffer acquire failed"
                    ),
                }
            }
            _ => {}
        }
    }

    /// Replay an on-disk block stream (no EL notify / producer events), then
    /// emit completion status on `Done`.
    fn on_replay(&mut self, m: ReplayBlock, producers: &mut Producers) {
        match m {
            ReplayBlock::Block { ssz } => {
                self.replay_block(ssz);
            }
            ReplayBlock::Envelope { ssz } => {
                self.replay_envelope(ssz);
            }
            ReplayBlock::Done => {
                producers.produce(BeaconStateEvent::ReplayComplete);
                self.publish_status(producers);
            }
        }
    }
}

#[cfg(feature = "ef_tests")]
use silver_common::PayloadValidationStatus;

/// EF `fork_choice`/`sync` vector harness API: thin gated wrappers over the
/// private production methods.
#[cfg(feature = "ef_tests")]
impl BeaconStateTile {
    pub fn ef_fork_choice(&self) -> &ForkChoice {
        &self.fork_choice
    }

    pub fn ef_tick(&mut self, since_genesis_ms: u64) {
        self.ticker.set_since_genesis_ms(since_genesis_ms);
        self.fork_choice_tick();
    }

    pub fn ef_apply_block(&mut self, ssz: &[u8]) -> Option<B256> {
        match self.try_apply_block(ssz) {
            Feedback::BlockImported(r) => Some(r),
            _ => None,
        }
    }

    pub fn ef_apply_attestation(&mut self, ssz: &[u8]) {
        self.apply_attestation(ssz);
        self.recompute_head();
    }

    pub fn ef_apply_attester_slashing(&mut self, ssz: &[u8]) {
        if self.handle_attester_slashing(ssz) == Feedback::Accept {
            self.recompute_head();
        }
    }

    pub fn ef_apply_execution_payload(&mut self, ssz: &[u8]) -> bool {
        // EF vectors have no execution client: validate against the committed bid
        // and mark the payload valid synchronously (production notifies the EL).
        let Some(block_root) = self.ef_processable_envelope(ssz) else { return false };
        self.fork_choice.mark_payload_verified(&block_root);
        self.fork_choice.on_payload_valid(&block_root);
        self.recompute_head();
        true
    }

    /// The block root of an envelope that passes gossip validation and
    /// `process_execution_payload`'s withdrawals check.
    fn ef_processable_envelope(&self, ssz: &[u8]) -> Option<B256> {
        match self.validate_execution_payload_envelope(ssz) {
            gossip::EnvelopeCheck::Ready { block_root, state_id } => {
                let rv = self.state.read_view(state_id);
                stf::envelope_withdrawals_match_expected(&rv, ssz).then_some(block_root)
            }
            gossip::EnvelopeCheck::AwaitBlock(_) |
            gossip::EnvelopeCheck::Ignore |
            gossip::EnvelopeCheck::Reject => None,
        }
    }

    pub fn ef_apply_payload_attestation(&mut self, ssz: &[u8]) -> bool {
        match self.prepare_ptc(ssz) {
            Ok(p) => {
                self.commit_ptc(&p);
                self.recompute_head();
                true
            }
            Err(_) => false,
        }
    }

    pub fn ef_payload_verdict(
        &mut self,
        block_root: B256,
        status: PayloadValidationStatus,
        latest_valid_hash: B256,
    ) {
        self.on_payload_verdict(&block_root, &latest_valid_hash, status);
    }

    /// An envelope seen on gossip and verified against its bid, with the EL
    /// verdict still outstanding (`ef_payload_verdict` delivers it).
    pub fn ef_receive_execution_payload(&mut self, ssz: &[u8]) -> bool {
        let Some(block_root) = self.ef_processable_envelope(ssz) else { return false };
        self.fork_choice.mark_payload_verified(&block_root);
        self.recompute_head();
        true
    }

    pub fn ef_set_finalized_checkpoint(&mut self, cp: Checkpoint) {
        self.fork_choice.lift_finalized(cp);
        self.recompute_head();
    }

    /// The `beacon_block` gossip verdict: precheck plus proposer signature,
    /// which is what production relays on.
    pub fn ef_gossip_block(&mut self, ssz: &[u8]) -> Feedback {
        match self.parse_and_verify_block(ssz, false) {
            Ok(_) => Feedback::Accept,
            Err(err) => err.feedback(),
        }
    }

    pub fn ef_gossip_attestation(&mut self, ssz: &[u8], subnet: u64) -> Feedback {
        self.handle_attestation(ssz, subnet)
    }

    pub fn ef_gossip_aggregate_and_proof(&mut self, ssz: &[u8]) -> Feedback {
        self.handle_aggregate_and_proof(ssz)
    }

    pub fn ef_gossip_voluntary_exit(&mut self, ssz: &[u8]) -> Feedback {
        self.handle_voluntary_exit(ssz)
    }

    pub fn ef_gossip_proposer_slashing(&mut self, ssz: &[u8]) -> Feedback {
        self.handle_proposer_slashing(ssz)
    }

    pub fn ef_gossip_attester_slashing(&mut self, ssz: &[u8]) -> Feedback {
        self.handle_attester_slashing(ssz)
    }

    pub fn ef_gossip_bls_to_execution_change(&mut self, ssz: &[u8]) -> Feedback {
        self.handle_bls_to_execution_change(ssz)
    }

    pub fn ef_gossip_sync_contribution(&mut self, ssz: &[u8]) -> Feedback {
        self.handle_sync_contribution(ssz)
    }

    /// The gossip envelope path minus the EL round-trip and the spine.
    pub fn ef_gossip_execution_payload(&mut self, ssz: &[u8]) -> Feedback {
        match self.validate_execution_payload_envelope(ssz) {
            gossip::EnvelopeCheck::Ready { block_root, state_id } => {
                let rv = self.state.read_view(state_id);
                if !stf::envelope_withdrawals_match_expected(&rv, ssz) {
                    return Feedback::Accept;
                }
                if self.fork_choice.is_payload_verified(&block_root) {
                    return Feedback::Ignore;
                }
                self.fork_choice.mark_payload_verified(&block_root);
                self.recompute_head();
                Feedback::Accept
            }
            gossip::EnvelopeCheck::AwaitBlock(_) | gossip::EnvelopeCheck::Ignore => {
                Feedback::Ignore
            }
            gossip::EnvelopeCheck::Reject => Feedback::Reject(None),
        }
    }
}

impl Tile<SilverSpine> for BeaconStateTile {
    fn try_init(&mut self, _adapter: &mut SpineAdapter<SilverSpine>) -> bool {
        self.open_tcaches().expect("tcache wiring");
        true
    }

    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        if !self.initial_status_emitted {
            tracing::info!("producing initial status");
            self.publish_status(&mut adapter.producers);
            self.initial_status_emitted = true;
        }

        if !self.sync_target.is_syncing() {
            self.following_loop(adapter)
        } else {
            self.syncing_loop(adapter)
        }

        if self.fork_choice.take_head_moved() {
            self.try_detect_reorg(&mut adapter.producers);
            self.publish_status_on_head_change(&mut adapter.producers);
        }
    }
}

/// Parsed view over a SignedAggregateAndProof gossip message.

#[cfg(test)]
mod tests;
