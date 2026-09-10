use std::{fmt::Debug, sync::Arc};

use flux::{
    spine::{FluxSpine, SpineAdapter, SpineProducers},
    tile::Tile,
};
use flux_profiler::timed;
use rustc_hash::FxHashMap;
use silver_beacon_state_data::{
    B256, BeaconState, BeaconStateOwner, BeaconStateReader, Checkpoint, Epoch, SLOTS_PER_EPOCH,
    Slot, SlotState, SpecConfig, StateId,
};
use silver_common::{
    BeaconStateEvent, BlockSource, DataColumnsEvent, DataKind, EngineResp, GossipTopic,
    NewGossipMsg, Origin, PayloadValidationStatus, ReplayBlock, RequestId, RpcInbound, RpcResponse,
    RpcResponseInbound, SilverSpine, SyncUpdate, TRandomAccess, TRead, hex32,
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
        held_blocks::HeldBlocks,
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
    Accept(Option<B256>),
    Ignore,
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
            Self::Accept(Some(r)) => write!(f, "Accept(Some(0x{}))", hex32(r)),
            Self::Accept(None) => f.write_str("Accept(None)"),
            Self::Ignore => f.write_str("Ignore"),
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

pub struct BeaconStateTile {
    sync_target: SyncUpdate,
    ticker: SlotTicker,

    spec: Arc<SpecConfig>,

    fork_choice: ForkChoice,
    shuffling_cache: Box<ShufflingCache>,
    seen_attesters: SeenValidators,
    seen_aggregators: SeenValidators,
    seen_aggregates: SeenAggregates,
    attestation_pool: AttestationPool,
    attestation_root_memo: AttestationRootMemo,
    vote_batch: Vec<NewGossipMsg>,
    vote_pending: Vec<(NewGossipMsg, gossip::PreparedVote)>,
    vote_sig_batch: bls::SigBatch,
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
    last_applied_block_root: B256,

    precomputed_epochs: PrecomputedEpochs,

    last_seen_head_root: B256,

    initial_status_emitted: bool,
    cached_fork_digest: Option<(Epoch, [u8; 4])>,

    stf_scratch: stf::StfScratch,
    /// Pre-validation pass collects every BLS sig in the block here, then
    /// runs `verify_all` once before pass 2 mutates state.
    sig_batch: bls::SigBatch,
    held: HeldBlocks,
    /// Gloas: payload envelopes seen before their block entered fork choice.
    pending_envelopes: FxHashMap<B256, TRead>,
    /// Resolved pending-buffer admission / eviction / fallback bounds.
    pending_bounds: PendingBounds,

    gossip_consumer: TRandomAccess,
    rpc_consumer: TRandomAccess,
    ea_consumer: TRandomAccess,
    replay_consumer: TRandomAccess,

    verify_weak_subjectivity: bool,
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
        gossip_consumer: TRandomAccess,
        rpc_consumer: TRandomAccess,
        incoming_engine_resp_consumer: TRandomAccess,
        replay_consumer: TRandomAccess,
        verify_weak_subjectivity: bool,
        state: BeaconState,
    ) -> Self {
        let mut owner = BeaconStateOwner::new(state);
        let val_cap = owner.state().validators.finalized().capacity();
        let anchor = owner.roll_fresh();
        let mut tile = Self {
            sync_target: SyncUpdate::default(),
            ticker,
            spec,
            state: owner,
            fork_choice: ForkChoice::default(),
            shuffling_cache: ShufflingCache::with_capacity(val_cap),
            seen_attesters: SeenValidators::new(val_cap),
            seen_aggregators: SeenValidators::new(val_cap),
            seen_aggregates: SeenAggregates::new(),
            attestation_pool: AttestationPool::new(),
            vote_batch: Vec::with_capacity(gossip::VOTE_BATCH_CAP),
            vote_pending: Vec::with_capacity(gossip::VOTE_BATCH_CAP),
            vote_sig_batch: bls::SigBatch::new(),
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
            last_applied_block_root: [0u8; 32],
            precomputed_epochs: PrecomputedEpochs::default(),
            last_seen_head_root: [0u8; 32],
            initial_status_emitted: false,
            cached_fork_digest: None,
            stf_scratch: stf::StfScratch::new(val_cap),
            sig_batch: bls::SigBatch::new(),
            held: HeldBlocks::new(&syncing.pending),
            pending_envelopes: root_map(),
            pending_bounds: syncing.pending,
            gossip_consumer,
            rpc_consumer,
            ea_consumer: incoming_engine_resp_consumer,
            replay_consumer,
            verify_weak_subjectivity,
        };
        tile.seed_anchor(anchor, val_cap);
        tracing::info!("created BeaconStateTile: head_state_slot is {}", tile.head_state_slot());
        tile
    }

    /// A read handle on the owned state, for wiring other tiles (lock-free
    /// seqlock reads). Valid across the anchor publish — same allocation.
    pub fn reader(&self) -> BeaconStateReader {
        self.state.reader()
    }

    pub fn head_block_root(&self) -> B256 {
        self.last_applied_block_root
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

    /// Seed fork choice from the freshly-anchored real state and publish the
    /// `anchor` — the second half of `new` for a non-stub state. (Caches are
    /// already sized for the real validator count in `new`.)
    fn seed_anchor(&mut self, anchor: StateId, validators_capacity: usize) {
        let slot = self.state.state().slot_states.finalized_view().slot_number();

        // Anchor block root. Compute on a local header copy so the state's
        // `latest_block_header.state_root` stays `[0;32]` — the first
        // post-bootstrap `process_slot` hashes that canonical state and a
        // patched value would shift the result.
        let (block_root, execution_block_hash) = {
            let rv = self.state.read_view(anchor);
            let state_root = ssz_hash::hash_tree_root_state(&rv);
            let mut header = rv.slot.state().latest_block_header;
            if header.state_root == [0u8; 32] {
                header.state_root = state_root;
            }
            (
                ssz_hash::hash_tree_root_block_header(&header),
                rv.slot.state().latest_execution_payload_header.block_hash,
            )
        };

        let trusted = Checkpoint { epoch: slot.div_ceil(SLOTS_PER_EPOCH), root: block_root };
        self.last_applied_block_root = block_root;
        self.last_seen_head_root = block_root;

        let anchor_is_gloas = self.state.read_view(anchor).is_gloas();
        self.fork_choice = ForkChoice::init(
            trusted,
            trusted,
            slot,
            block_root,
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

    fn status_payload(&mut self, head_root: B256, head_idx: Option<usize>) -> [u8; STATUS_V2_SIZE] {
        let fork_digest = self.fork_digest();

        let (slot, mut finalized) = match head_idx {
            Some(idx) => {
                let n = self.fork_choice.node(idx);
                (n.slot, n.checkpoints.finalized)
            }
            None => (
                self.slot_state_at(self.last_applied).latest_block_header.slot,
                self.head_finalized_checkpoint(),
            ),
        };

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

    fn status_event(&mut self) -> BeaconStateEvent {
        let head_root = self.fork_choice.find_head();
        let head_idx = self.fork_choice.find_node_idx(&head_root);
        let head_optimistic = head_idx.is_none_or(|idx| {
            self.fork_choice.node(idx).execution_status != ExecutionStatus::Valid
        });

        BeaconStateEvent::Status {
            ssz: self.status_payload(head_root, head_idx),
            latest_block_slot: self.last_applied_block_slot(),
            wall_slot: self.ticker.current_slot(),
            head_optimistic,
            enr_fork_id: self.enr_fork_id(),
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

        let new_id = self.state_at(self.last_applied_block_root, self.last_applied, target_slot);
        self.last_applied = new_id;
        self.state.publish_state_id(new_id);
        // Empty-slot epoch transitions can advance justified/finalized in the
        // head post-state; reflect that in fork choice before finalizing.
        self.lift_checkpoints();
        self.maybe_finalize();
        true
    }

    fn state_at(&mut self, root: B256, from: StateId, slot: Slot) -> StateId {
        let from = self.epoch_start_state(root, from, slot);
        if self.slot_state_at(from).slot == slot {
            return from;
        }
        Self::process_slots_advance(&mut self.state, &self.spec, &mut self.stf_scratch, from, slot)
    }

    /// `from` advanced to the first slot of `slot`'s epoch when `slot` is in a
    /// later one, else `from`.
    #[timed]
    fn epoch_start_state(&mut self, root: B256, from: StateId, slot: Slot) -> StateId {
        let from_slot = self.slot_state_at(from).slot;
        let (state, spec, scratch) = (&mut self.state, &self.spec, &mut self.stf_scratch);
        let epoch = slot / SLOTS_PER_EPOCH;
        self.precomputed_epochs.get_or_advance(root, from, from_slot, epoch, |from, to| {
            Self::process_slots_advance(state, spec, scratch, from, to)
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
                // A staged block is not in fork choice yet, so its INVALID must
                // be caught here or it imports optimistic once its columns arrive.
                if r.status == PayloadValidationStatus::Invalid &&
                    let Some(source) = self.held.reject_staged(&r.block_root)
                {
                    tracing::warn!(
                        block = hex32(&r.block_root),
                        "EL rejected a staged block; dropped"
                    );
                    producers.produce(BeaconStateEvent::BlockRejected {
                        block_root: r.block_root,
                        source,
                    });
                    return;
                }
                self.on_payload_verdict(&r.block_root, &r.latest_valid_hash, r.status);
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
            // Payload-body reconstruction is unneeded: the store persists and
            // serves full SignedBeaconBlocks, so there is nothing to rebuild
            // from EL bodies.
            EngineResp::GetPayloadBodies(_) => {}
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
            Self::reject_local_gossip(&m, producers);
        });
        self.gossip_consumer.free();
    }

    fn following_loop(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        self.consume_shared(adapter);

        match self.ticker.tick() {
            TickEvent::SlotStart(slot) => {
                let prev_head = self.fork_choice.find_head();
                let advanced = self.slot_tick(slot);
                if advanced || self.fork_choice.find_head() != prev_head {
                    adapter.produce(self.status_event());
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
        self.gossip_consumer.free();
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
        self.rpc_consumer.free();

        adapter.consume(|m: DataColumnsEvent, producers| {
            if let DataColumnsEvent::Available { block_root, slot } = m {
                self.handle_data_columns_available(block_root, slot, producers);
            }
        });

        adapter.consume(|eng_resp: EngineResp, producers| {
            self.handle_engine_response(eng_resp, producers);
        });
        self.ea_consumer.free();

        adapter.consume(|m: ReplayBlock, producers| self.on_replay(m, producers));
        self.replay_consumer.free();
    }

    fn on_sync_update(&mut self, target: SyncUpdate) {
        if target.is_following() != self.sync_target.is_following() {
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
                let acquired = self.rpc_consumer.acquire(ssz);
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
                        seq = acquired.read.seq(),
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
                producers.produce(self.status_event());
            }
        }
    }
}

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
            Feedback::Accept(r) => r,
            _ => None,
        }
    }

    pub fn ef_apply_attestation(&mut self, ssz: &[u8]) {
        self.apply_attestation(ssz);
        self.recompute_head();
    }

    pub fn ef_apply_attester_slashing(&mut self, ssz: &[u8]) {
        if matches!(self.handle_attester_slashing(ssz), Feedback::Accept(_)) {
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
    /// which is what production relays on. The import still runs afterwards,
    /// as in production, so a repeat is seen as already known.
    pub fn ef_gossip_block(&mut self, ssz: &[u8]) -> Feedback {
        match self.parse_and_verify_block(ssz, false) {
            Ok(parsed) => {
                let block_root = parsed.block_root;
                self.apply_and_import(parsed, ssz);
                Feedback::Accept(Some(block_root))
            }
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
                    return Feedback::Accept(None);
                }
                if self.fork_choice.is_payload_verified(&block_root) {
                    return Feedback::Ignore;
                }
                self.fork_choice.mark_payload_verified(&block_root);
                self.recompute_head();
                Feedback::Accept(Some(block_root))
            }
            gossip::EnvelopeCheck::AwaitBlock(_) | gossip::EnvelopeCheck::Ignore => {
                Feedback::Ignore
            }
            gossip::EnvelopeCheck::Reject => Feedback::Reject(None),
        }
    }
}

impl Tile<SilverSpine> for BeaconStateTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        if !self.initial_status_emitted {
            tracing::info!("producing initial status");
            adapter.produce(self.status_event());
            self.initial_status_emitted = true;
        }

        if self.sync_target.is_following() {
            self.following_loop(adapter)
        } else {
            self.syncing_loop(adapter)
        }

        if self.fork_choice.take_head_moved() {
            self.try_detect_reorg(&mut adapter.producers);
        }
    }
}

/// Parsed view over a SignedAggregateAndProof gossip message.

#[cfg(test)]
mod tests;
