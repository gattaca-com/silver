use std::{fmt::Debug, sync::Arc};

use flux::{
    spine::{FluxSpine, SpineAdapter, SpineProducers},
    tile::Tile,
};
use rustc_hash::FxHashMap;
use silver_beacon_state_data::{
    B256, BeaconBlockHeader, BeaconState, BeaconStateOwner, BeaconStateReader, BlobParameters,
    Checkpoint, Epoch, SLOTS_PER_EPOCH, Slot, SlotState, SpecConfig, StateId, Version,
};
use silver_common::{
    BeaconStateEvent, BlockSource, DataColumnsEvent, EngineResp, NewGossipMsg, ReplayBlock,
    RpcInbound, RpcResponse, RpcResponseInbound, SilverSpine, SyncUpdate, TRandomAccess, TRead,
    hex32,
    ssz_view::{MAX_ATTESTATIONS_ELECTRA, MAX_ATTESTING_INDICES, STATUS_V2_SIZE},
    ticker::{SlotTicker, TickEvent},
};
use silver_config::{PendingBounds, SyncingConfig};

use crate::{
    bls,
    fork_choice::{ExecutionStatus, FORK_CHOICE_NODES_HINT, ForkChoice, PayloadStatus},
    merkle, ssz_hash, stf,
    tile::{
        attestation_pool::AttestationPool, attestation_root_memo::AttestationRootMemo,
        fork_data_roots::ForkDataRoots, orphan_pool::PendingBlock, seen_aggregates::SeenAggregates,
        seen_validators::SeenValidators, shuffling_cache::ShufflingCache,
    },
    weak_subjectivity::{weak_subjectivity_period_fulu, weak_subjectivity_period_gloas},
};

mod attestation_pool;
// `pub` for the crate's `attestation_root_memo` criterion bench.
pub mod attestation_root_memo;
mod block;
mod finalize;
mod fork_choice;
mod fork_data_roots;
mod gossip;
mod orphan_pool;
mod seen_aggregates;
mod seen_validators;
mod shuffling_cache;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Syncing,
    Following,
}

impl Mode {
    fn is_following(self) -> bool {
        matches!(self, Self::Following)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Feedback {
    /// Contains the accepted block root.
    Accept(Option<B256>),
    Ignore,
    /// Carries the failed `block_root` (only) when the reject came from a
    /// post-`body_root`/STF path in block validation, so PM can blacklist
    /// the chain. All other reject paths (attestation, exit, slashing,
    /// pre-hash block fails) use `Reject(None)`.
    Reject(Option<B256>),
    /// The parent block is missing and must be requested.
    RequestParent {
        parent_root: B256,
        block_root: B256,
    },
    /// The block is valid but carries blob commitments whose data columns are
    /// not yet available.
    AwaitData(B256),
    /// Gloas block that builds on a parent whose execution-payload envelope
    /// hasn't been verified yet.
    AwaitParentPayload {
        parent_root: B256,
        block_root: B256,
    },
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
        }
    }
}

struct ParsedBlock {
    header: BeaconBlockHeader,
    block_root: B256,
    has_data_columns: bool,
    parent_state_id: StateId,
    is_gloas: bool,
    parent_payload_status: PayloadStatus,
}

pub struct BeaconStateTile {
    mode: Mode,
    ticker: SlotTicker,

    spec: Arc<SpecConfig>,

    fork_choice: ForkChoice,
    shuffling_cache: Box<ShufflingCache>,
    seen_attesters: SeenValidators,
    seen_aggregators: SeenValidators,
    seen_aggregates: SeenAggregates,
    attestation_pool: AttestationPool,
    attestation_root_memo: AttestationRootMemo,
    fork_data_roots: ForkDataRoots,

    /// Highest finalized slot PM has announced as a sync target — bounds the
    /// data-availability requirement while range sync back-fills.
    sync_finalized_slot: Slot,

    /// Canonical in-process state: finalized base + per-fork per-tier rings.
    /// Other tiles read via `state.reader()` (raw-ptr + seqlock).
    state: BeaconStateOwner,

    /// Index bundle of the canonical head's post-state.
    last_applied: StateId,
    last_applied_block_root: B256,

    initial_status_emitted: bool,
    cached_fork_digest: Option<(Epoch, [u8; 4])>,

    /// Reusable state-transition scratch buffers, threaded into
    /// `apply_block` / `process_slots`.
    stf_scratch: stf::StfScratch,
    /// Per-block buffer of votes emitted by `process_attestations` so the
    /// tile can fold them into the vote tracker after `apply_block` returns.
    attestation_votes_scratch: Vec<stf::AttestationVote>,
    /// Per-block buffer of validator indices actually slashed by a block's
    /// attester slashings; consumed in `publish_applied_block` to mark them
    /// equivocating in fork choice. Also reused transiently by the gossip
    /// attester-slashing path.
    slashed_indices_scratch: Vec<u32>,
    /// Pre-validation pass collects every BLS sig in the block here, then
    /// runs `verify_all` once before pass 2 mutates state.
    sig_batch: bls::SigBatch,
    /// Pending blocks - blocks we have received for which we do not have a
    /// parent block. Keyed by the parent block_hash.
    pending_blocks: FxHashMap<B256, Vec<(B256, PendingBlock)>>,
    /// Blocks fully prechecked but withheld from the STF until their data
    /// columns are available.
    dc_pending_blocks: FxHashMap<B256, PendingBlock>,
    /// Gloas: blocks withheld until their parent's execution-payload envelope
    /// is verified.
    payload_pending_blocks: FxHashMap<B256, Vec<PendingBlock>>,
    /// Block roots the storage tile has signalled data-available.
    dc_available: FxHashMap<B256, Slot>,
    /// Gloas: payload envelopes seen before their block entered fork choice.
    pending_envelopes: FxHashMap<B256, TRead>,
    /// Gloas: block roots a payload-present attestation referenced while their
    /// payload was still unverified (envelope missed on gossip).
    envelope_request_queue: Vec<B256>,
    /// Last by-root envelope request per block root:
    /// dedups repeated payload-present attestations and gates re-requests.
    envelope_requested: FxHashMap<B256, u64>,
    /// Resolved pending-buffer admission / eviction / fallback bounds.
    pending_bounds: PendingBounds,
    max_pending_per_parent: usize,

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
    /// publishes. Boots in `Mode::Syncing`; PM flips it to `Following` once
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
            // Boot in Syncing. PM's first `SyncUpdate::Following` flips us
            // once peer Status data confirms we're caught up.
            mode: Mode::Syncing,
            ticker,
            sync_finalized_slot: 0,
            spec,
            state: owner,
            fork_choice: ForkChoice::default(),
            shuffling_cache: ShufflingCache::with_capacity(val_cap),
            seen_attesters: SeenValidators::new(val_cap),
            seen_aggregators: SeenValidators::new(val_cap),
            seen_aggregates: SeenAggregates::new(),
            attestation_pool: AttestationPool::new(),
            attestation_root_memo: AttestationRootMemo::default(),
            fork_data_roots: ForkDataRoots::default(),
            last_applied: anchor,
            last_applied_block_root: [0u8; 32],
            initial_status_emitted: false,
            cached_fork_digest: None,
            stf_scratch: stf::StfScratch::new(val_cap),
            attestation_votes_scratch: Vec::with_capacity(
                MAX_ATTESTATIONS_ELECTRA * MAX_ATTESTING_INDICES,
            ),
            slashed_indices_scratch: Vec::with_capacity(MAX_ATTESTING_INDICES),
            sig_batch: bls::SigBatch::new(),
            pending_blocks: root_map(),
            dc_pending_blocks: root_map(),
            payload_pending_blocks: root_map(),
            dc_available: root_map(),
            pending_envelopes: root_map(),
            envelope_request_queue: Vec::with_capacity(FORK_CHOICE_NODES_HINT),
            envelope_requested: root_map(),
            pending_bounds: syncing.pending,
            max_pending_per_parent: (syncing.head_lag_threshold_slots * 2) as usize,
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
        self.state.set_head_block_root(block_root);

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

        let anchor_epoch = slot / SLOTS_PER_EPOCH;
        let view = self.state.read_view(anchor);
        self.shuffling_cache.ensure_window(&view, anchor_epoch);
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
        let bp =
            get_blob_parameters(epoch, &self.spec.blob_schedule, self.spec.default_blob_params());
        let d = compute_fork_digest(self.spec.fork_version_at(epoch), &gvr, Some(bp));
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

        // Advance on an unpublished child of the head — the published head is
        // resolved lock-free by readers and must not be mutated in place.
        // `process_slots` runs the per-slot loop and any epoch transitions
        // crossed; `process_epoch` rolls the child a private epoch (and
        // longtail) entry at each boundary, returning the committed ids for
        // the bundle assembly at `commit`.
        // Mandatory: `process_epoch` shifts `proposer_lookahead`, and
        // `self.last_applied` is a live fork-choice node that sibling blocks
        // build on and the proposer precheck reads — mutating its shared epoch
        // entry would leave that node with a next-epoch `proposer_lookahead`
        // shifted one epoch too far.
        let new_id;
        {
            let parent = self.last_applied;
            let (mut view, epoch, longtail) = self.state.apply_block_view(parent);
            let (epoch_idx, longtail_idx) = stf::process_slots(
                &self.spec,
                &mut view,
                epoch,
                longtail,
                parent,
                target_slot,
                &mut self.stf_scratch,
            );
            new_id = view.commit(epoch_idx, longtail_idx);
        }
        self.last_applied = new_id;
        self.state.publish_state_id(new_id);
        // Empty-slot epoch transitions can advance justified/finalized in the
        // head post-state; reflect that in fork choice before finalizing.
        self.lift_checkpoints();
        self.maybe_finalize();
        true
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
        self.fork_choice_tick();
        let floor = slot.saturating_sub(1);
        self.attestation_pool.prune_before(floor);
        self.seen_aggregates.prune_before(floor);
        self.attestation_root_memo.prune_before(floor);
        advanced
    }

    fn handle_engine_response(&mut self, eng_resp: EngineResp, _producers: &mut Producers) {
        match eng_resp {
            EngineResp::NewPayload(r) => {
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

    /// Validated-gossip entry: in Following mode acquire the buffer and
    /// dispatch; in Syncing mode drop it (PM drives sync).
    fn on_gossip(&mut self, m: NewGossipMsg, following: bool, producers: &mut Producers) {
        if following {
            self.handle_gossip(m.ssz, m, true, false, producers);
        } else {
            tracing::trace!(
                topic = ?m.topic,
                p2p_peer = m.stream_id.peer(),
                dc_pending_len = self.dc_pending_blocks.len(),
                head_slot = self.head_state_slot(),
                "gossip dropped: BeaconState in Syncing mode"
            );
        }
    }

    /// Mirror PM's latest sync target into `mode` (stale events collapse — only
    /// the latest wins). `mode` gates gossip / slot-tick processing.
    fn on_sync_update(&mut self, target: SyncUpdate) {
        let new_sync = match target {
            SyncUpdate::SyncingFinalized { target_epoch, .. } => {
                self.sync_finalized_slot =
                    self.sync_finalized_slot.max(target_epoch * SLOTS_PER_EPOCH);
                Mode::Syncing
            }
            SyncUpdate::SyncingHead { .. } => Mode::Syncing,
            SyncUpdate::Following => Mode::Following,
        };
        if new_sync != self.mode {
            tracing::info!(from = ?self.mode, to = ?new_sync, ?target, "BeaconState mode transition");
            self.mode = new_sync;
        }
    }

    fn on_rpc_inbound(&mut self, m: RpcInbound, producers: &mut Producers) {
        let RpcInbound::Response(RpcResponseInbound { application_id: _, stream_id, response }) = m
        else {
            return;
        };

        match response {
            RpcResponse::BeaconBlock { fork_digest: _, ssz } => {
                tracing::debug!(?stream_id, "received beacon block over rpc");
                self.handle_rpc_block(stream_id, ssz, false, producers);
            }
            RpcResponse::ExecutionPayloadEnvelope { fork_digest: _, ssz } => {
                let acquired = self.rpc_consumer.acquire(ssz);
                if let Ok((data, _)) = acquired.buffer() {
                    self.handle_execution_payload_envelope(
                        acquired.clone(),
                        data,
                        BlockSource::Rpc,
                        producers,
                    );
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
use silver_common::PayloadValidationStatus;

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
        match self.validate_execution_payload_envelope(ssz) {
            gossip::EnvelopeCheck::Ready { block_root, .. } => {
                self.fork_choice.mark_payload_verified(&block_root);
                self.fork_choice.on_payload_valid(&block_root);
                self.recompute_head();
                true
            }
            gossip::EnvelopeCheck::AwaitBlock(_) | gossip::EnvelopeCheck::Ignore => false,
        }
    }

    pub fn ef_apply_payload_attestation(&mut self, ssz: &[u8]) -> bool {
        matches!(self.handle_payload_attestation(ssz), Feedback::Accept(_))
    }

    pub fn ef_payload_verdict(
        &mut self,
        block_root: B256,
        status: PayloadValidationStatus,
        latest_valid_hash: B256,
    ) {
        self.on_payload_verdict(&block_root, &latest_valid_hash, status);
    }
}

impl Tile<SilverSpine> for BeaconStateTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        if !self.initial_status_emitted {
            tracing::info!("producing initial status");
            adapter.produce(self.status_event());
            self.initial_status_emitted = true;
        }

        let following = self.mode.is_following();
        if following {
            match self.ticker.tick() {
                TickEvent::SlotStart(slot) => {
                    // The head can move without a state advance (votes folded,
                    // boost expired), so emit status on either.
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
        }

        adapter.consume(|m: NewGossipMsg, producers| self.on_gossip(m, following, producers));
        self.gossip_consumer.free();

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
}

/// Parsed view over a SignedAggregateAndProof gossip message.
/// Spec gossip rule: `aggregate.slot + ATTESTATION_PROPAGATION_SLOT_RANGE >=
/// current_slot >= aggregate.slot`.
const ATTESTATION_PROPAGATION_SLOT_RANGE: u64 = 32;

/// By-root RPC requests carry no application correlation id — the peer manager
/// picks the peer/stream. `0` marks such unsolicited by-root requests.
const BY_ROOT_REQUEST_ID: u64 = 0;

/// Spec `compute_fork_digest` (Fulu EIP-7892). `blob_parameters` is `None`
/// pre-Fulu, `Some` from Fulu onward — the active BLOB_SCHEDULE entry.
fn compute_fork_digest(
    fork_version: Version,
    genesis_validators_root: &B256,
    blob_parameters: Option<BlobParameters>,
) -> [u8; 4] {
    let base = ssz_hash::hash_tree_root_fork_data(fork_version, genesis_validators_root);
    let Some(bp) = blob_parameters else {
        return base[..4].try_into().unwrap();
    };
    let mut input = [0u8; 16];
    input[..8].copy_from_slice(&bp.epoch.to_le_bytes());
    input[8..].copy_from_slice(&bp.max_blobs_per_block.to_le_bytes());
    let mix = merkle::sha256(&input);
    [base[0] ^ mix[0], base[1] ^ mix[1], base[2] ^ mix[2], base[3] ^ mix[3]]
}

/// Spec `get_blob_parameters`. `schedule` must be sorted ascending by epoch;
/// `default` is `BlobParameters(ELECTRA_FORK_EPOCH,
/// MAX_BLOBS_PER_BLOCK_ELECTRA)`.
pub(crate) fn get_blob_parameters(
    epoch: Epoch,
    schedule: &[BlobParameters],
    default: BlobParameters,
) -> BlobParameters {
    for entry in schedule.iter().rev() {
        if epoch >= entry.epoch {
            return *entry;
        }
    }
    default
}

#[cfg(test)]
mod tests;
