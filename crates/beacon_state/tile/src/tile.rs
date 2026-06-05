use flux::{
    spine::{FluxSpine, SpineAdapter, SpineProducers},
    tile::Tile,
    utils::ArrayVec,
};
use rustc_hash::FxHashMap;
use silver_beacon_state_data::{
    B256, BeaconBlockHeader, BeaconState, BeaconStateOwner, BlobParameters, Checkpoint,
    EPOCHS_PER_HISTORICAL_VECTOR, EPOCHS_RING_N, Epoch, EpochId, LONGTAILS_RING_N, LongtailId,
    MIN_SEED_LOOKAHEAD, SLOTS_PER_EPOCH, Slot, SlotState, SpecConfig, StateId, StateReadView,
    Version, decode_checkpoint_pubkeys, randao_mix_at_epoch,
};
use silver_common::{
    BeaconStateEvent, BlockSource, DataColumnsAvailable, EngineFcuReq, EngineNewPayloadReq,
    EngineReq, EngineResp, GossipTopic, NewGossipMsg, P2pStreamId, PayloadValidationStatus,
    PeerEvent, RpcInbound, RpcResponse, RpcResponseInbound, RpcSeverity, SilverSpine, SyncUpdate,
    TCacheRead, TRandomAccess, TRead, hex32,
    ssz_view::{
        self, AttesterSlashingView, MAX_ATTESTATIONS_ELECTRA, MAX_ATTESTING_INDICES,
        PROPOSER_SLASHING_SIZE, ProposerSlashingView, SIGNED_BLS_CHANGE_SIZE,
        SIGNED_VOLUNTARY_EXIT_SIZE, SINGLE_ATT_SIZE, STATUS_V2_SIZE, SignedAggregateAndProofView,
        SignedBeaconBlockView, SignedBlsToExecutionChangeView, SignedVoluntaryExitView,
        SingleAttestationView,
    },
    ticker::{SlotTicker, TickEvent},
};

use crate::{
    bls,
    error::PrecheckError,
    fork_choice::{BlockImport, ForkChoice, MAX_FORK_CHOICE_NODES, VoteTracker, compute_deltas},
    shuffling::{self, DOMAIN_BEACON_ATTESTER},
    ssz_hash, state_transition, validate,
};

/// Survivor set re-anchored at finalization: every fork-choice node's bundle
/// plus the (possibly node-less) slot-advanced head.
const MAX_SURVIVORS: usize = MAX_FORK_CHOICE_NODES + 1;

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
    RequestParent(B256),
    /// The block is valid but carries blob commitments whose data columns are
    /// not yet available.
    AwaitData(B256),
}

// Manual Debug to hex-encode the `B256` roots (`B256 = [u8; 32]`, whose
// derived Debug prints a raw byte array).
impl core::fmt::Debug for Feedback {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Accept(Some(r)) => write!(f, "Accept(Some(0x{}))", hex32(r)),
            Self::Accept(None) => f.write_str("Accept(None)"),
            Self::Ignore => f.write_str("Ignore"),
            Self::Reject(Some(r)) => write!(f, "Reject(Some(0x{}))", hex32(r)),
            Self::Reject(None) => f.write_str("Reject(None)"),
            Self::RequestParent(r) => write!(f, "RequestParent(0x{})", hex32(r)),
            Self::AwaitData(r) => write!(f, "AwaitData(0x{})", hex32(r)),
        }
    }
}

struct ParsedBlock {
    block_slot: Slot,
    proposer_index: u64,
    parent_root: B256,
    state_root: B256,
    body_root: B256,
    block_root: B256,
    /// `true` iff the block carries blob commitments, so its data columns must
    /// be available (`DataColumnsAvailable`) before it can enter fork choice.
    has_data_columns: bool,
    /// Index bundle of the parent block's post-state.
    parent_state_id: StateId,
}

// Per-fork attester shuffling cache, keyed by `(epoch, seed-epoch randao
// mix)`. Same `(epoch, mix)` ⇒ same active set ⇒ same shuffle output
// regardless of how many mid-epoch CoWs the fork went through; different
// pre-(epoch-2) fork ⇒ different mix ⇒ no false hit. 4 entries covers
// current+prev for two simultaneous forks; LRU-by-epoch past that.
const MAX_SHUFFLING_CACHE: usize = 4;

pub struct ShufflingCache {
    pub entries: [ShufflingEntry; MAX_SHUFFLING_CACHE],
}

impl ShufflingCache {
    pub fn with_capacity(capacity: usize) -> Box<Self> {
        Box::new(Self {
            entries: std::array::from_fn(|_| ShufflingEntry {
                epoch: 0,
                mix: [0u8; 32],
                status: 0,
                shuffled_indices: Vec::with_capacity(capacity),
            }),
        })
    }
}

pub struct ShufflingEntry {
    pub epoch: Epoch,
    pub mix: B256,
    /// 0=empty, 1=valid
    pub status: u64,
    pub shuffled_indices: Vec<u32>,
}

enum PendingBlock {
    Gossip(NewGossipMsg),
    Rpc(P2pStreamId, TCacheRead),
}

pub struct BeaconStateTile {
    mode: Mode,
    ticker: SlotTicker,

    /// Highest finalized slot PM has announced as a sync target — bounds the
    /// data-availability requirement while range sync back-fills.
    sync_finalized_slot: Slot,

    spec: SpecConfig,

    /// Canonical in-process state: finalized base + per-fork per-tier rings.
    /// Other tiles read via `state.reader()` (raw-ptr + seqlock).
    state: BeaconStateOwner,

    fork_choice: ForkChoice,
    vote_tracker: Box<VoteTracker>,
    shuffling_cache: Box<ShufflingCache>,

    /// Index bundle of the canonical head's post-state.
    last_applied: StateId,
    last_applied_block_root: B256,

    initial_status_emitted: bool,
    cached_fork_digest: Option<(Epoch, [u8; 4])>,
    /// Operator-configured fork digest. Used in lieu of a computed digest
    /// while the state is uninitialized (no checkpoint, pre-sync → zero
    /// `gvr`), so silver advertises the right digest instead of one derived
    /// from an all-zero genesis-validators-root.
    configured_fork_digest: Option<[u8; 4]>,

    /// Reusable state-transition scratch buffers, threaded into
    /// `apply_block` / `process_slots`.
    stf_scratch: state_transition::StfScratch,
    /// Per-block buffer of votes emitted by `process_attestations` so the
    /// tile can fold them into the vote tracker after `apply_block` returns.
    attestation_votes_scratch: Vec<state_transition::AttestationVote>,
    /// Effective-balance column from the previous `recompute_head`, kept so
    /// `compute_deltas` can net per-validator balance changes onto LMD weights
    /// (not just vote-root changes). Indexed by validator; new validators read
    /// as 0 (no prior weight).
    prev_eff_balances: Vec<u64>,
    /// Pre-validation pass collects every BLS sig in the block here, then
    /// runs `verify_all` once before pass 2 mutates state.
    sig_batch: bls::SigBatch,
    /// Pending blocks - blocks we have received for which we do not have a
    /// parent block. Keyed by the parent block_hash.
    pending_blocks: FxHashMap<B256, Vec<PendingBlock>>,
    /// Blocks fully prechecked but withheld from the STF until their data
    /// columns are available.
    dc_pending_blocks: FxHashMap<B256, PendingBlock>,
    /// Block roots the storage tile has signalled data-available.
    dc_available: FxHashMap<B256, Slot>,

    gossip_consumer: TRandomAccess,
    rpc_consumer: TRandomAccess,
    incoming_engine_resp_consumer: TRandomAccess,
}

type Producers = <SilverSpine as FluxSpine>::Producers;

impl BeaconStateTile {
    /// If `checkpoint_state` is non-empty, bootstraps immediately; otherwise
    /// starts inert in `Mode::Syncing` (call `bootstrap` before the loop).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ticker: SlotTicker,
        spec: SpecConfig,
        mut state: BeaconStateOwner,
        gossip_consumer: TRandomAccess,
        rpc_consumer: TRandomAccess,
        incoming_engine_resp_consumer: TRandomAccess,
        checkpoint_state: &[u8],
        decompressed_pubkeys: &[u8],
    ) -> Self {
        let val_cap = state.state().validators.finalized().capacity();
        // Pre-bootstrap placeholder head: honest per-tier entries rolled on
        // the (still empty) owner — a bundle never exists before its entries.
        // `bootstrap` installs the real anchor before any STF use.
        let last_applied = state.roll_fresh();
        let mut tile = Self {
            // Boot in Syncing. PM's first `SyncUpdate::Following` flips us
            // once peer Status data confirms we're caught up.
            mode: Mode::Syncing,
            ticker,
            sync_finalized_slot: 0,
            spec,
            state,
            fork_choice: ForkChoice::default(),
            vote_tracker: VoteTracker::with_capacity(val_cap),
            shuffling_cache: ShufflingCache::with_capacity(val_cap),
            last_applied,
            last_applied_block_root: [0u8; 32],
            initial_status_emitted: false,
            cached_fork_digest: None,
            configured_fork_digest: None,
            stf_scratch: state_transition::StfScratch::new(val_cap),
            attestation_votes_scratch: Vec::with_capacity(
                MAX_ATTESTATIONS_ELECTRA * MAX_ATTESTING_INDICES,
            ),
            prev_eff_balances: Vec::with_capacity(val_cap),
            sig_batch: bls::SigBatch::new(),
            pending_blocks: FxHashMap::with_capacity_and_hasher(
                MAX_FORK_CHOICE_NODES,
                Default::default(),
            ),
            dc_pending_blocks: FxHashMap::with_capacity_and_hasher(
                MAX_FORK_CHOICE_NODES,
                Default::default(),
            ),
            dc_available: FxHashMap::with_capacity_and_hasher(
                MAX_FORK_CHOICE_NODES,
                Default::default(),
            ),
            gossip_consumer,
            rpc_consumer,
            incoming_engine_resp_consumer,
        };

        if !checkpoint_state.is_empty() {
            tile.bootstrap(checkpoint_state, decompressed_pubkeys);
        }
        tile
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

    pub fn try_apply_block(&mut self, data: &[u8]) -> Feedback {
        self.apply_block_impl(data, false, |_block_root| {})
    }

    /// SSZ `hash_tree_root` of the most-recently-applied block's full
    /// BeaconState. Used by integration tests to cross-check tile-applied
    /// STF output against EF post-state vectors.
    pub fn head_state_root(&mut self) -> B256 {
        let rv = self.state.read_view(self.last_applied);
        ssz_hash::hash_tree_root_state(&rv, &mut self.stf_scratch.state_hash)
    }

    /// Load a checkpoint-state SSZ blob: decompose it into the finalized
    /// base, anchor a genesis slot delta on top (empty edits, full slot
    /// scalars seeded from the base), and seed fork choice with the trusted
    /// anchor checkpoint. `decompressed_pubkeys` is the optional sidecar of
    /// pre-decompressed validator pubkeys; on any decode/verify failure we
    /// fall back to decompressing from the SSZ itself.
    pub fn bootstrap(&mut self, ssz: &[u8], decompressed_pubkeys: &[u8]) {
        let pubkeys = (!decompressed_pubkeys.is_empty())
            .then(|| decode_checkpoint_pubkeys(decompressed_pubkeys))
            .transpose()
            .unwrap_or_else(|e| {
                tracing::warn!(?e, "checkpoint pubkey sidecar decode failed; decompressing");
                None
            });

        let anchor;
        let slot;
        {
            let mut guard = self.state.write();
            let bs: &mut BeaconState = &mut guard;
            // Replace the pre-bootstrap stub under the write window: readers
            // spin across the swap, the old stub drops inside it.
            let decoded = match pubkeys.as_deref() {
                Some(pk) => BeaconState::decompose(ssz, &self.spec, Some(pk)).or_else(|e| {
                    tracing::warn!(%e, "checkpoint pubkey sidecar rejected; decompressing");
                    BeaconState::decompose(ssz, &self.spec, None)
                }),
                None => BeaconState::decompose(ssz, &self.spec, None),
            };
            *bs = decoded.unwrap_or_else(|e| panic!("bootstrap: decompose failed: {e}"));
            slot = bs.slot_states.finalized_view().slot_number();

            // Anchor an empty per-fork delta on the freshly decoded base
            // (epoch/longtail stay lazy; `roll_fresh` anchors the slot fork's
            // full scalars at the base).
            anchor = bs.roll_fresh();
        }

        // Fresh state is correct here — nothing predates the anchor.
        let cap = self.state.state().validators.finalized().capacity();
        self.vote_tracker = VoteTracker::with_capacity(cap);
        self.shuffling_cache = ShufflingCache::with_capacity(cap);

        // Anchor block root. Compute on a local header copy so the state's
        // `latest_block_header.state_root` stays `[0;32]` — the first
        // post-bootstrap `process_slot` hashes that canonical state and a
        // patched value would shift the result.
        let (block_root, anchor_state_root) = {
            let rv = self.state.read_view(anchor);
            let state_root = ssz_hash::hash_tree_root_state(&rv, &mut self.stf_scratch.state_hash);
            let mut header = rv.slot.state().latest_block_header;
            if header.state_root == [0u8; 32] {
                header.state_root = state_root;
            }
            (ssz_hash::hash_tree_root_block_header(&header), state_root)
        };

        let trusted = Checkpoint { epoch: slot.div_ceil(SLOTS_PER_EPOCH), root: block_root };
        self.last_applied = anchor;
        self.last_applied_block_root = block_root;
        self.fork_choice =
            ForkChoice::init(trusted, trusted, slot, block_root, anchor_state_root, anchor);
        self.state.publish_state_id(anchor);
    }

    /// Index bundle of fork-choice's canonical tip. For gossip-object
    /// validation per spec ("the head state").
    fn canonical_state_id(&self) -> StateId {
        let head_root = self.fork_choice.find_head();
        let idx = self
            .fork_choice
            .find_node_idx(&head_root)
            .expect("find_head returns a node-resident root");
        self.fork_choice.node(idx).state_id
    }

    /// Seed-epoch randao mix that keys an epoch's attester shuffling (the
    /// single `randao_mixes[]` slot driving `get_seed(_, epoch, ATTESTER)`).
    fn shuffling_mix(view: &StateReadView, epoch: Epoch) -> B256 {
        let mix_epoch = epoch + EPOCHS_PER_HISTORICAL_VECTOR as u64 - MIN_SEED_LOOKAHEAD - 1;
        randao_mix_at_epoch(&view.epoch, &view.slot, mix_epoch)
    }

    /// Compute and cache the attester shuffling for `epoch` against the post-
    /// state named by `state_id`. No-op if already cached. Maintain the
    /// 2-epoch window: attestations with `target_epoch ∈ {epoch, epoch - 1}`
    /// resolve their committee against both.
    fn ensure_shuffling_window(&mut self, epoch: Epoch, state_id: StateId) {
        self.ensure_shuffling(epoch, state_id);
        if epoch > 0 {
            self.ensure_shuffling(epoch - 1, state_id);
        }
    }

    fn ensure_shuffling(&mut self, epoch: Epoch, state_id: StateId) {
        let mix = {
            let view = self.state.read_view(state_id);
            Self::shuffling_mix(&view, epoch)
        };
        if self
            .shuffling_cache
            .entries
            .iter()
            .any(|e| e.status == 1 && e.epoch == epoch && e.mix == mix)
        {
            return;
        }

        self.stf_scratch.active.clear();
        {
            let view = self.state.read_view(state_id);
            shuffling::get_active_validator_indices_into(
                &view.validators,
                epoch,
                &mut self.stf_scratch.active,
            );
        }
        let seed = shuffling::get_seed(&mix, epoch, DOMAIN_BEACON_ATTESTER);
        shuffling::shuffle_list(&mut self.stf_scratch.active, &seed);

        let slot = self.find_shuffling_slot();
        let entry = &mut self.shuffling_cache.entries[slot];
        entry.epoch = epoch;
        entry.mix = mix;
        entry.status = 1;
        entry.shuffled_indices.clear();
        for &idx in self.stf_scratch.active.iter() {
            entry.shuffled_indices.push(idx);
        }
    }

    /// Empty slot first, otherwise lowest-epoch among live entries. Mix is
    /// frozen data not tied to any arena slot, so there's no "dead gen"
    /// staleness to check — entries simply become uninteresting once the
    /// chain advances past their epoch.
    fn find_shuffling_slot(&self) -> usize {
        let mut best_live = 0;
        let mut best_live_epoch = u64::MAX;
        for (i, entry) in self.shuffling_cache.entries.iter().enumerate() {
            if entry.status == 0 {
                return i;
            }
            if entry.epoch < best_live_epoch {
                best_live_epoch = entry.epoch;
                best_live = i;
            }
        }
        best_live
    }

    fn get_shuffling(cache: &ShufflingCache, epoch: Epoch, mix: B256) -> Option<&ShufflingEntry> {
        cache.entries.iter().find(|e| e.status == 1 && e.epoch == epoch && e.mix == mix)
    }

    fn build_shuffling_ref<'a>(
        cache: &'a ShufflingCache,
        state: &mut BeaconStateOwner,
        state_id: StateId,
        block_epoch: Epoch,
    ) -> state_transition::ShufflingRef<'a> {
        let prev_epoch = block_epoch.saturating_sub(1);
        let (curr_mix, prev_mix) = {
            let view = state.read_view(state_id);
            (Self::shuffling_mix(&view, block_epoch), Self::shuffling_mix(&view, prev_epoch))
        };
        let curr = Self::get_shuffling(cache, block_epoch, curr_mix)
            .expect("ensure_shuffling_window cached current epoch");
        let prev = Self::get_shuffling(cache, prev_epoch, prev_mix)
            .expect("ensure_shuffling_window cached previous epoch");
        state_transition::ShufflingRef {
            curr_epoch: block_epoch,
            curr_shuffled: curr.shuffled_indices.as_slice(),
            curr_committees_per_slot: shuffling::committees_per_slot(curr.shuffled_indices.len()),
            prev_epoch,
            prev_shuffled: prev.shuffled_indices.as_slice(),
            prev_committees_per_slot: shuffling::committees_per_slot(prev.shuffled_indices.len()),
        }
    }

    /// Spec `compute_fork_digest` (Fulu EIP-7892). Cached per epoch: inputs
    /// (Fulu fork version, gvr, active blob_parameters) only change at epoch
    /// boundaries — schedule entries are epoch-aligned and `gvr` is frozen.
    /// Reorg within an epoch keeps the cache valid.
    fn fork_digest(&mut self) -> [u8; 4] {
        let epoch = self.head_state_slot() / SLOTS_PER_EPOCH;
        if let Some((cached_epoch, d)) = self.cached_fork_digest &&
            cached_epoch == epoch
        {
            return d;
        }

        let gvr = self.state.state().immutable.genesis_validators_root;
        // Uninitialized state (no checkpoint, pre-sync): a digest computed
        // from a zero gvr is bogus. Fall back to the operator-configured
        // digest until a real state lands. Not cached — recompute once gvr
        // is set so fork transitions still take effect.
        if gvr == [0u8; 32] &&
            let Some(d) = self.configured_fork_digest
        {
            return d;
        }
        let bp =
            get_blob_parameters(epoch, &self.spec.blob_schedule, self.spec.default_blob_params());
        let d = compute_fork_digest(self.spec.fulu_fork_version, &gvr, Some(bp));
        self.cached_fork_digest = Some((epoch, d));
        d
    }

    /// Set the operator-configured fork digest (bootstrap value used while the
    /// state is uninitialized). Call once after construction.
    pub fn set_configured_fork_digest(&mut self, digest: [u8; 4]) {
        self.configured_fork_digest = Some(digest);
    }

    fn status_payload(&mut self) -> [u8; STATUS_V2_SIZE] {
        let fork_digest = self.fork_digest();

        let head_root = self.fork_choice.find_head();
        let (slot, mut finalized) = match self.fork_choice.find_node_idx(&head_root) {
            Some(idx) => {
                let n = self.fork_choice.node(idx);
                (n.slot, n.finalized_checkpoint)
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
    /// empty slots. Sync's request watermark keys off this, not the fork-choice
    /// head in the Status SSZ (which can lag the imported tip).
    fn last_applied_block_slot(&self) -> Slot {
        self.slot_state_at(self.last_applied).latest_block_header.slot
    }

    fn status_event(&mut self) -> BeaconStateEvent {
        BeaconStateEvent::Status {
            ssz: self.status_payload(),
            latest_block_slot: self.last_applied_block_slot(),
            wall_slot: self.ticker.current_slot(),
        }
    }

    /// Post-import emission: PersistBlock (for storage) + Status (head and
    /// possibly finalized just moved). Called after `handle_block` returns
    /// `GossipFeedback::Accept` from gossip or RPC range/root response paths.
    fn apply_block(
        &mut self,
        data: &[u8],
        data_tcache: TRead,
        source: BlockSource,
        producers: &mut Producers,
    ) -> Feedback {
        let block_slot = SignedBeaconBlockView::slot(data);
        if block_slot < (self.head_finalized_checkpoint().epoch * SLOTS_PER_EPOCH) {
            // Pre-finalization block - either backfill or irrelevant.
            return Feedback::Ignore;
        }
        let f = self.apply_block_impl(data, true, |root| {
            producers.produce(EngineReq::NewPayload(EngineNewPayloadReq {
                data: *data_tcache,
                block_root: root,
                block_source: source,
            }));
        });

        if let Feedback::Reject(Some(block_root)) = f {
            producers.produce(BeaconStateEvent::BlockRejected { block_root, source });
        }
        tracing::info!(
            ?source,
            head_slot = self.head_state_slot(),
            block_slot,
            "applied block: {:?}",
            f
        );
        if !matches!(f, Feedback::Accept(_)) {
            return f;
        }

        producers.produce(BeaconStateEvent::PersistBlock { ssz: *data_tcache, source });

        let (head_root, head, safe, fin) = self.fork_choice.fcu_execution_hashes();
        producers.produce(EngineReq::Fcu(EngineFcuReq {
            block_root: head_root,
            head_block_hash: head,
            safe_block_hash: safe,
            finalized_block_hash: fin,
        }));

        f
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
            let (epoch_idx, longtail_idx) = state_transition::process_slots(
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

    /// Promote the fork-choice-finalized node's `StateId` tiers into the
    /// per-tier finalized bases, re-base every surviving descendant delta
    /// against the new base, and refresh the survivors' (and the published
    /// head's) bundles with the re-anchored ids. No-op until finality
    /// advances past the current base (fork-choice node 0).
    ///
    /// The epoch state-transition itself runs inside `process_slots`; this is
    /// purely the finalization / promotion step.
    fn maybe_finalize(&mut self) {
        // Lift fork-choice finality from the head post-state (monotone, only
        // to a block we actually hold).
        let hf = self.head_finalized_checkpoint();
        if hf.epoch > self.fork_choice.finalized_checkpoint.epoch &&
            self.fork_choice.find_node_idx(&hf.root).is_some()
        {
            self.fork_choice.finalized_checkpoint = hf;
        }

        let fin_root = self.fork_choice.finalized_checkpoint.root;
        let Some(fin_idx) = self.fork_choice.find_node_idx(&fin_root) else {
            return;
        };
        if fin_idx == 0 {
            return; // already the base
        }
        let promoted = self.fork_choice.node(fin_idx).state_id;

        // Drop non-descendants of the finalized block; the survivors (node 0
        // is now the finalized block) are exactly the deltas to re-base.
        self.fork_choice.prune();
        let mut survivors: ArrayVec<StateId, MAX_SURVIVORS> = ArrayVec::new();
        survivors.extend(self.fork_choice.live_state_ids());

        // `on_slot_start` advances the head onto a fresh bundle that is never
        // registered as a fork-choice node. It is still a live descendant of
        // the finalized base, so it must be re-based too — otherwise its
        // `base_count` goes stale and the next `apply_block_view` on it (or a
        // roll from it) trips the base-mirror assert. `MAX_SURVIVORS` covers
        // every node plus this extra head bundle.
        let head_pos = match survivors.iter().position(|&s| s == self.last_applied) {
            Some(p) => p,
            None => {
                survivors.push(self.last_applied);
                survivors.len() - 1
            }
        };

        // Unique epoch / longtail ring entries referenced by survivors, so
        // each cumulative log is re-based exactly once when siblings share it.
        let mut epoch_idxs: ArrayVec<EpochId, EPOCHS_RING_N> = ArrayVec::new();
        let mut longtail_idxs: ArrayVec<LongtailId, LONGTAILS_RING_N> = ArrayVec::new();
        for sid in survivors.iter() {
            if let Some(e) = sid.epoch_idx &&
                !epoch_idxs.as_slice().contains(&e)
            {
                epoch_idxs.push(e);
            }
            if let Some(l) = sid.longtail_idx &&
                !longtail_idxs.as_slice().contains(&l)
            {
                longtail_idxs.push(l);
            }
        }

        self.promote_and_rebase(
            promoted,
            survivors.as_mut_slice(),
            head_pos,
            epoch_idxs.as_slice(),
            longtail_idxs.as_slice(),
        );

        // Hand the re-anchored bundles back to their holders: fork-choice
        // nodes 1:1 (prune kept node order), then the head.
        let node_count = self.fork_choice.nodes.len();
        for (node, &sid) in
            self.fork_choice.nodes.iter_mut().zip(&survivors.as_slice()[..node_count])
        {
            node.state_id = sid;
        }
        self.last_applied = survivors.as_slice()[head_pos];

        let fin_slot = self.fork_choice.finalized_checkpoint.epoch * SLOTS_PER_EPOCH;
        self.clear_pending_blocks(fin_slot);
    }

    fn clear_pending_blocks(&mut self, finalized_slot: u64) {
        tracing::debug!(
            pending_blocks = self.pending_blocks.len(),
            finalized_slot,
            "clear pending blocks at finalization"
        );
        let (gossip_consumer, rpc_consumer) = (&mut self.gossip_consumer, &mut self.rpc_consumer);
        self.pending_blocks.retain(|_, msgs| {
            msgs.iter().all(|msg| {
                pending_block_outlives(gossip_consumer, rpc_consumer, msg, finalized_slot)
            })
        });

        self.dc_pending_blocks.retain(|_, msg| {
            pending_block_outlives(gossip_consumer, rpc_consumer, msg, finalized_slot)
        });
        self.dc_available.retain(|_, slot| *slot > finalized_slot);
    }

    /// Rewrites each survivor bundle's per-tier ids to the re-anchored ones,
    /// then stages `survivors[head_pos]` as the published bundle — it lands
    /// with the guard drop, in the same seqlock window as the tier rewrites,
    /// so readers never observe a bundle whose ids were already re-anchored.
    fn promote_and_rebase(
        &mut self,
        promoted: StateId,
        survivors: &mut [StateId],
        head_pos: usize,
        epoch_idxs: &[EpochId],
        longtail_idxs: &[LongtailId],
    ) {
        let mut guard = self.state.write();
        let bs = &mut *guard;

        // Old finalized epoch — the epoch tier overlays its ring at
        // `(old_fin_epoch + k) % …`. Read from the (still-old) slot-group
        // base before its finalize.
        let old_fin_epoch =
            (bs.slot_states.finalized_view().slot_number() / SLOTS_PER_EPOCH) as usize;

        // The always-rolled tiers finalize in their own groups — re-anchor
        // each survivor against the winner (pin pre-promote values + prune
        // redundancy), then promote the winner into the base. Each base is
        // untouched until its own group's finalize, so it still holds the old
        // count its rebase bounds read. Pending's drain-offset rebase
        // snapshots `old_base_lens` internally from the still-old base; the
        // slot tier prunes survivors' root tails of the promoted prefix.
        rebase_tier(
            survivors,
            |s| &mut s.validators_idx,
            |ids| bs.validators.finalize(promoted.validators_idx, ids),
        );
        rebase_tier(
            survivors,
            |s| &mut s.balances_idx,
            |ids| bs.balances.finalize(promoted.balances_idx, ids),
        );
        rebase_tier(survivors, |s| &mut s.eth1_idx, |ids| bs.eth1.finalize(promoted.eth1_idx, ids));
        rebase_tier(
            survivors,
            |s| &mut s.previous_participation_idx,
            |ids| bs.previous_participation.finalize(promoted.previous_participation_idx, ids),
        );
        rebase_tier(
            survivors,
            |s| &mut s.current_participation_idx,
            |ids| bs.current_participation.finalize(promoted.current_participation_idx, ids),
        );
        rebase_tier(
            survivors,
            |s| &mut s.inactivity_idx,
            |ids| bs.inactivity.finalize(promoted.inactivity_idx, ids),
        );
        rebase_tier(
            survivors,
            |s| &mut s.pending_idx,
            |ids| bs.pending.finalize(promoted.pending_idx, ids),
        );
        rebase_tier(
            survivors,
            |s| &mut s.slot_idx,
            |ids| bs.slot_states.finalize(promoted.slot_idx, ids),
        );

        // Epoch + longtail finalize in their own groups, but — unlike the
        // always-rolled tiers above — forks roll these lazily, so finalize only
        // when the promoted winner actually owns a delta. The survivor idx sets
        // are pre-deduped (one cumulative log re-based once when siblings share
        // it); the group returns the fresh ids 1:1, which we map old→new and
        // write back onto every bundle referencing the old entry.
        if let Some(winner_epoch) = promoted.epoch_idx {
            rebase_lazy_tier(
                survivors,
                epoch_idxs,
                |s| &mut s.epoch_idx,
                || bs.epoch.finalize(winner_epoch, epoch_idxs, old_fin_epoch),
            );
        }
        if let Some(winner_longtail) = promoted.longtail_idx {
            rebase_lazy_tier(
                survivors,
                longtail_idxs,
                |s| &mut s.longtail_idx,
                || bs.longtail.finalize(winner_longtail, longtail_idxs),
            );
        }

        // Publish-with-the-guard: the head's rewritten bundle replaces the
        // stale published one atomically at guard drop.
        guard.set_state_id(survivors[head_pos]);
    }

    fn on_attestation(&mut self, validator_idx: usize, block_root: B256, epoch: Epoch) {
        let n = self.head_validator_count();
        if validator_idx >= n {
            return;
        }
        // Spec `update_latest_messages`: only newer-epoch votes overwrite.
        // Zero `next_root` is the uninitialised sentinel — first vote always
        // takes; a real attestation never has a zero `beacon_block_root`.
        let v = &mut self.vote_tracker.votes[validator_idx];
        if v.next_root != [0u8; 32] && epoch <= v.next_epoch {
            return;
        }
        v.next_root = block_root;
        v.next_epoch = epoch;
    }

    fn recompute_head(&mut self) {
        // Materialise the head's effective-balance column into the reusable
        // scratch (compute_deltas weights LMD votes by effective balance).
        let n = {
            let validators = self.state.read_view(self.last_applied).validators;
            self.stf_scratch.eff.clear();
            self.stf_scratch.eff.extend(validators.iter_effective_balances());
            validators.count()
        };

        let mut deltas = compute_deltas(
            &mut self.vote_tracker.votes,
            n,
            self.fork_choice.indices.as_slice(),
            &self.prev_eff_balances,
            &self.stf_scratch.eff,
        );
        self.fork_choice.apply_score_changes(&mut deltas);
        // Remember this recompute's balances so the next one can net the change.
        self.prev_eff_balances.clear();
        self.prev_eff_balances.extend_from_slice(&self.stf_scratch.eff);
        self.lift_checkpoints();
    }

    /// Monotonically lift fork-choice justified/finalized from the head post-
    /// state, but only to roots present in our node list — during sync the
    /// post-state often names checkpoints from blocks we never imported.
    fn lift_checkpoints(&mut self) {
        let (j, f) = self.head_checkpoints();
        if j.epoch > self.fork_choice.justified_checkpoint.epoch &&
            self.fork_choice.find_node_idx(&j.root).is_some()
        {
            self.fork_choice.justified_checkpoint = j;
        }
        if f.epoch > self.fork_choice.finalized_checkpoint.epoch &&
            self.fork_choice.find_node_idx(&f.root).is_some()
        {
            self.fork_choice.finalized_checkpoint = f;
        }
    }

    fn relay_gossip(m: &NewGossipMsg, producers: &mut Producers) {
        producers.produce(PeerEvent::SendGossip {
            originator_stream_id: m.stream_id,
            topic: m.topic,
            msg_hash: m.msg_hash,
            recv_ts: m.recv_ts,
            protobuf: m.protobuf,
        });
    }

    /// EL payload verdict, from either newPayload or an FCU response.
    fn on_payload_verdict(
        &mut self,
        block_root: &B256,
        latest_valid_hash: &B256,
        status: PayloadValidationStatus,
    ) {
        match status {
            PayloadValidationStatus::Valid => {
                self.fork_choice.on_payload_valid(block_root);
            }
            PayloadValidationStatus::Invalid => {
                self.fork_choice.on_payload_invalid(block_root, latest_valid_hash);
                self.recompute_head();
            }
            // Optimistic: EL still syncing; verdict arrives on a later FCU.
            PayloadValidationStatus::Syncing | PayloadValidationStatus::Accepted => {}
        }
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

    fn handle_gossip(
        &mut self,
        m: NewGossipMsg,
        data: &[u8],
        do_relay: bool,
        producers: &mut Producers,
    ) {
        let feedback = match m.topic {
            GossipTopic::BeaconBlock => {
                let acquired = self.gossip_consumer.acquire(m.ssz);
                Some(self.apply_block(data, acquired, BlockSource::Gossip, producers))
            }
            GossipTopic::BeaconAttestation(_) => Some(self.handle_attestation(data)),
            GossipTopic::BeaconAggregateAndProof => Some(self.handle_aggregate_and_proof(data)),
            GossipTopic::VoluntaryExit => Some(self.handle_voluntary_exit(data)),
            GossipTopic::ProposerSlashing => Some(self.handle_proposer_slashing(data)),
            GossipTopic::AttesterSlashing => Some(self.handle_attester_slashing(data)),
            GossipTopic::BlsToExecutionChange => Some(self.handle_bls_to_execution_change(data)),
            _ => None,
        };
        match feedback {
            Some(Feedback::Reject(_)) => producers.produce(PeerEvent::P2pGossipInvalidMsg {
                p2p_peer: m.stream_id.peer(),
                topic: m.topic,
                hash: m.msg_hash,
            }),
            Some(Feedback::Accept(block_root)) => {
                if do_relay {
                    Self::relay_gossip(&m, producers);
                }

                // Try to apply any pending blocks for which this one was the parent.
                if let Some(root) = block_root {
                    self.apply_pending_blocks(root, producers);
                }
                producers.produce(self.status_event());
            }
            Some(Feedback::RequestParent(parent_root)) => {
                let peer = m.stream_id.peer();
                self.buffer_orphan(parent_root, PendingBlock::Gossip(m), peer, producers);
            }
            Some(Feedback::AwaitData(block_root)) => {
                if do_relay {
                    Self::relay_gossip(&m, producers);
                }
                self.buffer_awaiting_columns(block_root, PendingBlock::Gossip(m));
            }
            Some(Feedback::Ignore) | None => {}
        }
    }

    fn apply_pending_blocks(&mut self, parent_root: B256, producers: &mut Producers) {
        if let Some(pending) = self.pending_blocks.remove(&parent_root) {
            for child in pending {
                // First successful validation of an orphan held on a missing
                // parent: relay it now. Recursively applies chained orphans.
                self.replay_pending_block(child, true, producers);
            }
        }
    }

    /// Buffer an orphan on its missing parent; `apply_pending_blocks`
    /// retries it once the parent applies. Request the parent only when
    /// following and not already held awaiting columns — re-requesting a held
    /// block floods by-root, and during sync the range/DA path delivers it.
    fn buffer_orphan(
        &mut self,
        parent_root: B256,
        pending: PendingBlock,
        peer: usize,
        producers: &mut Producers,
    ) {
        let request =
            self.mode.is_following() && !self.dc_pending_blocks.contains_key(&parent_root);
        self.pending_blocks.entry(parent_root).or_default().push(pending);
        if request {
            producers.produce(PeerEvent::SendBlocksByRootRequest {
                request_id: 0,
                p2p_peer: Some(peer),
                block_root: parent_root,
            })
        }
    }

    /// Hold a fully-prechecked block until its data columns are available.
    fn buffer_awaiting_columns(&mut self, block_root: B256, pending: PendingBlock) {
        self.dc_pending_blocks.entry(block_root).or_insert(pending);
    }

    fn replay_pending_block(
        &mut self,
        pending: PendingBlock,
        do_relay: bool,
        producers: &mut Producers,
    ) {
        match pending {
            PendingBlock::Gossip(g) => {
                let acquired = self.gossip_consumer.acquire(g.ssz);
                if let Some(p) = acquired.buffer().ok().map(|(d, _)| d as *const [u8]) {
                    self.handle_gossip(g, unsafe { &*p }, do_relay, producers);
                }
            }
            PendingBlock::Rpc(stream_id, ssz) => {
                let acquired = self.rpc_consumer.acquire(ssz);
                if let Some(p) = acquired.buffer().ok().map(|(d, _)| d as *const [u8]) {
                    self.handle_rpc_block(stream_id, unsafe { &*p }, acquired, producers);
                } else {
                    tracing::error!("failed to acquire buffer for pending replay");
                }
            }
        }
    }

    fn handle_data_columns_available(
        &mut self,
        m: DataColumnsAvailable,
        producers: &mut Producers,
    ) {
        if m.slot > self.da_boundary() {
            self.dc_available.insert(m.block_root, m.slot);
        }
        tracing::debug!(
            block = hex32(&m.block_root),
            slot = m.slot,
            is_buffered = self.dc_pending_blocks.contains_key(&m.block_root),
            dc_pending = self.dc_pending_blocks.len(),
            "DataColumnsAvailable received"
        );
        if let Some(pending) = self.dc_pending_blocks.remove(&m.block_root) {
            // Already relayed when first seen — don't relay again.
            self.replay_pending_block(pending, false, producers);
        }
    }

    fn handle_rpc_block(
        &mut self,
        sender: P2pStreamId,
        data: &[u8],
        data_tcache: TRead,
        producers: &mut Producers,
    ) {
        {
            if !SignedBeaconBlockView::check_size(data) {
                producers.produce(PeerEvent::RpcMisbehaviour {
                    p2p_peer: sender.peer(),
                    severity: RpcSeverity::LowTolerance,
                });
                return;
            }
            let tcache = data_tcache.read;
            let f = self.apply_block(data, data_tcache, BlockSource::Rpc, producers);
            match f {
                Feedback::Accept(block_root) => {
                    // Try to apply any pending blocks for which this one was the parent.
                    if let Some(root) = block_root {
                        self.apply_pending_blocks(root, producers);
                    }
                    producers.produce(self.status_event());
                }
                Feedback::RequestParent(parent_root) => {
                    let peer = sender.peer();
                    self.buffer_orphan(
                        parent_root,
                        PendingBlock::Rpc(sender, tcache),
                        peer,
                        producers,
                    );
                }
                Feedback::AwaitData(block_root) => {
                    self.buffer_awaiting_columns(block_root, PendingBlock::Rpc(sender, tcache));
                }
                Feedback::Ignore => {}
                Feedback::Reject(_) => producers.produce(PeerEvent::RpcMisbehaviour {
                    p2p_peer: sender.peer(),
                    severity: RpcSeverity::Fatal,
                }),
            }
        }
    }

    /// Below this slot data availability is not required (already finalized,
    /// or PM is range-syncing past it).
    fn da_boundary(&self) -> Slot {
        self.sync_finalized_slot.max(self.fork_choice.finalized_checkpoint.epoch * SLOTS_PER_EPOCH)
    }

    fn apply_block_impl<F: FnMut([u8; 32])>(
        &mut self,
        data: &[u8],
        gate_da: bool,
        mut notify_el: F,
    ) -> Feedback {
        let parsed = match self.precheck_block(data) {
            Ok(p) => p,
            Err(err) => {
                tracing::warn!(head_slot = self.head_state_slot(), "{err}");
                return err.feedback();
            }
        };

        // Data availability is only required above the finalized boundary.
        if gate_da &&
            parsed.block_slot > self.da_boundary() &&
            parsed.has_data_columns &&
            !self.dc_available.contains_key(&parsed.block_root)
        {
            return Feedback::AwaitData(parsed.block_root);
        }

        // Fire as early as possible so the EL round-trip overlaps with the
        // state transition — mirrors Lighthouse's async payload notification.
        // After the DA gate, so a block parked on AwaitData doesn't re-send
        // newPayload on every retry.
        notify_el(parsed.block_root);

        let block_epoch = parsed.block_slot / SLOTS_PER_EPOCH;

        // Per-block attester shuffling against the parent post-state (active
        // set + seed for an epoch are fixed at its prior boundary). The child
        // is a COW copy of the parent pre-STF, so shuffle inputs read identical
        // off `parent_state_id` — done here, before the held-writer view takes the
        // `&mut self.state` borrow for the whole transition. Reuse the
        // `(epoch, mix)`-keyed cache so consecutive same-epoch blocks skip the
        // O(rounds·n) shuffle; `ensure_shuffling_window` only computes on a miss.
        self.ensure_shuffling_window(block_epoch, parsed.parent_state_id);
        let sref = Self::build_shuffling_ref(
            &self.shuffling_cache,
            &mut self.state,
            parsed.parent_state_id,
            block_epoch,
        );

        // COW: an unpublished child off the parent post-state. The view HOLDS
        // every rolled per-slot writer for the whole transition (the boundary
        // epoch/longtail writers are rolled inside `process_epoch` and their
        // committed ids returned); `commit` assembles the child bundle for
        // publish-last.
        let parent = parsed.parent_state_id;
        let (mut view, epoch, longtail) = self.state.apply_block_view(parent);
        self.attestation_votes_scratch.clear();
        let res = state_transition::apply_block(
            &self.spec,
            &mut view,
            epoch,
            longtail,
            parent,
            data,
            parsed.block_slot,
            parsed.proposer_index as u32,
            parsed.parent_root,
            parsed.body_root,
            parsed.state_root,
            Some(&sref),
            &mut self.stf_scratch,
            &mut self.attestation_votes_scratch,
            &mut self.sig_batch,
        );

        // Snapshot checkpoints while the view is live, then `commit` it so the
        // `&mut self.state` borrow ends before the fork-choice / publish work.
        let outcome = match res {
            Ok((epoch_idx, longtail_idx)) => {
                let es = epoch.view_opt(epoch_idx).state();
                let checkpoints = (es.current_justified_checkpoint, es.finalized_checkpoint);
                let execution_block_hash =
                    view.slot.state().latest_execution_payload_header.block_hash;
                Ok((view.commit(epoch_idx, longtail_idx), checkpoints, execution_block_hash))
            }
            Err(e) => Err(e),
        };
        // `view`'s &mut self.state borrow ends here (`commit`/`drop` consumed
        // it); the fork-choice + publish work below needs &mut self.

        let (new_id, (justified, finalized), execution_block_hash) = match outcome {
            Ok(committed) => committed,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    block_slot = %parsed.block_slot,
                    head_slot = self.head_state_slot(),
                    "block rejected"
                );
                return Feedback::Reject(Some(parsed.block_root));
            }
        };

        self.publish_applied_block(&parsed, new_id, justified, finalized, execution_block_hash);
        Feedback::Accept(Some(parsed.block_root))
    }

    fn publish_applied_block(
        &mut self,
        parsed: &ParsedBlock,
        new_id: StateId,
        justified: Checkpoint,
        finalized: Checkpoint,
        execution_block_hash: [u8; 32],
    ) {
        // Fold block-included attestations into the LMD vote tracker.
        for i in 0..self.attestation_votes_scratch.len() {
            let v = self.attestation_votes_scratch[i];
            self.on_attestation(v.validator as usize, v.block_root, v.target_epoch);
        }

        self.fork_choice.on_block(BlockImport {
            slot: parsed.block_slot,
            block_root: parsed.block_root,
            parent_root: parsed.parent_root,
            state_root: parsed.state_root,
            execution_block_hash,
            justified,
            finalized,
            state_id: new_id,
        });

        self.dc_available.remove(&parsed.block_root);

        self.recompute_head();

        self.last_applied = new_id;
        self.last_applied_block_root = parsed.block_root;
        self.state.publish_state_id(new_id);

        self.maybe_finalize();
    }

    /// Pre-COW block validation: parse, parent-known, past-slot, proposer
    /// lookahead, BLS sig. Cheap, no state mutation. Returns parsed fields
    /// on accept; a structured `PrecheckError` on reject/ignore. Caller
    /// projects via `err.feedback()`.
    fn precheck_block(&self, data: &[u8]) -> Result<ParsedBlock, PrecheckError> {
        if !SignedBeaconBlockView::check_size(data) {
            return Err(PrecheckError::SizeMismatch {
                expected_min: ssz_view::SIGNED_BEACON_BLOCK_MIN,
                expected_max: ssz_view::SIGNED_BEACON_BLOCK_MAX,
                got: data.len(),
            });
        }
        let block_slot = SignedBeaconBlockView::slot(data);
        let block_epoch = block_slot / SLOTS_PER_EPOCH;
        let finalized_epoch = self.fork_choice.finalized_checkpoint.epoch;
        if block_epoch < finalized_epoch {
            return Err(PrecheckError::PreFinalized { block_epoch, finalized_epoch });
        }

        let proposer_index = SignedBeaconBlockView::proposer_index(data);
        let parent_root = *SignedBeaconBlockView::parent_root(data);
        let state_root = *SignedBeaconBlockView::state_root(data);

        let body = SignedBeaconBlockView::body(data);
        let body_root = ssz_hash::hash_tree_root_body(body);
        let block_header = BeaconBlockHeader {
            slot: block_slot,
            proposer_index,
            parent_root,
            state_root,
            body_root,
        };
        let block_root = ssz_hash::hash_tree_root_block_header(&block_header);
        if self.fork_choice.find_node_idx(&block_root).is_some() {
            return Err(PrecheckError::AlreadyKnown { block_root });
        }

        let Some(parent_idx) = self.fork_choice.find_node_idx(&parent_root) else {
            let last_applied_slot = self.head_state_slot();
            return Err(PrecheckError::ParentMissing { parent_root, last_applied_slot, block_slot });
        };
        let parent_node = self.fork_choice.node(parent_idx);
        // EL declared the parent invalid — descendants are invalid by
        // definition. Reject before the COW/EL round-trip.
        if parent_node.execution_status == 3 {
            return Err(PrecheckError::ParentInvalid { parent_root, block_root });
        }
        let parent_state_id = parent_node.state_id;

        // Immutable read view of the parent post-state.
        let rv = self.state.read_view(parent_state_id);
        let parent_slot = rv.slot.slot_number();

        // A block must strictly extend its parent's slot.
        if block_slot <= parent_slot {
            return Err(PrecheckError::PastSlot { block_slot, parent_slot });
        }
        // Spec gossip rule: IGNORE blocks whose slot exceeds wall slot.
        let wall_slot_plus_one = self.ticker.current_slot() + 1;
        if block_slot > wall_slot_plus_one {
            return Err(PrecheckError::FutureSlot { block_slot, wall_slot_plus_one });
        }

        let parent_epoch = parent_slot / SLOTS_PER_EPOCH;
        // Fulu proposer selection via `proposer_lookahead` (current + next
        // epoch, 64 slots), fixed at the parent's prior epoch boundary — read
        // it from the parent post-state.
        if block_epoch == parent_epoch || block_epoch == parent_epoch + 1 {
            let lookahead_idx = (block_slot - parent_epoch * SLOTS_PER_EPOCH) as usize;
            if let Some(expected) = rv.epoch.proposer_at(lookahead_idx) &&
                proposer_index != expected
            {
                return Err(PrecheckError::ProposerLookaheadMismatch {
                    expected,
                    got: proposer_index,
                    block_root,
                });
            }
        }

        let validator_count = rv.validators.count();
        if proposer_index as usize >= validator_count {
            return Err(PrecheckError::ProposerIndexTooBig {
                got: proposer_index,
                validator_count,
                block_root,
            });
        }
        let (fork_version, gvr) = rv.imm.fork_version_at(block_epoch);
        let proposer_pubkey = rv.validators.pubkey_decompressed(proposer_index as usize);
        if !bls::verify_block_signature(data, proposer_pubkey, &body_root, fork_version, &gvr) {
            return Err(PrecheckError::InvalidBls {
                proposer_index,
                pubkey: *rv.validators.pubkey(proposer_index as usize),
                block_root,
            });
        }

        Ok(ParsedBlock {
            has_data_columns: SignedBeaconBlockView::has_data_columns(data),
            block_slot,
            proposer_index,
            parent_root,
            state_root,
            body_root,
            block_root,
            parent_state_id,
        })
    }

    fn handle_attestation(&mut self, data: &[u8]) -> Feedback {
        if data.len() < SINGLE_ATT_SIZE {
            return Feedback::Reject(None);
        }
        let buf: &[u8; SINGLE_ATT_SIZE] = data[..SINGLE_ATT_SIZE].try_into().unwrap();
        let attester_index = SingleAttestationView::attester_index(buf) as usize;
        let block_root = *SingleAttestationView::beacon_block_root(buf);
        let target_epoch = SingleAttestationView::target_epoch(buf);
        let att_slot = SingleAttestationView::slot(buf);
        let committee_index = SingleAttestationView::committee_index(buf) as usize;

        let wall = self.ticker.current_slot();
        if att_slot > wall || att_slot.saturating_add(ATTESTATION_PROPAGATION_SLOT_RANGE) < wall {
            return Feedback::Ignore;
        }

        let canon_id = self.canonical_state_id();
        let att_epoch = att_slot / SLOTS_PER_EPOCH;
        self.ensure_shuffling_window(att_epoch, canon_id);

        // Validate committee membership + signature against the canonical head.
        let view = self.state.read_view(canon_id);
        let mix = Self::shuffling_mix(&view, att_epoch);
        let entry = match Self::get_shuffling(&self.shuffling_cache, att_epoch, mix) {
            Some(e) => e,
            None => return Feedback::Ignore,
        };
        let committees_per_slot = shuffling::committees_per_slot(entry.shuffled_indices.len());
        if committee_index >= committees_per_slot {
            return Feedback::Reject(None);
        }
        let committee = shuffling::get_beacon_committee(
            entry.shuffled_indices.as_slice(),
            att_slot,
            committee_index,
            committees_per_slot,
        );
        if !committee.contains(&(attester_index as u32)) {
            return Feedback::Reject(None);
        }
        if attester_index >= view.validators.count() {
            return Feedback::Reject(None);
        }
        let (fork_version, gvr) = view.imm.fork_version_at(target_epoch);
        let ok = bls::verify_single_attestation(
            buf,
            view.validators.pubkey_decompressed(attester_index),
            fork_version,
            &gvr,
        );
        if !ok {
            return Feedback::Reject(None);
        }

        self.on_attestation(attester_index, block_root, target_epoch);
        Feedback::Accept(None)
    }

    fn handle_aggregate_and_proof(&mut self, data: &[u8]) -> Feedback {
        let Some(parsed) = ParsedAggregateAndProof::try_from(data) else {
            return Feedback::Reject(None);
        };

        // Gossip-rule checks (no state access).
        if parsed.agg_data_index != 0 || parsed.target_epoch != parsed.att_epoch {
            return Feedback::Reject(None);
        }
        let wall = self.ticker.current_slot();
        if parsed.agg_slot > wall ||
            parsed.agg_slot.saturating_add(ATTESTATION_PROPAGATION_SLOT_RANGE) < wall
        {
            return Feedback::Ignore;
        }
        if parsed.committee_bits.count_ones() != 1 {
            return Feedback::Reject(None);
        }
        let committee_index = parsed.committee_bits.trailing_zeros() as usize;

        // Fork-choice: block known + target.root ancestor at target-epoch start.
        match self
            .fork_choice
            .get_checkpoint_block(&parsed.beacon_block_root, parsed.target_epoch * SLOTS_PER_EPOCH)
        {
            Some(r) if r == parsed.target_root => {}
            Some(_) => return Feedback::Reject(None),
            None => return Feedback::Ignore,
        }

        let canon_id = self.canonical_state_id();
        self.ensure_shuffling_window(parsed.att_epoch, canon_id);

        let view = self.state.read_view(canon_id);
        let count = view.validators.count();
        if parsed.aggregator_index >= count {
            return Feedback::Ignore;
        }

        let mix = Self::shuffling_mix(&view, parsed.att_epoch);
        let shuffled = match Self::get_shuffling(&self.shuffling_cache, parsed.att_epoch, mix) {
            Some(e) => e.shuffled_indices.as_slice(),
            None => return Feedback::Ignore,
        };
        let committees_per_slot = shuffling::committees_per_slot(shuffled.len());
        if committee_index >= committees_per_slot {
            return Feedback::Reject(None);
        }
        let committee = shuffling::get_beacon_committee(
            shuffled,
            parsed.agg_slot,
            committee_index,
            committees_per_slot,
        );
        if !committee.contains(&(parsed.aggregator_index as u32)) {
            return Feedback::Reject(None);
        }
        let committee_len = committee.len();

        self.stf_scratch.active.clear();
        for (j, &vi32) in committee.iter().enumerate() {
            let byte_idx = j / 8;
            let bit_idx = j % 8;
            if byte_idx >= parsed.aggregation_bits.len() ||
                parsed.aggregation_bits[byte_idx] & (1 << bit_idx) == 0
            {
                continue;
            }
            if vi32 as usize >= count {
                return Feedback::Reject(None);
            }
            self.stf_scratch.active.push(vi32);
        }
        if self.stf_scratch.active.is_empty() {
            return Feedback::Reject(None);
        }

        if !is_aggregator(committee_len, parsed.selection_proof) {
            return Feedback::Reject(None);
        }

        if !Self::verify_aggregate_and_proof_sigs(
            &view,
            &parsed,
            &self.stf_scratch.active,
            &mut self.sig_batch,
        ) {
            return Feedback::Reject(None);
        }

        for i in 0..self.stf_scratch.active.len() {
            let vi = self.stf_scratch.active[i] as usize;
            self.on_attestation(vi, parsed.beacon_block_root, parsed.target_epoch);
        }
        Feedback::Accept(None)
    }

    fn verify_aggregate_and_proof_sigs(
        view: &StateReadView,
        parsed: &ParsedAggregateAndProof<'_>,
        active_scratch: &[u32],
        sig_batch: &mut bls::SigBatch,
    ) -> bool {
        let (fv, gvr) = view.imm.fork_version_at(parsed.target_epoch);

        // (1) selection_proof — signer = aggregator, msg = htr(uint64(slot)).
        let slot_root = ssz_hash::uint64_chunk(parsed.agg_slot);
        let domain_sp = bls::compute_domain(bls::DOMAIN_SELECTION_PROOF, fv, &gvr);
        let sr_sp = bls::compute_signing_root(&slot_root, &domain_sp);

        // (2) outer AggregateAndProof signature.
        let agg_proof_root = ssz_hash::hash_tree_root_aggregate_and_proof(
            parsed.aggregator_index as u64,
            parsed.aggregate_bytes,
            parsed.selection_proof,
        );
        let domain_aap = bls::compute_domain(bls::DOMAIN_AGGREGATE_AND_PROOF, fv, &gvr);
        let sr_aap = bls::compute_signing_root(&agg_proof_root, &domain_aap);

        // (3) inner aggregate signature over AttestationData.
        let data_root = ssz_hash::hash_attestation_data(parsed.agg_data);
        let domain_att = bls::compute_domain(bls::DOMAIN_BEACON_ATTESTER, fv, &gvr);
        let sr_att = bls::compute_signing_root(&data_root, &domain_att);

        sig_batch.clear();
        let aggregator_pk = view.validators.pubkey_decompressed(parsed.aggregator_index);
        sig_batch.push_one(aggregator_pk, parsed.selection_proof, sr_sp);
        sig_batch.push_one(aggregator_pk, parsed.outer_sig, sr_aap);
        sig_batch.push_aggregate(
            active_scratch.iter().map(|&vi| view.validators.pubkey_decompressed(vi as usize)),
            parsed.agg_sig,
            sr_att,
        );
        sig_batch.verify_all()
    }

    fn handle_voluntary_exit(&mut self, data: &[u8]) -> Feedback {
        if data.len() != SIGNED_VOLUNTARY_EXIT_SIZE {
            return Feedback::Reject(None);
        }
        let buf: &[u8; SIGNED_VOLUNTARY_EXIT_SIZE] =
            data[..SIGNED_VOLUNTARY_EXIT_SIZE].try_into().unwrap();
        let exit_epoch = SignedVoluntaryExitView::epoch(buf);
        let vi_u = SignedVoluntaryExitView::validator_index(buf);
        let vi = vi_u as usize;

        let canon_id = self.canonical_state_id();
        let view = self.state.read_view(canon_id);
        // Out-of-range index: state may be stale, defer.
        if vi >= view.validators.count() {
            return Feedback::Ignore;
        }
        let current_epoch = view.slot.current_epoch();
        if let Err(e) = validate::validate_voluntary_exit(
            &self.spec,
            &view.validators,
            vi_u as u32,
            exit_epoch,
            current_epoch,
        ) {
            tracing::debug!(error = %e, "voluntary_exit gossip rejected");
            return Feedback::Reject(None);
        }
        if state_transition::get_pending_balance_to_withdraw(&view.pending, vi_u as u32) != 0 {
            return Feedback::Reject(None);
        }

        let object_root = ssz_hash::hash_tree_root_voluntary_exit(exit_epoch, vi_u);
        let imm = view.imm;
        let domain = bls::compute_domain(
            bls::DOMAIN_VOLUNTARY_EXIT,
            imm.capella_fork_version,
            &imm.genesis_validators_root,
        );
        let signing_root = bls::compute_signing_root(&object_root, &domain);
        let sig = SignedVoluntaryExitView::signature(buf);
        if !bls::verify_one(view.validators.pubkey_decompressed(vi), sig, &signing_root) {
            return Feedback::Reject(None);
        }
        Feedback::Accept(None)
    }

    fn handle_proposer_slashing(&mut self, data: &[u8]) -> Feedback {
        if data.len() != PROPOSER_SLASHING_SIZE {
            return Feedback::Reject(None);
        }
        let buf: &[u8; PROPOSER_SLASHING_SIZE] = data[..PROPOSER_SLASHING_SIZE].try_into().unwrap();
        if let Err(e) = validate::validate_proposer_slashing(buf) {
            tracing::debug!(error = %e, "proposer_slashing gossip rejected");
            return Feedback::Reject(None);
        }

        let canon_id = self.canonical_state_id();
        let view = self.state.read_view(canon_id);
        let current_epoch = view.slot.current_epoch();
        let proposer_index = ProposerSlashingView::h1_proposer_index(buf) as usize;
        if proposer_index >= view.validators.count() {
            return Feedback::Ignore;
        }
        if !state_transition::is_slashable_validator(
            &view.validators,
            proposer_index as u32,
            current_epoch,
        ) {
            return Feedback::Reject(None);
        }

        let h1_epoch = ProposerSlashingView::h1_slot(buf) / SLOTS_PER_EPOCH;
        let h2_epoch = ProposerSlashingView::h2_slot(buf) / SLOTS_PER_EPOCH;
        let (fv1, gvr) = view.imm.fork_version_at(h1_epoch);
        let (fv2, _) = view.imm.fork_version_at(h2_epoch);
        let sr1 = state_transition::signing_root_for_block_header(&buf[0..208], fv1, &gvr);
        let sr2 = state_transition::signing_root_for_block_header(&buf[208..416], fv2, &gvr);
        let sig1 = ProposerSlashingView::h1_signature(buf);
        let sig2 = ProposerSlashingView::h2_signature(buf);
        let pubkey = view.validators.pubkey_decompressed(proposer_index);

        self.sig_batch.clear();
        self.sig_batch.push_one(pubkey, sig1, sr1);
        self.sig_batch.push_one(pubkey, sig2, sr2);
        if !self.sig_batch.verify_all() {
            return Feedback::Reject(None);
        }
        Feedback::Accept(None)
    }

    fn handle_attester_slashing(&mut self, data: &[u8]) -> Feedback {
        if !AttesterSlashingView::check_size(data) {
            return Feedback::Reject(None);
        }
        let canon_id = self.canonical_state_id();
        let view = self.state.read_view(canon_id);
        if state_transition::validate_attester_slashing_for_gossip(&view, data, &mut self.sig_batch)
        {
            Feedback::Accept(None)
        } else {
            Feedback::Reject(None)
        }
    }

    fn handle_bls_to_execution_change(&mut self, data: &[u8]) -> Feedback {
        if data.len() != SIGNED_BLS_CHANGE_SIZE {
            return Feedback::Reject(None);
        }
        let buf: &[u8; SIGNED_BLS_CHANGE_SIZE] = data[..SIGNED_BLS_CHANGE_SIZE].try_into().unwrap();

        let canon_id = self.canonical_state_id();
        let view = self.state.read_view(canon_id);

        let vi_u = SignedBlsToExecutionChangeView::validator_index(buf);
        let vi = vi_u as usize;
        if vi >= view.validators.count() {
            return Feedback::Ignore;
        }
        let from_pubkey = SignedBlsToExecutionChangeView::from_bls_pubkey(buf);
        let to_address = SignedBlsToExecutionChangeView::to_execution_address(buf);
        if let Err(e) =
            validate::validate_bls_to_execution_change(&view.validators, vi_u as u32, from_pubkey)
        {
            tracing::debug!(error = %e, "bls_to_execution_change gossip rejected");
            return Feedback::Reject(None);
        }

        let object_root = ssz_hash::hash_tree_root_bls_change(vi_u, from_pubkey, to_address);
        let imm = view.imm;
        let domain = bls::compute_domain(
            bls::DOMAIN_BLS_TO_EXECUTION_CHANGE,
            imm.genesis_fork_version,
            &imm.genesis_validators_root,
        );
        let signing_root = bls::compute_signing_root(&object_root, &domain);
        let sig = SignedBlsToExecutionChangeView::signature(buf);
        // Signer is the message's `from_bls_pubkey`, not a cached key.
        if !bls::verify_one_compressed(from_pubkey, sig, &signing_root) {
            return Feedback::Reject(None);
        }
        Feedback::Accept(None)
    }
}

/// Parsed view over a SignedAggregateAndProof gossip message.
struct ParsedAggregateAndProof<'a> {
    outer_sig: &'a [u8; 96],
    aggregator_index: usize,
    selection_proof: &'a [u8; 96],
    agg_slot: u64,
    agg_data_index: u64,
    beacon_block_root: B256,
    target_epoch: Epoch,
    target_root: B256,
    committee_bits: u64,
    agg_sig: &'a [u8; 96],
    agg_data: &'a [u8],
    aggregation_bits: &'a [u8],
    aggregate_bytes: &'a [u8],
    att_epoch: Epoch,
}

impl<'a> ParsedAggregateAndProof<'a> {
    fn try_from(data: &'a [u8]) -> Option<Self> {
        if !SignedAggregateAndProofView::check_size(data) {
            return None;
        }
        let agg_slot = SignedAggregateAndProofView::agg_slot(data);
        Some(Self {
            outer_sig: SignedAggregateAndProofView::signature(data),
            aggregator_index: SignedAggregateAndProofView::aggregator_index(data) as usize,
            selection_proof: SignedAggregateAndProofView::selection_proof(data),
            agg_slot,
            agg_data_index: SignedAggregateAndProofView::agg_data_index(data),
            beacon_block_root: *SignedAggregateAndProofView::agg_beacon_block_root(data),
            target_epoch: SignedAggregateAndProofView::agg_target_epoch(data),
            target_root: *SignedAggregateAndProofView::agg_target_root(data),
            committee_bits: u64::from_le_bytes(*SignedAggregateAndProofView::agg_committee_bits(
                data,
            )),
            agg_sig: SignedAggregateAndProofView::agg_signature(data),
            agg_data: SignedAggregateAndProofView::agg_data(data),
            aggregation_bits: SignedAggregateAndProofView::agg_aggregation_bits(data),
            aggregate_bytes: SignedAggregateAndProofView::aggregate(data),
            att_epoch: agg_slot / SLOTS_PER_EPOCH,
        })
    }
}

impl Tile<SilverSpine> for BeaconStateTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        if !self.initial_status_emitted {
            adapter.produce(self.status_event());
            self.initial_status_emitted = true;
        }

        let following = self.mode.is_following();
        if following {
            match self.ticker.tick() {
                TickEvent::SlotStart(slot) => {
                    if self.on_slot_start(slot) {
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

        adapter.consume(|m: NewGossipMsg, producers| {
            if following {
                let acquired = self.gossip_consumer.acquire(m.ssz);
                let data = acquired.buffer().ok().map(|(d, _)| d as *const [u8]);
                if let Some(p) = data {
                    self.handle_gossip(m, unsafe { &*p }, true, producers);
                }
            } else {
                tracing::trace!(
                    topic = ?m.topic,
                    p2p_peer = m.stream_id.peer(),
                    dc_pending_len = self.dc_pending_blocks.len(),
                    head_slot = self.head_state_slot(),
                    "gossip dropped: BeaconState in Syncing mode"
                );
            }
        });
        self.gossip_consumer.free();

        // PM drives sync. Mirror the latest target into `mode`, used only
        // to gate gossip/slot-tick processing. Stale events in the queue
        // collapse — only the latest wins.
        adapter.consume(|target: SyncUpdate, _producers| {
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
                tracing::info!(
                    from = ?self.mode,
                    to = ?new_sync,
                    ?target,
                    "BeaconState mode transition"
                );
                self.mode = new_sync;
            }
        });

        adapter.consume(|m: RpcInbound, producers| {
            if let RpcInbound::Response(RpcResponseInbound {
                application_id: _,
                stream_id,
                response,
            }) = m &&
                let RpcResponse::BeaconBlock { fork_digest: _, ssz } = response
            {
                tracing::debug!(?stream_id, "received beacon block over rpc");
                let acquired = self.rpc_consumer.acquire(ssz);
                let data = acquired.buffer().ok().map(|(d, _)| d as *const [u8]);
                if let Some(p) = data {
                    self.handle_rpc_block(stream_id, unsafe { &*p }, acquired, producers);
                }
            }
        });
        self.rpc_consumer.free();

        adapter.consume(|m: DataColumnsAvailable, producers| {
            self.handle_data_columns_available(m, producers);
        });

        adapter.consume(|eng_resp: EngineResp, producers| {
            self.handle_engine_response(eng_resp, producers);
        });
        self.incoming_engine_resp_consumer.free();
    }
}

/// Spec gossip rule: `aggregate.slot + ATTESTATION_PROPAGATION_SLOT_RANGE >=
/// current_slot >= aggregate.slot`.
const ATTESTATION_PROPAGATION_SLOT_RANGE: u64 = 32;

/// Re-anchor one always-rolled tier: collect each survivor's id for the tier
/// (`proj`), run the group's `finalize`, and write the fresh ids back 1:1.
fn rebase_tier<I: Copy>(
    survivors: &mut [StateId],
    proj: impl Fn(&mut StateId) -> &mut I,
    finalize: impl FnOnce(&ArrayVec<I, MAX_SURVIVORS>) -> Vec<I>,
) {
    let ids: ArrayVec<I, MAX_SURVIVORS> = survivors.iter_mut().map(|s| *proj(s)).collect();
    let new = finalize(&ids);
    for (sid, &n) in survivors.iter_mut().zip(&new) {
        *proj(sid) = n;
    }
}

/// Re-anchor a lazily-rolled tier: `old_idxs` is the pre-deduped set of live
/// entries (one cumulative log re-based once when siblings share it); the
/// group's `finalize` returns the fresh ids 1:1, mapped old→new onto every
/// bundle referencing an old entry.
fn rebase_lazy_tier<I: Copy + PartialEq>(
    survivors: &mut [StateId],
    old_idxs: &[I],
    proj: impl Fn(&mut StateId) -> &mut Option<I>,
    finalize: impl FnOnce() -> Vec<I>,
) {
    let new = finalize();
    for sid in survivors.iter_mut() {
        if let Some(old) = *proj(sid) &&
            let Some(pos) = old_idxs.iter().position(|&e| e == old)
        {
            *proj(sid) = Some(new[pos]);
        }
    }
}

/// Resolve a pending block's SSZ via its source consumer; keep it iff its
/// slot is above the finalized boundary (unreadable buffers are dropped).
fn pending_block_outlives(
    gossip_consumer: &mut TRandomAccess,
    rpc_consumer: &mut TRandomAccess,
    msg: &PendingBlock,
    finalized_slot: u64,
) -> bool {
    let acquired = match msg {
        PendingBlock::Gossip(g) => gossip_consumer.acquire(g.ssz),
        PendingBlock::Rpc(_, ssz) => rpc_consumer.acquire(*ssz),
    };
    if let Ok((buffer, _)) = acquired.buffer() {
        return SignedBeaconBlockView::slot(buffer) > finalized_slot;
    }
    false
}

fn is_aggregator(committee_len: usize, selection_proof: &[u8; 96]) -> bool {
    const TARGET_AGGREGATORS_PER_COMMITTEE: u64 = 16;
    let modulo = (committee_len as u64 / TARGET_AGGREGATORS_PER_COMMITTEE).max(1);
    let h = ssz_hash::sha256(selection_proof);
    u64::from_le_bytes(h[0..8].try_into().unwrap()) % modulo == 0
}

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
    let mix = ssz_hash::sha256(&input);
    [base[0] ^ mix[0], base[1] ^ mix[1], base[2] ^ mix[2], base[3] ^ mix[3]]
}

/// Spec `get_blob_parameters`. `schedule` must be sorted ascending by epoch;
/// `default` is `BlobParameters(ELECTRA_FORK_EPOCH,
/// MAX_BLOBS_PER_BLOCK_ELECTRA)`.
fn get_blob_parameters(
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
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use silver_beacon_state_data::{
        BLSPubkey, BalancesGroup, CurrentParticipationGroup, EPOCHS_PER_SLASHINGS_VECTOR,
        EpochGroup, EpochState, EpochStateFinalized, Eth1Group, Eth1Votes, FinalizedValidators,
        Immutable, InactivityScoresGroup, LongtailGroup, LongtailState, PROPOSER_LOOKAHEAD_SIZE,
        PendingDeposit, PendingGroup, PendingQueues, PreviousParticipationGroup,
        SLOTS_PER_HISTORICAL_ROOT, SlotStateFinalized, SlotStateGroup, SlotStateId, ValSeed,
        ValidatorsGroup, Withdrawals, validator_capacity,
    };
    use silver_common::{TCache, TCacheProducer, ssz_view::SIGNED_AGG_PROOF_MIN};

    use super::*;
    use crate::test_signing;

    const MAX_EFFECTIVE_BALANCE: u64 = 32_000_000_000;
    const ANCHOR_ROOT: B256 = [0x01u8; 32];

    fn make_tile() -> BeaconStateTile {
        make_tile_at_wall_slot(1)
    }

    /// Tile whose ticker reports `wall_slot` as the current slot.
    fn make_tile_at_wall_slot(wall_slot: u64) -> BeaconStateTile {
        let secs_per_slot = 12u64;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let genesis = now.saturating_sub(wall_slot * secs_per_slot + 1);
        let ticker = SlotTicker::new(genesis, Duration::from_secs(12), Duration::from_secs(4));
        let gossip_p = TCache::producer("test_gossip", 1 << 20);
        let event_p = TCache::producer("test_event", 1 << 20);
        let engine_p = TCache::producer("test_engine", 1 << 20);
        let gossip_c = gossip_p.cache_ref().random_access("test_gossip", true).unwrap();
        let rpc_c = event_p.cache_ref().random_access("test_event", true).unwrap();
        let engine_c = engine_p.cache_ref().random_access("test_engine", true).unwrap();
        let state = BeaconStateOwner::pre_bootstrap();
        BeaconStateTile::new(
            ticker,
            SpecConfig::mainnet(),
            state,
            gossip_c,
            rpc_c,
            engine_c,
            &[],
            &[],
        )
    }

    fn placeholder_pubkey(i: usize) -> BLSPubkey {
        let mut pk = [0u8; 48];
        pk[..4].copy_from_slice(&(i as u32).to_le_bytes());
        pk
    }

    /// Epoch-tier base with zeroed rings and the given checkpoints seeded —
    /// the harness analog of a decomposed anchor.
    fn epoch_base_with(justified: Checkpoint, finalized: Checkpoint) -> EpochStateFinalized {
        EpochStateFinalized::from_parts(
            EpochState {
                current_justified_checkpoint: justified,
                finalized_checkpoint: finalized,
                ..Default::default()
            },
            vec![[0u8; 32]; EPOCHS_PER_HISTORICAL_VECTOR].into_boxed_slice(),
            vec![0u64; EPOCHS_PER_SLASHINGS_VECTOR].into_boxed_slice(),
        )
    }

    /// Build seed bases with `n` active validators (MAX effective balance,
    /// activation epoch 0, exit FAR_FUTURE) at `start_slot`. With `real_keys`,
    /// install spec BLS test pubkeys (+ BLS-prefix withdrawal creds) so
    /// signature-checking handlers accept; otherwise collision-free
    /// placeholder pubkeys.
    fn build_seed_finalized(n: usize, real_keys: bool) -> (EpochStateFinalized, Vec<ValSeed>) {
        let cp_fin = Checkpoint { epoch: 0, root: ANCHOR_ROOT };
        let seeds: Vec<ValSeed> = (0..n)
            .map(|i| {
                let (pubkey, withdrawal_credentials) = if real_keys {
                    let sk_idx = i % test_signing::PRIVKEY_HEX.len();
                    let pk_bytes = test_signing::pubkey_pk(sk_idx).to_bytes();
                    // BLS-prefix creds: [0]=0x00, [1..]=hash(pk)[1..].
                    let mut creds = Withdrawals(ssz_hash::sha256(&pk_bytes));
                    creds.0[0] = 0x00;
                    (pk_bytes, creds)
                } else {
                    (placeholder_pubkey(i), Withdrawals::default())
                };
                ValSeed {
                    pubkey,
                    withdrawal_credentials,
                    effective_balance: MAX_EFFECTIVE_BALANCE,
                    balance: MAX_EFFECTIVE_BALANCE,
                    activation_epoch: 0,
                    ..Default::default()
                }
            })
            .collect();
        // The finalized slot lives in the slot-group base (seeded in
        // `arm_tile` from `start_slot`); the validator registry rides its own
        // group (seeded in `arm_tile` from `seeds`); the epoch tier rides its
        // own group (built in `arm_tile` from this base).
        (epoch_base_with(cp_fin, cp_fin), seeds)
    }

    /// Install the seed bases as the tile's state, anchor an empty per-fork
    /// delta seeded with the finalized slot scalars, and arm fork choice + the
    /// start-epoch attester shuffling at the anchor.
    fn arm_tile(
        tile: &mut BeaconStateTile,
        epoch_base: EpochStateFinalized,
        seeds: &[ValSeed],
        start_slot: Slot,
    ) {
        // Test-built state: epoch base seeded from `epoch_base`, registry from
        // `seeds`, slot base anchored at `start_slot`, per-validator columns
        // zeroed at the registry's count, the rest empty.
        let zero_roots = || vec![[0u8; 32]; SLOTS_PER_HISTORICAL_ROOT].into_boxed_slice();
        let n = seeds.len();
        let cap = validator_capacity(n);
        let zero_u64s = vec![0u8; n * 8];
        let zero_flags = vec![0u8; n];
        let bs = BeaconState {
            immutable: Immutable::default(),
            validators: ValidatorsGroup::new(FinalizedValidators::with_validators(seeds)),
            balances: BalancesGroup::new(cap, n, &zero_u64s).unwrap(),
            eth1: Eth1Group::new(Eth1Votes::default()),
            pending: PendingGroup::new(PendingQueues::default()),
            previous_participation: PreviousParticipationGroup::new(cap, n, &zero_flags).unwrap(),
            current_participation: CurrentParticipationGroup::new(cap, n, &zero_flags).unwrap(),
            inactivity: InactivityScoresGroup::new(cap, n, &zero_u64s).unwrap(),
            slot_states: SlotStateGroup::new(SlotStateFinalized::from_parts(
                SlotState { slot: start_slot, ..Default::default() },
                zero_roots(),
                zero_roots(),
            )),
            epoch: EpochGroup::new(epoch_base),
            longtail: LongtailGroup::new(LongtailState::default()),
        };
        let mut bs = bs;
        // Anchor each tier's fork at the base (the slot tier at `start_slot`);
        // epoch/longtail stay lazy. Rolled before the owner wraps the state.
        let anchor = bs.roll_fresh();
        let mut owner = BeaconStateOwner::new(bs);
        owner.publish_state_id(anchor);

        tile.state = owner;
        tile.last_applied = anchor;
        tile.last_applied_block_root = ANCHOR_ROOT;
        tile.mode = Mode::Following;

        let cp = Checkpoint { epoch: 0, root: ANCHOR_ROOT };
        tile.fork_choice = ForkChoice::init(cp, cp, start_slot, ANCHOR_ROOT, ANCHOR_ROOT, anchor);

        tile.ensure_shuffling_window(start_slot / SLOTS_PER_EPOCH, anchor);
    }

    fn seed_tile(tile: &mut BeaconStateTile, n: usize, start_slot: Slot) {
        let (epoch_base, seeds) = build_seed_finalized(n, false);
        arm_tile(tile, epoch_base, &seeds, start_slot);
    }

    fn seed_tile_with_keys(tile: &mut BeaconStateTile, n: usize, start_slot: Slot) {
        let (epoch_base, seeds) = build_seed_finalized(n, true);
        arm_tile(tile, epoch_base, &seeds, start_slot);
    }

    /// Immutable tier the signed-object builders sign against. `seed_*` leave
    /// the base immutable all-default, so a default crate `Immutable` matches
    /// the common one the handlers read, field-for-field (fork versions + gvr
    /// all zero → identical signing domains).
    fn seed_immutable(_tile: &BeaconStateTile) -> Immutable {
        Immutable::default()
    }

    #[test]
    fn slot_advance_skip_multiple() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 10);
        tile.on_slot_start(15);
        assert_eq!(tile.head_state_slot(), 15);
    }

    #[test]
    fn slot_advance_noop_past_slot() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 10);
        tile.on_slot_start(5);
        assert_eq!(tile.head_state_slot(), 10);
    }

    #[test]
    fn slot_advance_crosses_epoch_boundary() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 30);
        tile.on_slot_start(34);
        assert_eq!(tile.head_state_slot(), 34);
        // Crossing into epoch 1 allocated the head fork its own epoch delta.
        assert!(tile.last_applied.epoch_idx.is_some());
    }

    /// Regression: advancing the head over an empty epoch-boundary slot must
    /// COW the epoch tier, not shift the parent's shared `proposer_lookahead`
    /// in place. The parent stays a live fork-choice node the proposer
    /// precheck reads; an in-place shift left its next-epoch slice one epoch
    /// too far, rejecting valid boundary blocks.
    #[test]
    fn empty_slot_advance_preserves_parent_lookahead() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 31); // anchor at epoch-0's last slot

        // Give the anchor its own epoch entry with a recognizable lookahead —
        // rolled, mutated through the held writer, committed (append-only).
        // The anchor bundle is rebuilt with the new epoch id and re-installed
        // as the head (the fork-choice anchor node keeps the lazy bundle —
        // this test never reads it).
        let anchor_epoch_idx = {
            let mut g = tile.state.write();
            let mut w = g.epoch.roll_inheriting(tile.last_applied.epoch_idx);
            let es = w.state_mut();
            for i in 0..PROPOSER_LOOKAHEAD_SIZE {
                es.proposer_lookahead[i] = i as u64;
            }
            w.commit()
        };
        tile.last_applied.epoch_idx = Some(anchor_epoch_idx);
        let before = tile.state.state().epoch.view(anchor_epoch_idx).state().proposer_lookahead;

        // Advance across the epoch 0 -> 1 boundary on empty slots.
        tile.on_slot_start(32);
        assert_eq!(tile.head_state_slot(), 32);

        // Head forked onto a private epoch delta; the anchor's is untouched.
        let head_epoch_idx = tile.last_applied.epoch_idx.unwrap();
        assert_ne!(head_epoch_idx, anchor_epoch_idx, "head must COW its epoch delta");
        let after = tile.state.state().epoch.view(anchor_epoch_idx).state().proposer_lookahead;
        assert_eq!(before, after, "parent proposer_lookahead shifted in place");
    }

    #[test]
    fn slot_advance_crosses_two_epoch_boundaries() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 30);
        tile.on_slot_start(66);
        assert_eq!(tile.head_state_slot(), 66);
    }

    #[test]
    fn block_unknown_parent_rejected() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 10);

        // Minimal SignedBeaconBlock: message at fixed offset 100 (4-byte
        // offset + 96-byte signature), parent_root @ 116 set to an unknown
        // root so precheck bails with ParentMissing before any state change.
        let mut buf = vec![0u8; 200];
        buf[100..108].copy_from_slice(&11u64.to_le_bytes()); // slot
        buf[108..116].copy_from_slice(&0u64.to_le_bytes()); // proposer_index
        buf[116] = 0xFF; // parent_root[0]

        let head_before = tile.last_applied;
        let nodes_before = tile.fork_choice.nodes.len();
        tile.apply_block_impl(&buf, true, |_block_root| {});

        assert_eq!(tile.last_applied, head_before, "head must be unchanged");
        assert_eq!(tile.fork_choice.nodes.len(), nodes_before, "no node added");
    }

    // ── gossip handlers ──

    #[test]
    fn attestation_too_short_ignored() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 10);
        let buf = [0u8; 100];
        tile.handle_attestation(&buf);
        assert_eq!(tile.vote_tracker.votes[0].next_epoch, 0);
    }

    #[test]
    fn ve_unknown_validator_ignored() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 0);
        let mut buf = [0u8; SIGNED_VOLUNTARY_EXIT_SIZE];
        buf[8..16].copy_from_slice(&999u64.to_le_bytes());
        assert_eq!(tile.handle_voluntary_exit(&buf), Feedback::Ignore);
    }

    #[test]
    fn ve_accept() {
        let mut tile = make_tile();
        // Past shard-committee-period so the exit is permitted.
        seed_tile_with_keys(&mut tile, 4, 256 * SLOTS_PER_EPOCH);
        let imm = seed_immutable(&tile);
        let buf = test_signing::sign_voluntary_exit(0, 0, 0, &imm);
        assert_eq!(tile.handle_voluntary_exit(&buf), Feedback::Accept(None));
    }

    #[test]
    fn ps_identical_headers_rejected() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 0);
        let buf = [0u8; PROPOSER_SLASHING_SIZE];
        assert_eq!(tile.handle_proposer_slashing(&buf), Feedback::Reject(None));
    }

    #[test]
    fn ps_unknown_proposer_ignored() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 0);
        let mut buf = [0u8; PROPOSER_SLASHING_SIZE];
        buf[8..16].copy_from_slice(&999u64.to_le_bytes());
        buf[216..224].copy_from_slice(&999u64.to_le_bytes());
        buf[208 + 80] = 0xFF; // distinct body_root in h2
        assert_eq!(tile.handle_proposer_slashing(&buf), Feedback::Ignore);
    }

    #[test]
    fn ps_accept() {
        let mut tile = make_tile();
        seed_tile_with_keys(&mut tile, 4, 0);
        let imm = seed_immutable(&tile);
        let buf = test_signing::sign_proposer_slashing(0, 0, 0, &imm);
        assert_eq!(tile.handle_proposer_slashing(&buf), Feedback::Accept(None));
    }

    #[test]
    fn ps_mismatched_slot_rejected() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 0);
        let mut buf = [0u8; PROPOSER_SLASHING_SIZE];
        buf[208] = 1; // h2.slot differs
        assert_eq!(tile.handle_proposer_slashing(&buf), Feedback::Reject(None));
    }

    #[test]
    fn ps_mismatched_proposer_rejected() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 0);
        let mut buf = [0u8; PROPOSER_SLASHING_SIZE];
        buf[208 + 8] = 1; // h2.proposer_index differs
        assert_eq!(tile.handle_proposer_slashing(&buf), Feedback::Reject(None));
    }

    /// IndexedAttestation with `attesting_indices = indices`, zero sig — for
    /// structural / state-derived reject tests only.
    fn build_ia_with_indices(target_epoch: u64, bbr_marker: u8, indices: &[u64]) -> Vec<u8> {
        let mut buf = vec![0u8; 228 + indices.len() * 8];
        buf[0..4].copy_from_slice(&228u32.to_le_bytes());
        buf[20] = bbr_marker;
        buf[92..100].copy_from_slice(&target_epoch.to_le_bytes());
        for (i, &vi) in indices.iter().enumerate() {
            buf[228 + i * 8..228 + (i + 1) * 8].copy_from_slice(&vi.to_le_bytes());
        }
        buf
    }

    fn wrap_attester_slashing(ia1: &[u8], ia2: &[u8]) -> Vec<u8> {
        let off1: u32 = 8;
        let off2: u32 = off1 + ia1.len() as u32;
        let mut buf = Vec::with_capacity(8 + ia1.len() + ia2.len());
        buf.extend_from_slice(&off1.to_le_bytes());
        buf.extend_from_slice(&off2.to_le_bytes());
        buf.extend_from_slice(ia1);
        buf.extend_from_slice(ia2);
        buf
    }

    #[test]
    fn as_zero_intersection_rejected() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 0);
        let ia1 = build_ia_with_indices(0, 0xAA, &[0]);
        let ia2 = build_ia_with_indices(0, 0xBB, &[1]);
        let buf = wrap_attester_slashing(&ia1, &ia2);
        assert_eq!(tile.handle_attester_slashing(&buf), Feedback::Reject(None));
    }

    #[test]
    fn as_accept() {
        let mut tile = make_tile();
        seed_tile_with_keys(&mut tile, 4, 0);
        let imm = seed_immutable(&tile);
        let buf = test_signing::sign_attester_slashing_double_vote(0, 0, 0, 0, &imm);
        assert_eq!(tile.handle_attester_slashing(&buf), Feedback::Accept(None));
    }

    #[test]
    fn as_zero_intersection_with_valid_sigs_rejected() {
        let mut tile = make_tile();
        seed_tile_with_keys(&mut tile, 4, 0);
        let imm = seed_immutable(&tile);
        let ia1 = test_signing::build_indexed_attestation(0, 0, 0, 0, 0, 0xAA, &imm);
        let ia2 = test_signing::build_indexed_attestation(1, 1, 0, 0, 0, 0xBB, &imm);
        let buf = wrap_attester_slashing(&ia1, &ia2);
        assert_eq!(tile.handle_attester_slashing(&buf), Feedback::Reject(None));
    }

    #[test]
    fn bls_change_unknown_validator_ignored() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 0);
        let mut buf = [0u8; SIGNED_BLS_CHANGE_SIZE];
        buf[0..8].copy_from_slice(&999u64.to_le_bytes());
        assert_eq!(tile.handle_bls_to_execution_change(&buf), Feedback::Ignore);
    }

    #[test]
    fn bls_change_wrong_prefix_rejected() {
        let mut tile = make_tile();
        // Validator 0 has ETH1-prefixed credentials in the base; the
        // canonical head (anchor over the base) then rejects the change.
        let mut eth1 = Withdrawals([0u8; 32]);
        eth1.0[0] = 0x01;
        let seeds: Vec<ValSeed> = (0..4)
            .map(|i| ValSeed {
                pubkey: placeholder_pubkey(i),
                withdrawal_credentials: if i == 0 { eth1 } else { Withdrawals::default() },
                effective_balance: MAX_EFFECTIVE_BALANCE,
                balance: MAX_EFFECTIVE_BALANCE,
                activation_epoch: 0,
                ..Default::default()
            })
            .collect();
        let cp = Checkpoint { epoch: 0, root: ANCHOR_ROOT };
        let epoch_base = epoch_base_with(cp, cp);
        arm_tile(&mut tile, epoch_base, &seeds, 0);
        let buf = [0u8; SIGNED_BLS_CHANGE_SIZE]; // vi = 0
        assert_eq!(tile.handle_bls_to_execution_change(&buf), Feedback::Reject(None));
    }

    #[test]
    fn bls_change_accept() {
        let mut tile = make_tile();
        seed_tile_with_keys(&mut tile, 4, 0);
        let imm = seed_immutable(&tile);
        let to_addr = [0x42u8; 20];
        let buf = test_signing::sign_bls_to_execution_change(0, 0, &to_addr, &imm);
        assert_eq!(tile.handle_bls_to_execution_change(&buf), Feedback::Accept(None));
    }

    #[test]
    fn block_known_parent_bad_sig_rejected() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 128, 10);

        // Known latest_block_header → derive a realistic parent_root and
        // anchor fork choice on it.
        let genesis_header = BeaconBlockHeader {
            slot: 10,
            proposer_index: 0,
            parent_root: [0u8; 32],
            state_root: [0x01; 32],
            body_root: [0u8; 32],
        };
        {
            // Roll a fresh slot fork off the anchor with the known header set
            // on the writer, commit, and repoint the head bundle's slot index
            // — append-only, no re-open of the published anchor fork.
            let new_slot_idx = {
                let mut g = tile.state.write();
                let mut sw = g.slot_states.roll_from(tile.last_applied.slot_idx);
                sw.state_mut().latest_block_header = genesis_header;
                sw.commit()
            };
            tile.last_applied.slot_idx = new_slot_idx;
        }
        let parent_root = ssz_hash::hash_tree_root_block_header(&genesis_header);

        let cp = Checkpoint { epoch: 0, root: parent_root };
        tile.fork_choice =
            ForkChoice::init(cp, cp, 10, parent_root, parent_root, tile.last_applied);
        tile.last_applied_block_root = parent_root;

        // Valid structure, zeroed BLS signature → precheck reaches and fails
        // signature verification, so no fork-choice node is added.
        let mut buf = vec![0u8; 200];
        buf[100..108].copy_from_slice(&11u64.to_le_bytes()); // slot
        buf[108..116].copy_from_slice(&0u64.to_le_bytes()); // proposer_index
        buf[116..148].copy_from_slice(&parent_root); // parent_root

        tile.apply_block_impl(&buf, true, |_block_root| {});
        assert_eq!(tile.fork_choice.nodes.len(), 1);
    }

    // ── attestation / aggregate (committee resolution via shuffling cache) ──

    /// Locate `(slot, committee_index, pos_in_committee, committee_size)` for
    /// validator 0 in epoch 0. The seed arms exactly one cache entry per epoch.
    fn find_committee_for_vi0(tile: &BeaconStateTile) -> (Slot, usize, usize, usize) {
        let entry = tile
            .shuffling_cache
            .entries
            .iter()
            .find(|e| e.status == 1 && e.epoch == 0)
            .expect("shuffling for epoch 0");
        let committees_per_slot = shuffling::committees_per_slot(entry.shuffled_indices.len());
        for s in 0..SLOTS_PER_EPOCH {
            for ci in 0..committees_per_slot {
                let c = shuffling::get_beacon_committee(
                    entry.shuffled_indices.as_slice(),
                    s,
                    ci,
                    committees_per_slot,
                );
                if let Some(pos) = c.iter().position(|&v| v == 0) {
                    return (s, ci, pos, c.len());
                }
            }
        }
        panic!("validator 0 in some committee")
    }

    fn build_agg_for_vi0(tile: &BeaconStateTile) -> Vec<u8> {
        let imm = seed_immutable(tile);
        let beacon_block_root = tile.last_applied_block_root;
        let target_root = tile.last_applied_block_root;
        let (slot, ci, pos, csize) = find_committee_for_vi0(tile);
        test_signing::sign_aggregate_and_proof(
            0,
            0,
            slot,
            slot / SLOTS_PER_EPOCH,
            beacon_block_root,
            target_root,
            ci,
            pos,
            csize,
            &imm,
        )
    }

    #[test]
    fn attestation_updates_vote_tracker() {
        // Wall slot in the propagation window of the committee slot (mirrors
        // the aggregate tests) so the gossip slot-range check accepts.
        let mut tile = make_tile_at_wall_slot(31);
        seed_tile_with_keys(&mut tile, 128, 0);
        let (slot, ci, _, _) = find_committee_for_vi0(&tile);
        let imm = seed_immutable(&tile);
        let bbr = [0xAAu8; 32];
        let buf = test_signing::sign_single_attestation(
            0,
            0,
            ci as u64,
            slot,
            bbr,
            slot / SLOTS_PER_EPOCH,
            &imm,
        );
        // Assert against what the handler reads via the view (the view owns
        // the offsets), verifying the vote fold self-consistently.
        let want_root = *SingleAttestationView::beacon_block_root(&buf);
        let want_epoch = SingleAttestationView::target_epoch(&buf);
        assert_eq!(tile.handle_attestation(&buf), Feedback::Accept(None));
        assert_eq!(tile.vote_tracker.votes[0].next_root, want_root);
        assert_eq!(tile.vote_tracker.votes[0].next_epoch, want_epoch);
    }

    #[test]
    fn agg_multi_committee_bits_rejected() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 0);
        let mut buf = vec![0u8; SIGNED_AGG_PROOF_MIN];
        buf[436] = 0b0000_0011; // two committee bits
        assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Reject(None));
    }

    #[test]
    fn agg_unknown_block_root_ignored() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 0);
        let mut buf = vec![0u8; SIGNED_AGG_PROOF_MIN];
        buf[436] = 0b0000_0001; // single committee bit
        buf[228] = 0xFF; // beacon_block_root not in fork choice
        assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Ignore);
    }

    #[test]
    fn agg_accept() {
        let mut tile = make_tile_at_wall_slot(31);
        seed_tile_with_keys(&mut tile, 128, 0);
        let buf = build_agg_for_vi0(&tile);
        let beacon_block_root = tile.last_applied_block_root;
        let slot = SignedAggregateAndProofView::agg_slot(&buf);
        assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Accept(None));
        assert_eq!(tile.vote_tracker.votes[0].next_root, beacon_block_root);
        assert_eq!(tile.vote_tracker.votes[0].next_epoch, slot / SLOTS_PER_EPOCH);
    }

    #[test]
    fn agg_respects_epoch_monotonicity() {
        let mut tile = make_tile_at_wall_slot(31);
        seed_tile_with_keys(&mut tile, 128, 0);

        let preset_root = [0x99u8; 32];
        tile.vote_tracker.votes[0].next_root = preset_root;
        tile.vote_tracker.votes[0].next_epoch = 1;

        let buf = build_agg_for_vi0(&tile);
        assert_eq!(SignedAggregateAndProofView::agg_target_epoch(&buf), 0);
        assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Accept(None));

        // Older-epoch aggregate must not overwrite the newer vote.
        assert_eq!(tile.vote_tracker.votes[0].next_root, preset_root);
        assert_eq!(tile.vote_tracker.votes[0].next_epoch, 1);
    }

    #[test]
    fn agg_slot_too_old_ignored() {
        let mut tile = make_tile_at_wall_slot(100);
        seed_tile_with_keys(&mut tile, 128, 0);
        let buf = build_agg_for_vi0(&tile);
        assert!(
            SignedAggregateAndProofView::agg_slot(&buf) < 100 - ATTESTATION_PROPAGATION_SLOT_RANGE
        );
        assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Ignore);
    }

    #[test]
    fn agg_slot_too_future_ignored() {
        let mut tile = make_tile_at_wall_slot(0);
        seed_tile(&mut tile, 128, 0);
        let mut buf = vec![0u8; SIGNED_AGG_PROOF_MIN];
        buf[436] = 0b0000_0001;
        buf[212] = 5; // slot = 5 > wall (0)
        assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Ignore);
    }

    #[test]
    fn agg_committee_index_oor_rejected() {
        let mut tile = make_tile_at_wall_slot(31);
        seed_tile_with_keys(&mut tile, 128, 0);
        let mut buf = build_agg_for_vi0(&tile);
        for i in 0..8 {
            buf[436 + i] = 0;
        }
        buf[436] = 0b0000_0010; // committee_index 1, OOR for committees_per_slot=1
        assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Reject(None));
    }

    #[test]
    fn agg_is_aggregator_false_rejected() {
        let mut tile = make_tile_at_wall_slot(31);
        seed_tile_with_keys(&mut tile, 1024, 0);
        let mut buf = build_agg_for_vi0(&tile);
        let (_, _, _, csize) = find_committee_for_vi0(&tile);
        assert_eq!(csize, 32, "committee_len drives the aggregator modulo");

        let sp_off = 112usize;
        let mut sig_arr: [u8; 96] = buf[sp_off..sp_off + 96].try_into().unwrap();
        let mut b: u16 = 0;
        loop {
            sig_arr[0] = b as u8;
            if !is_aggregator(csize, &sig_arr) {
                break;
            }
            b += 1;
            assert!(b < 256, "no parity-flipping byte found (impossible)");
        }
        buf[sp_off..sp_off + 96].copy_from_slice(&sig_arr);
        assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Reject(None));
    }

    // ── finalization (deposit append lands on the delta, not the base) ──

    /// A `PendingDeposit` for a brand-new validator (spec key 0), signed under
    /// the genesis deposit domain (fork version + gvr both zero).
    fn signed_new_validator_deposit() -> (BLSPubkey, PendingDeposit) {
        const DOMAIN_DEPOSIT: u32 = 0x03;
        let pk = test_signing::pubkey_bytes(0);
        let wc = Withdrawals([0xAAu8; 32]);
        let amount = 32_000_000_000u64;

        let msg_root = ssz_hash::merkleize(&[
            ssz_hash::hash_fixed_bytes(&pk),
            wc.0,
            ssz_hash::uint64_chunk(amount),
        ]);
        let domain = bls::compute_domain(DOMAIN_DEPOSIT, [0; 4], &[0u8; 32]);
        let signing_root = bls::compute_signing_root(&msg_root, &domain);
        let sig = test_signing::sign(0, &signing_root);

        (pk, PendingDeposit {
            pubkey: pk,
            withdrawal_credentials: wc,
            amount,
            signature: sig,
            slot: 0,
        })
    }

    /// Speculative validator appends from deposit processing must land on the
    /// head fork's `validators` delta, not on the shared finalized base —
    /// the base only advances at Casper finality.
    #[test]
    fn epoch_transition_keeps_base_until_finality() {
        let mut tile = make_tile();
        // Arm with epoch 1 already finalized in the base (finality lives in the
        // base, so this is equivalent to advancing it — and avoids mutating the
        // published base mid-test) so slot-0 deposits are eligible.
        let (_eb, seeds) = build_seed_finalized(1, false);
        let epoch_base = epoch_base_with(Checkpoint { epoch: 0, root: ANCHOR_ROOT }, Checkpoint {
            epoch: 1,
            root: ANCHOR_ROOT,
        });
        arm_tile(&mut tile, epoch_base, &seeds, 0);

        let (pk, deposit) = signed_new_validator_deposit();
        // Queue the deposit append-only: roll a fresh pending fork off the
        // head, push, and repoint the head bundle at the committed id.
        tile.last_applied.pending_idx = {
            let mut g = tile.state.write();
            let mut pw = g.pending.roll_from(tile.last_applied.pending_idx);
            pw.push_pending_deposit(deposit);
            pw.commit()
        };

        tile.on_slot_start(SLOTS_PER_EPOCH);

        // Base unchanged; the new validator lives on the head fork's delta.
        assert_eq!(
            tile.state.state().validators.finalized().validator_count(),
            1,
            "base must wait for finality"
        );
        let head_validators = tile.state.state().validators.view(tile.last_applied.validators_idx);
        assert_eq!(head_validators.count(), 2);
        assert_eq!(*head_validators.pubkey(1), pk);
    }

    /// `maybe_finalize` with `fin_idx > 0` must (a) promote the finalized
    /// delta into the base, (b) prune non-descendant siblings from fork
    /// choice, (c) re-base the surviving descendant's cumulative edits against
    /// the new base, and (d) hand the survivor its re-anchored bundle. This is
    /// the only place the survivor re-base path is exercised — single-fork
    /// tests take the no-promote branch (`fin_idx == 0`).
    #[test]
    fn multi_fork_finalize_promotes_and_rebases() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 0);
        let anchor_id = tile.last_applied;

        const F_ROOT: B256 = [0x0F; 32];
        const D_ROOT: B256 = [0x0D; 32];
        const F2_ROOT: B256 = [0xF2; 32];
        const ZERO_CP: Checkpoint = Checkpoint { epoch: 0, root: [0u8; 32] };
        let f_cp = Checkpoint { epoch: 0, root: F_ROOT };

        // Roll a slot-group fork off `parent` with a slot number + one
        // cumulative block root set on the writer, then commit — the
        // writer→commit path (no in-place re-open). `reset_from` carries the
        // parent's root tail, so a child appends onto it.
        let roll_slot = |st: &mut BeaconStateOwner, parent: SlotStateId, slot: Slot, root: B256| {
            let mut g = st.write();
            let mut sw = g.slot_states.roll_from(parent);
            sw.state_mut().slot = slot;
            sw.push_block_root(root);
            sw.commit()
        };
        let roll_balances = |st: &mut BeaconStateOwner, parent| {
            let mut g = st.write();
            g.balances.roll_from(parent).commit()
        };

        // F: child of anchor (to be finalized). One cumulative `block_root`.
        // Each fork's bundle copies its parent's and re-points the rolled
        // tiers (slot + balances here, the others shared for this test).
        let f_id = StateId {
            balances_idx: roll_balances(&mut tile.state, anchor_id.balances_idx),
            slot_idx: roll_slot(&mut tile.state, anchor_id.slot_idx, 1, F_ROOT),
            ..anchor_id
        };

        // D: child of F (head, survives). Inherits F's block_roots via
        // `reset_from`, appends its own → [F_ROOT, D_ROOT].
        let d_id = StateId {
            balances_idx: roll_balances(&mut tile.state, f_id.balances_idx),
            slot_idx: roll_slot(&mut tile.state, f_id.slot_idx, 2, D_ROOT),
            ..f_id
        };

        // F2: sibling of F (will be pruned by fork choice).
        let f2_id = StateId {
            balances_idx: roll_balances(&mut tile.state, anchor_id.balances_idx),
            slot_idx: roll_slot(&mut tile.state, anchor_id.slot_idx, 1, F2_ROOT),
            ..anchor_id
        };

        // Insert F2 first so its idx is below F's — fork choice's `prune`
        // only drops the prefix below the finalized node, so the sibling has
        // to live ahead of the to-be-finalized node to be reclaimed.
        tile.fork_choice.on_block(BlockImport {
            slot: 1,
            block_root: F2_ROOT,
            parent_root: ANCHOR_ROOT,
            state_root: [0u8; 32],
            execution_block_hash: [0u8; 32],
            justified: ZERO_CP,
            finalized: ZERO_CP,
            state_id: f2_id,
        });
        tile.fork_choice.on_block(BlockImport {
            slot: 1,
            block_root: F_ROOT,
            parent_root: ANCHOR_ROOT,
            state_root: [0u8; 32],
            execution_block_hash: [0u8; 32],
            justified: f_cp,
            finalized: f_cp,
            state_id: f_id,
        });
        tile.fork_choice.on_block(BlockImport {
            slot: 2,
            block_root: D_ROOT,
            parent_root: F_ROOT,
            state_root: [0u8; 32],
            execution_block_hash: [0u8; 32],
            justified: f_cp,
            finalized: f_cp,
            state_id: d_id,
        });

        // Head is D; finality target is F.
        tile.last_applied = d_id;
        tile.last_applied_block_root = D_ROOT;
        tile.fork_choice.finalized_checkpoint = f_cp;
        // Republish so the seqlock control matches the new head.
        tile.state.publish_state_id(d_id);

        // Sanity: pre-finalize state.
        assert_eq!(tile.state.state().slot_states.finalized_view().slot_number(), 0);
        let d_slot_view = tile.state.state().slot_states.view(d_id.slot_idx);
        assert_eq!(d_slot_view.delta_block_roots(), [F_ROOT, D_ROOT]);
        assert!(tile.fork_choice.find_node_idx(&F2_ROOT).is_some());

        tile.maybe_finalize();

        // (a) Base advanced to F's slot scalars; F's block_root landed in the
        //     circular buffer at the old finalized slot offset.
        let base = tile.state.state().slot_states.finalized_view();
        assert_eq!(base.slot_number(), 1, "base slot promoted to F's slot");
        assert_eq!(
            base.finalized_block_roots()[0],
            F_ROOT,
            "F's block_root in base circular buffer"
        );

        // (b) F2 pruned from fork choice; F is now node 0 (anchor); D survives.
        assert!(tile.fork_choice.find_node_idx(&F2_ROOT).is_none(), "F2 dropped");
        assert_eq!(tile.fork_choice.find_node_idx(&F_ROOT), Some(0), "F is the new anchor");
        let d_node = tile.fork_choice.find_node_idx(&D_ROOT).expect("D survives");

        // (c) D's cumulative `block_roots` log re-based against the new base:
        //     F's prefix drained, only D's incremental entry remains. Finalize
        //     re-anchored D into a fresh slot fork, so re-read its bundle from
        //     the fork-choice node.
        let d_rebased = tile.fork_choice.node(d_node).state_id;
        let d_slot_view = tile.state.state().slot_states.view(d_rebased.slot_idx);
        assert_eq!(
            d_slot_view.delta_block_roots(),
            [D_ROOT],
            "D's block_roots drained of F's prefix"
        );

        // (d) D was the head, so `last_applied` got the same re-anchored
        //     bundle (not the stale pre-finalize one).
        assert_eq!(tile.last_applied, d_rebased, "head bundle refreshed");
        assert_ne!(tile.last_applied, d_id, "stale head bundle replaced");
    }

    // ── fork_digest (standalone `compute_fork_digest`, no tile state) ──

    const FD_SENTINEL: BlobParameters = BlobParameters { epoch: u64::MAX, max_blobs_per_block: 0 };

    fn fd_genesis_validators_root(b: u8) -> B256 {
        [b; 32]
    }

    fn fd_ef_schedule() -> [BlobParameters; 6] {
        [
            BlobParameters { epoch: 9, max_blobs_per_block: 9 },
            BlobParameters { epoch: 100, max_blobs_per_block: 100 },
            BlobParameters { epoch: 150, max_blobs_per_block: 175 },
            BlobParameters { epoch: 200, max_blobs_per_block: 200 },
            BlobParameters { epoch: 250, max_blobs_per_block: 275 },
            BlobParameters { epoch: 300, max_blobs_per_block: 300 },
        ]
    }

    fn fd_ef_digest(epoch: Epoch, fork_version: Version, gvr: &B256) -> [u8; 4] {
        let schedule = fd_ef_schedule();
        let bp = get_blob_parameters(epoch, &schedule, FD_SENTINEL);
        compute_fork_digest(fork_version, gvr, Some(bp))
    }

    #[test]
    fn ef_compute_fork_digest_vectors() {
        let v6 = [0x06, 0x00, 0x00, 0x00];
        let v61 = [0x06, 0x00, 0x00, 0x01];
        let v7 = [0x07, 0x00, 0x00, 0x00];
        let v71 = [0x07, 0x00, 0x00, 0x01];

        let cases: &[(Epoch, Version, B256, [u8; 4])] = &[
            (9, v6, fd_genesis_validators_root(0), [0xab, 0x3a, 0xe6, 0xc8]),
            (10, v6, fd_genesis_validators_root(0), [0xab, 0x3a, 0xe6, 0xc8]),
            (11, v6, fd_genesis_validators_root(0), [0xab, 0x3a, 0xe6, 0xc8]),
            (99, v6, fd_genesis_validators_root(0), [0xab, 0x3a, 0xe6, 0xc8]),
            (100, v6, fd_genesis_validators_root(0), [0xdf, 0x67, 0x55, 0x7b]),
            (101, v6, fd_genesis_validators_root(0), [0xdf, 0x67, 0x55, 0x7b]),
            (150, v6, fd_genesis_validators_root(0), [0x8a, 0xb3, 0x8b, 0x59]),
            (199, v6, fd_genesis_validators_root(0), [0x8a, 0xb3, 0x8b, 0x59]),
            (200, v6, fd_genesis_validators_root(0), [0xd9, 0xb8, 0x14, 0x38]),
            (201, v6, fd_genesis_validators_root(0), [0xd9, 0xb8, 0x14, 0x38]),
            (250, v6, fd_genesis_validators_root(0), [0x4e, 0xf3, 0x2a, 0x62]),
            (299, v6, fd_genesis_validators_root(0), [0x4e, 0xf3, 0x2a, 0x62]),
            (300, v6, fd_genesis_validators_root(0), [0xca, 0x10, 0x0d, 0x64]),
            (301, v6, fd_genesis_validators_root(0), [0xca, 0x10, 0x0d, 0x64]),
            (9, v6, fd_genesis_validators_root(1), [0x89, 0x67, 0x11, 0x11]),
            (9, v6, fd_genesis_validators_root(2), [0xf4, 0x9b, 0x0e, 0x24]),
            (9, v6, fd_genesis_validators_root(3), [0x86, 0x54, 0x4e, 0x4f]),
            (100, v6, fd_genesis_validators_root(1), [0xfd, 0x3a, 0xa2, 0xa2]),
            (100, v6, fd_genesis_validators_root(2), [0x80, 0xc6, 0xbd, 0x97]),
            (100, v6, fd_genesis_validators_root(3), [0xf2, 0x09, 0xfd, 0xfc]),
            (9, v61, fd_genesis_validators_root(0), [0x30, 0xf8, 0xc2, 0x5b]),
            (9, v7, fd_genesis_validators_root(0), [0x04, 0x32, 0xf5, 0xa9]),
            (9, v71, fd_genesis_validators_root(0), [0x6e, 0x69, 0xa6, 0x71]),
            (100, v61, fd_genesis_validators_root(0), [0x44, 0xa5, 0x71, 0xe8]),
            (100, v7, fd_genesis_validators_root(0), [0x70, 0x6f, 0x46, 0x1a]),
            (100, v71, fd_genesis_validators_root(0), [0x1a, 0x34, 0x15, 0xc2]),
        ];

        for (epoch, fv, g, expected) in cases {
            let got = fd_ef_digest(*epoch, *fv, g);
            assert_eq!(
                got, *expected,
                "epoch={epoch} fv={fv:02x?} gvr[0]={:#04x}: got {got:02x?}, want {expected:02x?}",
                g[0]
            );
        }
    }

    #[test]
    fn mainnet_fulu_fork_digest_419072() {
        let mainnet_gvr: B256 = [
            0x4b, 0x36, 0x3d, 0xb9, 0x4e, 0x28, 0x61, 0x20, 0xd7, 0x6e, 0xb9, 0x05, 0x34, 0x0f,
            0xdd, 0x4e, 0x54, 0xbf, 0xe9, 0xf0, 0x6b, 0xf3, 0x3f, 0xf6, 0xcf, 0x5a, 0xd2, 0x7f,
            0x51, 0x1b, 0xfe, 0x95,
        ];
        let spec = SpecConfig::mainnet();
        let bp = get_blob_parameters(419072, &spec.blob_schedule, spec.default_blob_params());
        assert_eq!(bp, BlobParameters { epoch: 419072, max_blobs_per_block: 21 });

        let digest = compute_fork_digest(spec.fulu_fork_version, &mainnet_gvr, Some(bp));
        assert_eq!(digest, [0x8c, 0x9f, 0x62, 0xfe]);
    }
}
