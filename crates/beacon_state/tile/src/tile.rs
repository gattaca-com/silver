use flux::{
    spine::{FluxSpine, SpineAdapter, SpineProducers},
    tile::Tile,
    utils::ArrayVec,
};
use rustc_hash::FxHashMap;
use silver_beacon_state_data::{
    B256, BeaconBlockHeader, BeaconState, BeaconStateOwner, BlobParameters, Checkpoint,
    EPOCHS_PER_HISTORICAL_VECTOR, EPOCHS_RING_N, Epoch, LONGTAILS_RING_N, MIN_SEED_LOOKAHEAD,
    PROPOSER_LOOKAHEAD_SIZE, PendingQueuesOldBaseLens, SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT,
    SLOTS_RING_N, Slot, SlotStateDelta, SpecConfig, StateDelta, StateDeltaReadView, StateDeltaView,
    ValidatorsDelta, Version, buffer::RollResult,
};
use silver_common::{
    BeaconStateEvent, GossipTopic, NewGossipMsg, P2pStreamId, PeerEvent, RejectSource, RpcInbound,
    RpcMsg, RpcResponse, RpcResponseInbound, RpcSeverity, SilverSpine, SyncUpdate, TCacheRead,
    TRandomAccess, TRead,
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
    epoch_transition::{EPOCHS_PER_SYNC_COMMITTEE_PERIOD, MAX_PENDING_DEPOSITS_PER_EPOCH},
    error::PrecheckError,
    fork_choice::{BlockImport, ForkChoice, VoteTracker, compute_deltas},
    shuffling::{self, DOMAIN_BEACON_ATTESTER},
    ssz_hash, state_transition, validate,
};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
}

struct ParsedBlock {
    block_slot: Slot,
    proposer_index: u64,
    parent_root: B256,
    state_root: B256,
    body_root: B256,
    block_root: B256,
    /// Slots-ring seq of the parent block's post-state delta.
    parent_seq: usize,
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

    spec: SpecConfig,

    /// Canonical in-process state: finalized base + per-fork `StateDelta`
    /// rings. Other tiles read via `state.reader()` (raw-ptr + seqlock).
    state: BeaconStateOwner,

    fork_choice: ForkChoice,
    vote_tracker: Box<VoteTracker>,
    shuffling_cache: Box<ShufflingCache>,

    /// Slots-ring seq of the canonical head's post-state `StateDelta`.
    last_applied: usize,
    last_applied_block_root: B256,

    initial_status_emitted: bool,
    cached_fork_digest: Option<(Epoch, [u8; 4])>,
    /// Operator-configured fork digest. Used in lieu of a computed digest
    /// while the state is uninitialized (no checkpoint, pre-sync → zero
    /// `gvr`), so silver advertises the right digest instead of one derived
    /// from an all-zero genesis-validators-root.
    configured_fork_digest: Option<[u8; 4]>,

    postponed_scratch: Vec<silver_beacon_state_data::PendingDeposit>,
    /// Per-block buffer of (validator_idx, beacon_block_root, target_epoch)
    /// emitted by `process_attestations` so the tile can fold them into the
    /// vote tracker after `apply_block` returns.
    attestation_votes_scratch: Vec<(u32, B256, Epoch)>,
    /// Epoch transition uses this
    /// for the active set (`process_sync_committee_updates` /
    /// `process_proposer_lookahead`); pass 1 of `process_block_body` reuses
    /// it for committee participants in `collect_sigs_*`; pass 2 reuses it
    /// again for participating indices in `process_single_attestation`.
    active_scratch: Vec<u32>,
    /// Reusable epoch-transition scratch buffers (sparse-edit rebuilds +
    /// effective-balance column) — threaded into `process_epoch`.
    replace_u64_scratch: Vec<(u32, u64)>,
    replace_u8_scratch: Vec<(u32, u8)>,
    eff_scratch: Vec<u64>,
    /// Effective-balance column from the previous `recompute_head`, kept so
    /// `compute_deltas` can net per-validator balance changes onto LMD weights
    /// (not just vote-root changes). Indexed by validator; new validators read
    /// as 0 (no prior weight).
    prev_eff_balances: Vec<u64>,
    /// Pre-validation pass collects every BLS sig in the block here, then
    /// runs `verify_all` once before pass 2 mutates state.
    sig_batch: bls::SigBatch,
    /// Reusable merged-ring buffers for `hash_tree_root_state` (block/state
    /// roots, randao, slashings) — avoids re-allocating the rings per slot.
    state_hash_scratch: ssz_hash::StateHashScratch,
    /// Pending blocks - blocks we have received for which we do not have a
    /// parent block. Keyed by the parent block_hash.
    pending_blocks: FxHashMap<B256, Vec<PendingBlock>>,

    gossip_consumer: TRandomAccess,
    rpc_consumer: TRandomAccess,
}

type Producers = <SilverSpine as FluxSpine>::Producers;

impl BeaconStateTile {
    /// If `checkpoint_state` is non-empty, bootstraps immediately; otherwise
    /// starts inert in `Mode::Syncing` (call `bootstrap` before the loop).
    pub fn new(
        ticker: SlotTicker,
        spec: SpecConfig,
        state: BeaconStateOwner,
        gossip_consumer: TRandomAccess,
        rpc_consumer: TRandomAccess,
        checkpoint_state: &[u8],
    ) -> Self {
        let val_cap = state.state().finalized.validators.capacity();
        let mut tile = Self {
            // Boot in Syncing. PM's first `SyncUpdate::Following` flips us
            // once peer Status data confirms we're caught up.
            mode: Mode::Syncing,
            ticker,
            spec,
            state,
            fork_choice: ForkChoice::default(),
            vote_tracker: VoteTracker::with_capacity(val_cap),
            shuffling_cache: ShufflingCache::with_capacity(val_cap),
            last_applied: 0,
            last_applied_block_root: [0u8; 32],
            initial_status_emitted: false,
            cached_fork_digest: None,
            active_scratch: Vec::with_capacity(val_cap.max(MAX_ATTESTING_INDICES)),
            configured_fork_digest: None,
            postponed_scratch: Vec::with_capacity(MAX_PENDING_DEPOSITS_PER_EPOCH),
            attestation_votes_scratch: Vec::with_capacity(
                MAX_ATTESTATIONS_ELECTRA * MAX_ATTESTING_INDICES,
            ),
            replace_u64_scratch: Vec::with_capacity(val_cap),
            replace_u8_scratch: Vec::with_capacity(val_cap),
            eff_scratch: Vec::with_capacity(val_cap),
            prev_eff_balances: Vec::with_capacity(val_cap),
            sig_batch: bls::SigBatch::new(),
            state_hash_scratch: ssz_hash::StateHashScratch::new(),
            pending_blocks: FxHashMap::default(),
            gossip_consumer,
            rpc_consumer,
        };

        if !checkpoint_state.is_empty() {
            tile.bootstrap(checkpoint_state);
        }
        tile
    }

    pub fn head_block_root(&self) -> B256 {
        self.last_applied_block_root
    }

    pub fn fork_choice_head(&self) -> B256 {
        self.fork_choice.find_head()
    }

    pub fn head_state_slot(&self) -> Slot {
        self.state.state().slots.get(self.last_applied).slot.slot.slot
    }

    pub fn head_validator_count(&self) -> usize {
        let d = self.state.state().slots.get(self.last_applied);
        d.validators.base_count + d.validators.appended.len()
    }

    /// `(current_justified, finalized)` as seen by the canonical head's
    /// post-state. Reads the epoch delta if the head fork owns one; otherwise
    /// falls back to the finalized base epoch state.
    fn head_checkpoints(&self) -> (Checkpoint, Checkpoint) {
        let bs = self.state.state();
        let d = bs.slots.get(self.last_applied);
        let es = match d.epoch_idx {
            Some(s) => &bs.epochs.get(s).state,
            None => &bs.finalized.epoch.state,
        };
        (es.current_justified_checkpoint, es.finalized_checkpoint)
    }

    fn head_finalized_checkpoint(&self) -> Checkpoint {
        self.head_checkpoints().1
    }

    pub fn try_apply_block(&mut self, data: &[u8]) -> Feedback {
        self.handle_block(data)
    }

    /// SSZ `hash_tree_root` of the most-recently-applied block's full
    /// BeaconState. Used by integration tests to cross-check tile-applied
    /// STF output against EF post-state vectors.
    pub fn head_state_root(&mut self) -> B256 {
        let seq = self.last_applied;
        let view = self.state.delta_view(seq);
        ssz_hash::hash_tree_root_state(&view, &mut self.state_hash_scratch)
    }

    /// Load a checkpoint-state SSZ blob: decompose it into the finalized
    /// base, anchor a genesis slot delta on top (empty edits, full slot
    /// scalars seeded from the base), and seed fork choice with the trusted
    /// anchor checkpoint.
    fn bootstrap(&mut self, ssz: &[u8]) {
        let seq;
        let slot;
        {
            let mut guard = self.state.write();
            let bs: &mut BeaconState = &mut guard;
            bs.finalized
                .decompose(ssz, &self.spec)
                .unwrap_or_else(|e| panic!("bootstrap: decompose failed: {e}"));
            slot = bs.finalized.slot.slot.slot;

            // Anchor an empty per-fork delta on the freshly decoded base.
            seq = match bs.slots.roll(None) {
                RollResult::Reset(s) | RollResult::Rolled(s) => s,
            };
            let validators = ValidatorsDelta::new_at(&bs.finalized.validators);
            let sd = bs.slots.get_mut(seq);
            sd.validators = validators;
            sd.slot = SlotStateDelta { slot: bs.finalized.slot.slot, ..Default::default() };
        }

        // Fresh state is correct here — nothing predates the anchor.
        let cap = self.state.state().finalized.validators.capacity();
        self.vote_tracker = VoteTracker::with_capacity(cap);
        self.shuffling_cache = ShufflingCache::with_capacity(cap);

        // Anchor block root. Compute on a local header copy so the state's
        // `latest_block_header.state_root` stays `[0;32]` — the first
        // post-bootstrap `process_slot` hashes that canonical state and a
        // patched value would shift the result.
        let (block_root, anchor_state_root) = {
            let view = self.state.delta_view(seq);
            let state_root = ssz_hash::hash_tree_root_state(&view, &mut self.state_hash_scratch);
            let mut header = view.latest_block_header();
            if header.state_root == [0u8; 32] {
                header.state_root = state_root;
            }
            (ssz_hash::hash_tree_root_block_header(&header), state_root)
        };

        let trusted = Checkpoint { epoch: slot / SLOTS_PER_EPOCH, root: block_root };
        self.last_applied = seq;
        self.last_applied_block_root = block_root;
        self.fork_choice =
            ForkChoice::init(trusted, trusted, slot, block_root, anchor_state_root, seq);
        self.state.publish_offsets(None, Some(seq));
    }

    /// Slots-ring seq of fork-choice's canonical tip. For gossip-object
    /// validation per spec ("the head state").
    fn canonical_state_seq(&self) -> usize {
        let head_root = self.fork_choice.find_head();
        let idx = self
            .fork_choice
            .find_node_idx(&head_root)
            .expect("find_head returns a node-resident root");
        self.fork_choice.node(idx).state_seq
    }

    /// Seed-epoch randao mix that keys an epoch's attester shuffling (the
    /// single `randao_mixes[]` slot driving `get_seed(_, epoch, ATTESTER)`).
    fn shuffling_mix(view: &StateDeltaView, epoch: Epoch) -> B256 {
        let mix_epoch = epoch + EPOCHS_PER_HISTORICAL_VECTOR as u64 - MIN_SEED_LOOKAHEAD - 1;
        view.randao_mix_at_epoch(mix_epoch)
    }

    /// Compute and cache the attester shuffling for `epoch` against the post-
    /// state at ring seq `seq`. No-op if already cached. Maintain the 2-epoch
    /// window: attestations with `target_epoch ∈ {epoch, epoch - 1}` resolve
    /// their committee against both.
    fn ensure_shuffling_window(&mut self, epoch: Epoch, seq: usize) {
        self.ensure_shuffling(epoch, seq);
        if epoch > 0 {
            self.ensure_shuffling(epoch - 1, seq);
        }
    }

    fn ensure_shuffling(&mut self, epoch: Epoch, seq: usize) {
        let mix = {
            let view = self.state.delta_view(seq);
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

        self.active_scratch.clear();
        {
            let view = self.state.delta_view(seq);
            shuffling::get_active_validator_indices_into(&view, epoch, &mut self.active_scratch);
        }
        let seed = shuffling::get_seed(&mix, epoch, DOMAIN_BEACON_ATTESTER);
        shuffling::shuffle_list(&mut self.active_scratch, &seed);

        let slot = self.find_shuffling_slot();
        let entry = &mut self.shuffling_cache.entries[slot];
        entry.epoch = epoch;
        entry.mix = mix;
        entry.status = 1;
        entry.shuffled_indices.clear();
        for &idx in self.active_scratch.iter() {
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
        seq: usize,
        block_epoch: Epoch,
    ) -> state_transition::ShufflingRef<'a> {
        let prev_epoch = block_epoch.saturating_sub(1);
        let (curr_mix, prev_mix) = {
            let view = state.delta_view(seq);
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

        let gvr = self.state.state().finalized.immutable.genesis_validators_root;
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
            None => {
                let d = self.state.state().slots.get(self.last_applied);
                (d.slot.slot.latest_block_header.slot, self.head_finalized_checkpoint())
            }
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
        self.state.state().slots.get(self.last_applied).slot.slot.latest_block_header.slot
    }

    fn status_event(&mut self) -> BeaconStateEvent {
        BeaconStateEvent::Status {
            ssz: self.status_payload(),
            latest_block_slot: self.last_applied_block_slot(),
        }
    }

    /// Post-import emission: PersistBlock (for storage) + Status (head and
    /// possibly finalized just moved). Called after `handle_block` returns
    /// `GossipFeedback::Accept` from gossip or RPC range/root response paths.
    fn apply_block(
        &mut self,
        data: &[u8],
        data_tcache: TRead,
        source: RejectSource,
        producers: &mut Producers,
    ) -> Feedback {
        let block_slot = SignedBeaconBlockView::slot(data);
        let prev_last_applied = self.last_applied;
        let prev_finalized = self.head_finalized_checkpoint();

        let f = self.handle_block(data);
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

        producers.produce(BeaconStateEvent::PersistBlock(*data_tcache));

        let head_changed = self.last_applied != prev_last_applied;
        let finalized_changed = self.head_finalized_checkpoint() != prev_finalized;
        if head_changed || finalized_changed {
            producers.produce(self.status_event());
        }
        f
    }

    /// Returns `true` iff at least one slot was processed (so head_slot
    /// definitely advanced, and finalized may have advanced via an epoch
    /// transition along the way).
    fn on_slot_start(&mut self, target_slot: Slot) -> bool {
        let curr_slot = self.state.state().slots.get(self.last_applied).slot.slot.slot;
        if target_slot <= curr_slot {
            return false;
        }

        // Advance on an unpublished child of the head — the published head is
        // resolved lock-free by readers and must not be mutated in place.
        // `process_slots` runs the per-slot loop and any epoch transitions
        // crossed, recording the epoch-ring seq on the delta's `epoch_idx`.
        //
        // `cow_state_for_block` gives the child private epoch/longtail deltas
        // when the advance crosses an epoch boundary. Mandatory: `process_epoch`
        // shifts `proposer_lookahead` in place, and `self.last_applied` is a
        // live fork-choice node that sibling blocks build on and the proposer
        // precheck reads. Mutating its shared epoch delta would leave that node
        // with a next-epoch `proposer_lookahead` shifted one epoch too far.
        let curr_epoch = curr_slot / SLOTS_PER_EPOCH;
        let target_epoch = target_slot / SLOTS_PER_EPOCH;
        let new_seq = self.cow_state_for_block(self.last_applied, target_epoch, curr_epoch);
        {
            let mut view = self.state.delta_view(new_seq);
            state_transition::process_slots(
                &self.spec,
                &mut view,
                target_slot,
                &mut self.active_scratch,
                &mut self.postponed_scratch,
                &mut self.replace_u64_scratch,
                &mut self.replace_u8_scratch,
                &mut self.eff_scratch,
                &mut self.state_hash_scratch,
            );
        }
        let epoch_off = self.state.state().slots.get(new_seq).epoch_idx;
        self.last_applied = new_seq;
        self.state.publish_offsets(epoch_off, Some(new_seq));
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

    /// Promote the fork-choice-finalized node's `StateDelta` into the
    /// `Finalized` base, re-base every surviving descendant delta against the
    /// new base, and reclaim orphaned ring slots. No-op until finality
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
        let promoted_seq = self.fork_choice.finalize_node(fin_idx);

        // Drop non-descendants of the finalized block; the survivors (node 0
        // is now the finalized block) are exactly the deltas to re-base.
        self.fork_choice.prune();
        let mut survivors: ArrayVec<usize, SLOTS_RING_N> = ArrayVec::new();
        survivors.extend(self.fork_choice.live_state_seqs());

        // `on_slot_start` advances the head across empty slots into a fresh
        // ring slot that is never registered as a fork-choice node. It is
        // still a live descendant of the finalized base, so it must be
        // re-based too — otherwise its `base_count` goes stale and the next
        // `delta_view` on it (or a roll from it) trips the base-mirror assert.
        if !survivors.as_slice().contains(&self.last_applied) {
            // Cannot overflow: live nodes occupy distinct ring slots, so a full
            // `survivors` (== SLOTS_RING_N) means every slot is a node and
            // `last_applied` would have matched above.
            debug_assert!(survivors.len() < SLOTS_RING_N, "survivors full, last_applied absent");
            survivors.push(self.last_applied);
        }

        // Unique epoch / longtail ring entries referenced by survivors, so
        // each cumulative log is re-based exactly once when siblings share it.
        let mut epoch_idxs: ArrayVec<usize, EPOCHS_RING_N> = ArrayVec::new();
        let mut longtail_idxs: ArrayVec<usize, LONGTAILS_RING_N> = ArrayVec::new();
        {
            let bs = self.state.state();
            for &seq in survivors.iter() {
                let d = bs.slots.get(seq);
                if let Some(e) = d.epoch_idx &&
                    !epoch_idxs.as_slice().contains(&e)
                {
                    epoch_idxs.push(e);
                }
                if let Some(l) = d.longtail_idx &&
                    !longtail_idxs.as_slice().contains(&l)
                {
                    longtail_idxs.push(l);
                }
            }
        }

        self.promote_and_rebase(
            promoted_seq,
            survivors.as_slice(),
            epoch_idxs.as_slice(),
            longtail_idxs.as_slice(),
        );

        // Reclaim ring slots below the oldest surviving seq in each tier.
        if let Some(&min_slot) = survivors.as_slice().iter().min() {
            self.state.slots().free(min_slot);
        }
        if let Some(&min_epoch) = epoch_idxs.as_slice().iter().min() {
            self.state.epochs().free(min_epoch);
        }
        if let Some(&min_longtail) = longtail_idxs.as_slice().iter().min() {
            self.state.longtails().free(min_longtail);
        }

        let fin_slot = self.fork_choice.finalized_checkpoint.epoch * SLOTS_PER_EPOCH;
        self.clear_pending_blocks(fin_slot);
    }

    fn clear_pending_blocks(&mut self, finalized_slot: u64) {
        tracing::debug!(
            pending_blocks = self.pending_blocks.len(),
            finalized_slot,
            "clear pending blocks at finalization"
        );
        self.pending_blocks.retain(|_, msgs| {
            msgs.iter().all(|msg| {
                let acquired = match msg {
                    PendingBlock::Gossip(g) => self.gossip_consumer.acquire(g.ssz),
                    PendingBlock::Rpc(_, ssz) => self.rpc_consumer.acquire(*ssz),
                };
                if let Ok((buffer, _)) = acquired.buffer() {
                    return SignedBeaconBlockView::slot(buffer) > finalized_slot;
                }
                false
            })
        });
    }

    fn promote_and_rebase(
        &mut self,
        promoted_seq: usize,
        survivors: &[usize],
        epoch_idxs: &[usize],
        longtail_idxs: &[usize],
    ) {
        let mut guard = self.state.write();
        let bs = &mut *guard;

        // Clone the promoted delta out of the ring: `apply_delta` borrows it
        // while mutating the base, and the per-survivor re-base borrows it
        // while mutating sibling slots in the same buffer.
        let promoted = bs.slots.get(promoted_seq).clone();
        let promoted_epoch = promoted.epoch_idx.map(|s| bs.epochs.get(s).clone());
        let promoted_longtail = promoted.longtail_idx.map(|s| bs.longtails.get(s).clone());

        // Snapshot the finalized base into survivors at indices `promoted`
        // will overwrite.
        snapshot_finalized_into_survivors(bs, &promoted, survivors, promoted_seq);

        // `prune_queue_delta` needs the pre-apply_delta fin queue lengths
        // to recover how many of promoted's `*_appended` prefix each
        // survivor's cumulative `drain_offset` already consumed.
        let old_pending_lens = PendingQueuesOldBaseLens::snapshot(&bs.finalized.pending);

        bs.finalized.apply_delta(&promoted, promoted_epoch.as_ref(), promoted_longtail.as_ref());

        for &seq in survivors {
            bs.slots.get_mut(seq).prune_to_base(&bs.finalized, &promoted, &old_pending_lens);
        }
        if let Some(promoted_epoch) = &promoted_epoch {
            for &e in epoch_idxs {
                bs.epochs.get_mut(e).prune_to_base(promoted_epoch);
            }
        }
        if let Some(promoted_longtail) = &promoted_longtail {
            for &l in longtail_idxs {
                bs.longtails.get_mut(l).prune_to_base(promoted_longtail);
            }
        }
    }

    fn on_attestation(&mut self, validator_idx: usize, block_root: B256, epoch: Epoch) {
        let n = {
            let d = self.state.state().slots.get(self.last_applied);
            d.validators.base_count + d.validators.appended.len()
        };
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
            let view = self.state.delta_view(self.last_applied);
            self.eff_scratch.clear();
            self.eff_scratch.extend(view.iter_validator_effective_balances());
            view.validators_count()
        };

        let mut deltas = compute_deltas(
            &mut self.vote_tracker.votes,
            n,
            self.fork_choice.indices.as_slice(),
            &self.prev_eff_balances,
            &self.eff_scratch,
        );
        self.fork_choice.apply_score_changes(&mut deltas);
        // Remember this recompute's balances so the next one can net the change.
        self.prev_eff_balances.clear();
        self.prev_eff_balances.extend_from_slice(&self.eff_scratch);
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

    fn handle_gossip(&mut self, m: NewGossipMsg, data: &[u8], producers: &mut Producers) {
        let feedback = match m.topic {
            GossipTopic::BeaconBlock => {
                let acquired = self.gossip_consumer.acquire(m.ssz);
                Some(self.apply_block(data, acquired, RejectSource::Gossip, producers))
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
                producers.produce(PeerEvent::SendGossip {
                    originator_stream_id: m.stream_id,
                    topic: m.topic,
                    msg_hash: m.msg_hash,
                    recv_ts: m.recv_ts,
                    protobuf: m.protobuf,
                });

                // Try to apply any pending blocks for which this one was the parent.
                if let Some(root) = block_root {
                    self.apply_pending_blocks(root, producers);
                }
            }
            Some(Feedback::RequestParent(parent_root)) if self.mode.is_following() => {
                self.pending_blocks
                    .entry(parent_root)
                    .and_modify(|v| v.push(PendingBlock::Gossip(m)))
                    .or_insert_with(|| vec![PendingBlock::Gossip(m)]);
                producers.produce(PeerEvent::SendBlocksByRootRequest {
                    request_id: 0,
                    p2p_peer: Some(m.stream_id.peer()),
                    block_root: parent_root,
                })
            }
            Some(Feedback::RequestParent(_)) | Some(Feedback::Ignore) | None => {}
        }
    }

    fn apply_pending_blocks(&mut self, parent_root: B256, producers: &mut Producers) {
        if let Some(pending) = self.pending_blocks.remove(&parent_root) {
            // Have one or more pending child blocks.
            for msg in pending {
                match msg {
                    PendingBlock::Gossip(g) => {
                        let acquired = self.gossip_consumer.acquire(g.ssz);
                        let data = acquired.buffer().ok().map(|(d, _)| d as *const [u8]);
                        if let Some(p) = data {
                            // This will recursively apply any chained pending blocks
                            self.handle_gossip(g, unsafe { &*p }, producers);
                        }
                    }
                    PendingBlock::Rpc(stream_id, ssz) => {
                        let acquired = self.rpc_consumer.acquire(ssz);
                        let data = acquired.buffer().ok().map(|(d, _)| d as *const [u8]);
                        if let Some(p) = data {
                            // This will recursively apply any chained pending blocks
                            self.handle_rpc(
                                RpcMsg::BlocksRootResp(SignedBeaconBlockView),
                                stream_id,
                                unsafe { &*p },
                                acquired,
                                producers,
                            );
                        }
                    }
                }
            }
        }
    }

    fn handle_rpc(
        &mut self,
        msg: RpcMsg,
        sender: P2pStreamId,
        data: &[u8],
        data_tcache: TRead,
        producers: &mut Producers,
    ) {
        if let RpcMsg::BlocksRangeResp(_) = msg {
            if !SignedBeaconBlockView::check_size(data) {
                producers.produce(PeerEvent::RpcMisbehaviour {
                    p2p_peer: sender.peer(),
                    severity: RpcSeverity::LowTolerance,
                });
                return;
            }
            let tcache = data_tcache.read;
            let f = self.apply_block(data, data_tcache, RejectSource::Rpc, producers);
            match f {
                Feedback::Accept(block_root) => {
                    // Try to apply any pending blocks for which this one was the parent.
                    if let Some(root) = block_root {
                        self.apply_pending_blocks(root, producers);
                    }
                    producers.produce(self.status_event());
                }
                Feedback::RequestParent(parent_root) if self.mode.is_following() => {
                    self.pending_blocks
                        .entry(parent_root)
                        .and_modify(|v| v.push(PendingBlock::Rpc(sender, tcache)))
                        .or_insert_with(|| vec![PendingBlock::Rpc(sender, tcache)]);
                    producers.produce(PeerEvent::SendBlocksByRootRequest {
                        request_id: 0,
                        p2p_peer: Some(sender.peer()),
                        block_root: parent_root,
                    })
                }
                Feedback::Ignore | Feedback::RequestParent(_) => {}
                Feedback::Reject(_) => producers.produce(PeerEvent::RpcMisbehaviour {
                    p2p_peer: sender.peer(),
                    severity: RpcSeverity::Fatal,
                }),
            }
        }
    }

    fn handle_block(&mut self, data: &[u8]) -> Feedback {
        let parsed = match self.precheck_block(data) {
            Ok(p) => p,
            Err(err) => {
                tracing::warn!(head_slot = self.head_state_slot(), "{err}");
                return err.feedback();
            }
        };

        let block_epoch = parsed.block_slot / SLOTS_PER_EPOCH;
        let parent_slot = self.state.state().slots.get(parsed.parent_seq).slot.slot.slot;
        let parent_epoch = parent_slot / SLOTS_PER_EPOCH;

        // COW: an unpublished child off the parent post-state (slot delta, plus
        // private epoch/longtail copies if an epoch transition will be crossed).
        let new_seq = self.cow_state_for_block(parsed.parent_seq, block_epoch, parent_epoch);

        // Per-block attester shuffling against the parent post-state (active
        // set + seed for an epoch are fixed at its prior boundary). Reuse the
        // `(epoch, mix)`-keyed cache so consecutive same-epoch blocks skip the
        // O(rounds·n) shuffle; `ensure_shuffling_window` only computes on a miss.
        self.ensure_shuffling_window(block_epoch, new_seq);
        let sref =
            Self::build_shuffling_ref(&self.shuffling_cache, &mut self.state, new_seq, block_epoch);

        let mut view = self.state.delta_view(new_seq);
        self.attestation_votes_scratch.clear();
        let res = state_transition::apply_block(
            &self.spec,
            &mut view,
            data,
            parsed.block_slot,
            parsed.proposer_index as u32,
            parsed.parent_root,
            parsed.body_root,
            parsed.state_root,
            Some(&sref),
            &mut self.active_scratch,
            &mut self.postponed_scratch,
            &mut self.replace_u64_scratch,
            &mut self.replace_u8_scratch,
            &mut self.eff_scratch,
            &mut self.state_hash_scratch,
            &mut self.attestation_votes_scratch,
            &mut self.sig_batch,
        );

        // Snapshot checkpoints while the view is live, then drop it so the
        // `&mut self.state` borrow ends before the fork-choice / publish work.
        let outcome = match res {
            Ok(()) => {
                let es = view.epoch_state();
                Ok((es.current_justified_checkpoint, es.finalized_checkpoint))
            }
            Err(e) => Err(e),
        };
        // `view`'s &mut self.state borrow ends here (last use above); the
        // fork-choice + publish work below needs &mut self.

        let (justified, finalized) = match outcome {
            Ok(checkpoints) => checkpoints,
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

        self.publish_applied_block(&parsed, new_seq, justified, finalized);
        Feedback::Accept(Some(parsed.block_root))
    }

    fn publish_applied_block(
        &mut self,
        parsed: &ParsedBlock,
        new_seq: usize,
        justified: Checkpoint,
        finalized: Checkpoint,
    ) {
        // Fold block-included attestations into the LMD vote tracker.
        for i in 0..self.attestation_votes_scratch.len() {
            let (vi, root, ep) = self.attestation_votes_scratch[i];
            self.on_attestation(vi as usize, root, ep);
        }

        // TODO(EL): pass the execution payload block hash to fork choice and
        // drive engine_forkchoiceUpdatedV3 once the EL path is wired.
        self.fork_choice.on_block(BlockImport {
            slot: parsed.block_slot,
            block_root: parsed.block_root,
            parent_root: parsed.parent_root,
            state_root: parsed.state_root,
            execution_block_hash: [0u8; 32],
            justified,
            finalized,
            state_seq: new_seq,
        });

        self.recompute_head();

        self.last_applied = new_seq;
        self.last_applied_block_root = parsed.block_root;
        let epoch_off = self.state.state().slots.get(new_seq).epoch_idx;
        self.state.publish_offsets(epoch_off, Some(new_seq));

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
            return Err(PrecheckError::PreFinalized { block_epoch, finalized_epoch })
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
        let parent_seq = parent_node.state_seq;

        // Immutable read view of the parent post-state.
        let bs = self.state.state();
        let parent_delta = bs.slots.get(parent_seq);
        let epoch_delta = parent_delta.epoch_idx.map(|s| bs.epochs.get(s));
        let read_view = StateDeltaReadView::new(&bs.finalized, Some(parent_delta), epoch_delta);
        let parent_slot = read_view.slot();

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
            if lookahead_idx < PROPOSER_LOOKAHEAD_SIZE {
                let expected = read_view.epoch_state().proposer_lookahead[lookahead_idx];
                if proposer_index != expected {
                    return Err(PrecheckError::ProposerLookaheadMismatch {
                        expected,
                        got: proposer_index,
                        block_root,
                    });
                }
            }
        }

        let validator_count = read_view.validators_count();
        if proposer_index as usize >= validator_count {
            return Err(PrecheckError::ProposerIndexTooBig {
                got: proposer_index,
                validator_count,
                block_root,
            });
        }
        let (fork_version, gvr) = read_view.fork_version_at(block_epoch);
        let proposer_pubkey = read_view.validator_pubkey_decompressed(proposer_index as usize);
        if !bls::verify_block_signature(data, proposer_pubkey, &body_root, fork_version, &gvr) {
            return Err(PrecheckError::InvalidBls {
                proposer_index,
                pubkey: read_view.validator_pubkey(proposer_index as usize),
                block_root,
            });
        }

        Ok(ParsedBlock {
            block_slot,
            proposer_index,
            parent_root,
            state_root,
            body_root,
            block_root,
            parent_seq,
        })
    }

    /// Roll an unpublished child slot delta off `parent_seq`. `reset_from`
    /// copies the parent's `epoch_idx`/`longtail_idx`, so when the child
    /// crosses an epoch boundary (where `process_epoch` writes those tiers)
    /// it is given private copies — otherwise it would corrupt sibling forks
    /// sharing the parent's ring entries.
    fn cow_state_for_block(
        &mut self,
        parent_seq: usize,
        block_epoch: Epoch,
        parent_epoch: Epoch,
    ) -> usize {
        let new_seq = match self.state.slots().roll(Some(parent_seq)) {
            RollResult::Reset(s) | RollResult::Rolled(s) => s,
        };
        if block_epoch == parent_epoch {
            return new_seq;
        }
        if let Some(parent_epoch_idx) = self.state.slots().get(new_seq).epoch_idx {
            let new_epoch_idx = match self.state.epochs().roll(Some(parent_epoch_idx)) {
                RollResult::Reset(s) | RollResult::Rolled(s) => s,
            };
            self.state.slots().get_mut(new_seq).epoch_idx = Some(new_epoch_idx);
        }
        if longtail_rotates_at_epoch(block_epoch) &&
            let Some(parent_longtail_idx) = self.state.slots().get(new_seq).longtail_idx
        {
            let new_longtail_idx = match self.state.longtails().roll(Some(parent_longtail_idx)) {
                RollResult::Reset(s) | RollResult::Rolled(s) => s,
            };
            self.state.slots().get_mut(new_seq).longtail_idx = Some(new_longtail_idx);
        }
        new_seq
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

        let canon_seq = self.canonical_state_seq();
        let att_epoch = att_slot / SLOTS_PER_EPOCH;
        self.ensure_shuffling_window(att_epoch, canon_seq);

        // Validate committee membership + signature against the canonical head.
        let view = self.state.delta_view(canon_seq);
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
        if attester_index >= view.validators_count() {
            return Feedback::Reject(None);
        }
        let (fork_version, gvr) = view.fork_version_at(target_epoch);
        let ok = bls::verify_single_attestation(
            buf,
            view.validator_pubkey_decompressed(attester_index),
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

        let canon_seq = self.canonical_state_seq();
        self.ensure_shuffling_window(parsed.att_epoch, canon_seq);

        let view = self.state.delta_view(canon_seq);
        let count = view.validators_count();
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

        self.active_scratch.clear();
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
            self.active_scratch.push(vi32);
        }
        if self.active_scratch.is_empty() {
            return Feedback::Reject(None);
        }

        if !is_aggregator(committee_len, parsed.selection_proof) {
            return Feedback::Reject(None);
        }

        if !Self::verify_aggregate_and_proof_sigs(
            &view,
            &parsed,
            &self.active_scratch,
            &mut self.sig_batch,
        ) {
            return Feedback::Reject(None);
        }

        for i in 0..self.active_scratch.len() {
            let vi = self.active_scratch[i] as usize;
            self.on_attestation(vi, parsed.beacon_block_root, parsed.target_epoch);
        }
        Feedback::Accept(None)
    }

    fn verify_aggregate_and_proof_sigs(
        view: &StateDeltaView,
        parsed: &ParsedAggregateAndProof<'_>,
        active_scratch: &[u32],
        sig_batch: &mut bls::SigBatch,
    ) -> bool {
        let (fv, gvr) = view.fork_version_at(parsed.target_epoch);

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
        let aggregator_pk = view.validator_pubkey_decompressed(parsed.aggregator_index);
        sig_batch.push_one(aggregator_pk, parsed.selection_proof, sr_sp);
        sig_batch.push_one(aggregator_pk, parsed.outer_sig, sr_aap);
        sig_batch.push_aggregate(
            active_scratch.iter().map(|&vi| view.validator_pubkey_decompressed(vi as usize)),
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

        let canon_seq = self.canonical_state_seq();
        let view = self.state.delta_view(canon_seq);
        // Out-of-range index: state may be stale, defer.
        if vi >= view.validators_count() {
            return Feedback::Ignore;
        }
        let current_epoch = view.current_epoch();
        if let Err(e) = validate::validate_voluntary_exit(
            &self.spec,
            &view,
            vi_u as u32,
            exit_epoch,
            current_epoch,
        ) {
            tracing::debug!(error = %e, "voluntary_exit gossip rejected");
            return Feedback::Reject(None);
        }
        if state_transition::get_pending_balance_to_withdraw(&view, vi_u as u32) != 0 {
            return Feedback::Reject(None);
        }

        let object_root = ssz_hash::hash_tree_root_voluntary_exit(exit_epoch, vi_u);
        let imm = view.immutable();
        let domain = bls::compute_domain(
            bls::DOMAIN_VOLUNTARY_EXIT,
            imm.capella_fork_version,
            &imm.genesis_validators_root,
        );
        let signing_root = bls::compute_signing_root(&object_root, &domain);
        let sig = SignedVoluntaryExitView::signature(buf);
        if !bls::verify_one(view.validator_pubkey_decompressed(vi), sig, &signing_root) {
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

        let canon_seq = self.canonical_state_seq();
        let view = self.state.delta_view(canon_seq);
        let current_epoch = view.current_epoch();
        let proposer_index = ProposerSlashingView::h1_proposer_index(buf) as usize;
        if proposer_index >= view.validators_count() {
            return Feedback::Ignore;
        }
        if !state_transition::is_slashable_validator(&view, proposer_index as u32, current_epoch) {
            return Feedback::Reject(None);
        }

        let h1_epoch = ProposerSlashingView::h1_slot(buf) / SLOTS_PER_EPOCH;
        let h2_epoch = ProposerSlashingView::h2_slot(buf) / SLOTS_PER_EPOCH;
        let (fv1, gvr) = view.fork_version_at(h1_epoch);
        let (fv2, _) = view.fork_version_at(h2_epoch);
        let sr1 = state_transition::signing_root_for_block_header(&buf[0..208], fv1, &gvr);
        let sr2 = state_transition::signing_root_for_block_header(&buf[208..416], fv2, &gvr);
        let sig1 = ProposerSlashingView::h1_signature(buf);
        let sig2 = ProposerSlashingView::h2_signature(buf);
        let pubkey = view.validator_pubkey_decompressed(proposer_index);

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
        let canon_seq = self.canonical_state_seq();
        let view = self.state.delta_view(canon_seq);
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

        let canon_seq = self.canonical_state_seq();
        let view = self.state.delta_view(canon_seq);

        let vi_u = SignedBlsToExecutionChangeView::validator_index(buf);
        let vi = vi_u as usize;
        if vi >= view.validators_count() {
            return Feedback::Ignore;
        }
        let from_pubkey = SignedBlsToExecutionChangeView::from_bls_pubkey(buf);
        let to_address = SignedBlsToExecutionChangeView::to_execution_address(buf);
        if let Err(e) = validate::validate_bls_to_execution_change(&view, vi_u as u32, from_pubkey)
        {
            tracing::debug!(error = %e, "bls_to_execution_change gossip rejected");
            return Feedback::Reject(None);
        }

        let object_root = ssz_hash::hash_tree_root_bls_change(vi_u, from_pubkey, to_address);
        let imm = view.immutable();
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
                    self.handle_gossip(m, unsafe { &*p }, producers);
                }
            } else {
                tracing::warn!(
                    topic = ?m.topic,
                    p2p_peer = m.stream_id.peer(),
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
                SyncUpdate::SyncingFinalized { .. } | SyncUpdate::SyncingHead { .. } => {
                    Mode::Syncing
                }
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
                    self.handle_rpc(
                        RpcMsg::BlocksRangeResp(SignedBeaconBlockView),
                        stream_id,
                        unsafe { &*p },
                        acquired,
                        producers,
                    );
                }
            }
        });
        self.rpc_consumer.free();
    }
}

/// Spec gossip rule: `aggregate.slot + ATTESTATION_PROPAGATION_SLOT_RANGE >=
/// current_slot >= aggregate.slot`.
const ATTESTATION_PROPAGATION_SLOT_RANGE: u64 = 32;

fn is_aggregator(committee_len: usize, selection_proof: &[u8; 96]) -> bool {
    const TARGET_AGGREGATORS_PER_COMMITTEE: u64 = 16;
    let modulo = (committee_len as u64 / TARGET_AGGREGATORS_PER_COMMITTEE).max(1);
    let h = ssz_hash::sha256(selection_proof);
    u64::from_le_bytes(h[0..8].try_into().unwrap()) % modulo == 0
}

/// `true` when crossing into `epoch` rotates the `HistoricalLongtail` tier:
/// either a sync-committee rotation (every `EPOCHS_PER_SYNC_COMMITTEE_PERIOD`)
/// or a historical-summaries push (every `SLOTS_PER_HISTORICAL_ROOT /
/// SLOTS_PER_EPOCH`).
fn longtail_rotates_at_epoch(epoch: Epoch) -> bool {
    let hs_period = SLOTS_PER_HISTORICAL_ROOT as u64 / SLOTS_PER_EPOCH;
    epoch.is_multiple_of(EPOCHS_PER_SYNC_COMMITTEE_PERIOD) || epoch.is_multiple_of(hs_period)
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

/// Pin each survivor's effective view against the impending `apply_delta`:
/// for every index promoted is about to overwrite that a survivor reads
/// through the finalized base, materialise `(idx, finalized[idx])` on the
/// survivor so its view doesn't shift to the new value.
fn snapshot_finalized_into_survivors(
    bs: &mut BeaconState,
    promoted: &StateDelta,
    survivors: &[usize],
    promoted_seq: usize,
) {
    // Skip promoted's appended-validator range — those indices aren't yet
    // in the finalized base, so there's no pre-promote value to preserve.
    let valid_below = bs.finalized.validators.validator_count() as u32;
    let fin = &bs.finalized;
    let vfin = &fin.validators;

    for &seq in survivors {
        if seq == promoted_seq {
            continue;
        }
        let d = bs.slots.get_mut(seq);
        merge_finalized(
            &mut d.previous_participation.edits,
            &promoted.previous_participation.edits,
            valid_below,
            |i| fin.previous_participation.get(i),
        );
        merge_finalized(
            &mut d.current_participation.edits,
            &promoted.current_participation.edits,
            valid_below,
            |i| fin.current_participation.get(i),
        );
        merge_finalized(&mut d.balances.edits, &promoted.balances.edits, valid_below, |i| {
            fin.balances.get(i)
        });
        merge_finalized(
            &mut d.inactivity_scores.edits,
            &promoted.inactivity_scores.edits,
            valid_below,
            |i| fin.inactivity_scores.get(i),
        );
        merge_finalized(
            &mut d.validators.credentials_edits,
            &promoted.validators.credentials_edits,
            valid_below,
            |i| *vfin.withdrawal_credentials(i),
        );
        merge_finalized(
            &mut d.validators.effective_balance_edits,
            &promoted.validators.effective_balance_edits,
            valid_below,
            |i| vfin.effective_balance(i),
        );
        merge_finalized(
            &mut d.validators.slashed_edits,
            &promoted.validators.slashed_edits,
            valid_below,
            |i| vfin.is_slashed(i),
        );
        merge_finalized(
            &mut d.validators.activation_eligibility_epoch_edits,
            &promoted.validators.activation_eligibility_epoch_edits,
            valid_below,
            |i| vfin.activation_eligibility_epoch(i),
        );
        merge_finalized(
            &mut d.validators.activation_epoch_edits,
            &promoted.validators.activation_epoch_edits,
            valid_below,
            |i| vfin.activation_epoch(i),
        );
        merge_finalized(
            &mut d.validators.exit_epoch_edits,
            &promoted.validators.exit_epoch_edits,
            valid_below,
            |i| vfin.exit_epoch(i),
        );
        merge_finalized(
            &mut d.validators.withdrawable_epoch_edits,
            &promoted.validators.withdrawable_epoch_edits,
            valid_below,
            |i| vfin.withdrawable_epoch(i),
        );
    }
}

/// O(n + m) in-place merge over the sorted-by-idx edit lists. For each idx
/// in `promoted_edits` < `valid_below` not already in `edits`, insert
/// `(idx, finalized_get(idx))`. Reverse-merge into a resized `edits`:
/// no temporary `Vec`, no realloc once capacity has grown to the working
/// set's high-water mark.
#[inline]
fn merge_finalized<T, F>(
    edits: &mut Vec<(u32, T)>,
    promoted_edits: &[(u32, T)],
    valid_below: u32,
    finalized_get: F,
) where
    T: Copy + Default,
    F: Fn(usize) -> T,
{
    if promoted_edits.is_empty() {
        return;
    }
    // Pass 1: count entries we'll actually add.
    let mut to_add = 0usize;
    let (mut i, mut j) = (0usize, 0usize);
    while i < edits.len() && j < promoted_edits.len() {
        let ei = edits[i].0;
        let pj = promoted_edits[j].0;
        if ei < pj {
            i += 1;
        } else if ei > pj {
            if pj < valid_below {
                to_add += 1;
            }
            j += 1;
        } else {
            i += 1;
            j += 1;
        }
    }
    while j < promoted_edits.len() {
        if promoted_edits[j].0 < valid_below {
            to_add += 1;
        }
        j += 1;
    }
    if to_add == 0 {
        return;
    }

    // Pass 2: reverse-merge in place. Read from the back of each input,
    // write to the back of the resized `edits`.
    let orig = edits.len();
    edits.resize(orig + to_add, (0u32, T::default()));
    let mut w = orig + to_add;
    let mut ii = orig;
    let mut jj = promoted_edits.len();
    while ii > 0 && jj > 0 {
        let pj = promoted_edits[jj - 1].0;
        if pj >= valid_below {
            jj -= 1;
            continue;
        }
        let ei = edits[ii - 1].0;
        if ei > pj {
            w -= 1;
            edits[w] = edits[ii - 1];
            ii -= 1;
        } else if ei < pj {
            w -= 1;
            edits[w] = (pj, finalized_get(pj as usize));
            jj -= 1;
        } else {
            w -= 1;
            edits[w] = edits[ii - 1];
            ii -= 1;
            jj -= 1;
        }
    }
    while jj > 0 {
        let pj = promoted_edits[jj - 1].0;
        if pj < valid_below {
            w -= 1;
            edits[w] = (pj, finalized_get(pj as usize));
        }
        jj -= 1;
    }
    debug_assert_eq!(w, ii, "reverse merge wrote past the surviving prefix");
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use silver_beacon_state_data::{BLSPubkey, Finalized, Immutable, ValSeed, Withdrawals};
    use silver_common::{TCache, TCacheProducer, ssz_view::SIGNED_AGG_PROOF_MIN};

    use super::*;

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
        let gossip_c = gossip_p.cache_ref().random_access("test_gossip", true).unwrap();
        let rpc_c = event_p.cache_ref().random_access("test_event", true).unwrap();
        let state = BeaconStateOwner::new(BeaconState::empty());
        BeaconStateTile::new(ticker, SpecConfig::mainnet(), state, gossip_c, rpc_c, &[])
    }

    fn placeholder_pubkey(i: usize) -> BLSPubkey {
        let mut pk = [0u8; 48];
        pk[..4].copy_from_slice(&(i as u32).to_le_bytes());
        pk
    }

    /// Build a `Finalized` base with `n` active validators (MAX effective
    /// balance, activation epoch 0, exit FAR_FUTURE) at `start_slot`. With
    /// `real_keys`, install spec BLS test pubkeys (+ BLS-prefix withdrawal
    /// creds) so signature-checking handlers accept; otherwise collision-
    /// free placeholder pubkeys.
    fn build_seed_finalized(n: usize, start_slot: Slot, real_keys: bool) -> Box<Finalized> {
        let cp_fin = silver_beacon_state_data::Checkpoint { epoch: 0, root: ANCHOR_ROOT };
        let seeds: Vec<ValSeed> = (0..n)
            .map(|i| {
                let (pubkey, withdrawal_credentials) = if real_keys {
                    let sk_idx = i % crate::test_signing::PRIVKEY_HEX.len();
                    let pk_bytes = crate::test_signing::pubkey_pk(sk_idx).to_bytes();
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
        let mut fin = Finalized::new(&seeds);
        fin.slot.slot.slot = start_slot;
        fin.epoch.state.current_justified_checkpoint = cp_fin;
        fin.epoch.state.finalized_checkpoint = cp_fin;
        fin
    }

    /// Install `fin` as the tile's base, anchor an empty per-fork delta seeded
    /// with the finalized slot scalars, and arm fork choice + the start-epoch
    /// attester shuffling at the anchor.
    fn arm_tile(tile: &mut BeaconStateTile, fin: Box<Finalized>, start_slot: Slot) {
        let mut bs = BeaconState::empty();
        bs.finalized = *fin;
        let mut owner = BeaconStateOwner::new(bs);

        let fin_slot = owner.state().finalized.slot.slot;
        let vd = ValidatorsDelta::new_at(&owner.state().finalized.validators);
        let seq = match owner.slots().roll(None) {
            RollResult::Reset(s) | RollResult::Rolled(s) => s,
        };
        {
            let sd = owner.slots().get_mut(seq);
            sd.validators = vd;
            sd.slot = SlotStateDelta { slot: fin_slot, ..Default::default() };
        }
        owner.publish_offsets(None, Some(seq));

        tile.state = owner;
        tile.last_applied = seq;
        tile.last_applied_block_root = ANCHOR_ROOT;
        tile.mode = Mode::Following;

        let cp = Checkpoint { epoch: 0, root: ANCHOR_ROOT };
        tile.fork_choice = ForkChoice::init(cp, cp, start_slot, ANCHOR_ROOT, ANCHOR_ROOT, seq);

        tile.ensure_shuffling_window(start_slot / SLOTS_PER_EPOCH, seq);
    }

    fn seed_tile(tile: &mut BeaconStateTile, n: usize, start_slot: Slot) {
        arm_tile(tile, build_seed_finalized(n, start_slot, false), start_slot);
    }

    fn seed_tile_with_keys(tile: &mut BeaconStateTile, n: usize, start_slot: Slot) {
        arm_tile(tile, build_seed_finalized(n, start_slot, true), start_slot);
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
        assert!(tile.state.state().slots.get(tile.last_applied).epoch_idx.is_some());
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

        // Give the anchor its own epoch delta with a recognizable lookahead.
        let anchor = tile.last_applied;
        {
            let mut view = tile.state.delta_view(anchor);
            view.ensure_epoch_delta();
            let es = view.epoch_state_mut();
            for i in 0..PROPOSER_LOOKAHEAD_SIZE {
                es.proposer_lookahead[i] = i as u64;
            }
        }
        let anchor_epoch_idx = tile.state.state().slots.get(anchor).epoch_idx.unwrap();
        let before = tile.state.state().epochs.get(anchor_epoch_idx).state.proposer_lookahead;

        // Advance across the epoch 0 -> 1 boundary on empty slots.
        tile.on_slot_start(32);
        assert_eq!(tile.head_state_slot(), 32);

        // Head forked onto a private epoch delta; the anchor's is untouched.
        let head_epoch_idx = tile.state.state().slots.get(tile.last_applied).epoch_idx.unwrap();
        assert_ne!(head_epoch_idx, anchor_epoch_idx, "head must COW its epoch delta");
        let after = tile.state.state().epochs.get(anchor_epoch_idx).state.proposer_lookahead;
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
        tile.handle_block(&buf);

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
        let buf = crate::test_signing::sign_voluntary_exit(0, 0, 0, &imm);
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
        let buf = crate::test_signing::sign_proposer_slashing(0, 0, 0, &imm);
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
        let buf = crate::test_signing::sign_attester_slashing_double_vote(0, 0, 0, 0, &imm);
        assert_eq!(tile.handle_attester_slashing(&buf), Feedback::Accept(None));
    }

    #[test]
    fn as_zero_intersection_with_valid_sigs_rejected() {
        let mut tile = make_tile();
        seed_tile_with_keys(&mut tile, 4, 0);
        let imm = seed_immutable(&tile);
        let ia1 = crate::test_signing::build_indexed_attestation(0, 0, 0, 0, 0, 0xAA, &imm);
        let ia2 = crate::test_signing::build_indexed_attestation(1, 1, 0, 0, 0, 0xBB, &imm);
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
        let mut fin = Finalized::new(&seeds);
        fin.epoch.state.current_justified_checkpoint = cp;
        fin.epoch.state.finalized_checkpoint = cp;
        arm_tile(&mut tile, fin, 0);
        let buf = [0u8; SIGNED_BLS_CHANGE_SIZE]; // vi = 0
        assert_eq!(tile.handle_bls_to_execution_change(&buf), Feedback::Reject(None));
    }

    #[test]
    fn bls_change_accept() {
        let mut tile = make_tile();
        seed_tile_with_keys(&mut tile, 4, 0);
        let imm = seed_immutable(&tile);
        let to_addr = [0x42u8; 20];
        let buf = crate::test_signing::sign_bls_to_execution_change(0, 0, &to_addr, &imm);
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
            let seq = tile.last_applied;
            tile.state.slots().get_mut(seq).slot.slot.latest_block_header = genesis_header;
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

        tile.handle_block(&buf);
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
        crate::test_signing::sign_aggregate_and_proof(
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
        let buf = crate::test_signing::sign_single_attestation(
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
    fn signed_new_validator_deposit()
    -> (silver_beacon_state_data::BLSPubkey, silver_beacon_state_data::PendingDeposit) {
        const DOMAIN_DEPOSIT: u32 = 0x03;
        let pk = crate::test_signing::pubkey_bytes(0);
        let wc = Withdrawals([0xAAu8; 32]);
        let amount = 32_000_000_000u64;

        let msg_root = ssz_hash::merkleize(&[
            ssz_hash::hash_fixed_bytes(&pk),
            wc.0,
            ssz_hash::uint64_chunk(amount),
        ]);
        let domain = bls::compute_domain(DOMAIN_DEPOSIT, [0; 4], &[0u8; 32]);
        let signing_root = bls::compute_signing_root(&msg_root, &domain);
        let sig = crate::test_signing::sign(0, &signing_root);

        (pk, silver_beacon_state_data::PendingDeposit {
            pubkey: pk,
            withdrawal_credentials: wc,
            amount,
            signature: sig,
            slot: 0,
        })
    }

    /// Speculative validator appends from deposit processing must land on the
    /// head fork's `validators` delta, not on the shared `Finalized` base —
    /// the base only advances at Casper finality.
    #[test]
    fn epoch_transition_keeps_base_until_finality() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 1, 0);

        let (pk, deposit) = signed_new_validator_deposit();
        // Queue the deposit on the head delta and mark slot-0 deposits eligible
        // by finalizing epoch 1 in the base.
        {
            let seq = tile.last_applied;
            tile.state.slots().get_mut(seq).pending.deposits_appended.push(deposit);
            let mut g = tile.state.write();
            g.finalized.epoch.state.finalized_checkpoint =
                silver_beacon_state_data::Checkpoint { epoch: 1, root: ANCHOR_ROOT };
        }

        tile.on_slot_start(SLOTS_PER_EPOCH);

        // Base unchanged; the new validator lives on the head fork's delta.
        assert_eq!(
            tile.state.state().finalized.validators.validator_count(),
            1,
            "base must wait for finality"
        );
        let head = tile.state.state().slots.get(tile.last_applied);
        assert_eq!(head.validators.appended.len(), 1);
        assert_eq!(head.validators.appended[0].pubkey, pk);
    }

    /// `maybe_finalize` with `fin_idx > 0` must (a) promote the finalized
    /// delta into the base, (b) prune non-descendant siblings from fork
    /// choice, (c) re-base the surviving descendant's cumulative edits against
    /// the new base, and (d) advance the slots-ring tail. This is the only
    /// place the survivor re-base path is exercised — single-fork tests take
    /// the no-promote branch (`fin_idx == 0`).
    #[test]
    fn multi_fork_finalize_promotes_and_rebases() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 0);
        let anchor_seq = tile.last_applied;

        const F_ROOT: B256 = [0x0F; 32];
        const D_ROOT: B256 = [0x0D; 32];
        const F2_ROOT: B256 = [0xF2; 32];
        const ZERO_CP: Checkpoint = Checkpoint { epoch: 0, root: [0u8; 32] };
        let f_cp = Checkpoint { epoch: 0, root: F_ROOT };

        // F: child of anchor (to be finalized). One cumulative `block_root`.
        let f_seq = match tile.state.slots().roll(Some(anchor_seq)) {
            RollResult::Reset(s) | RollResult::Rolled(s) => s,
        };
        {
            let f = tile.state.slots().get_mut(f_seq);
            f.slot.slot.slot = 1;
            f.slot.block_roots.push(F_ROOT);
        }

        // D: child of F (head, survives). Inherits F's block_roots via
        // `reset_from`, appends its own → [F_ROOT, D_ROOT].
        let d_seq = match tile.state.slots().roll(Some(f_seq)) {
            RollResult::Reset(s) | RollResult::Rolled(s) => s,
        };
        {
            let d = tile.state.slots().get_mut(d_seq);
            d.slot.slot.slot = 2;
            d.slot.block_roots.push(D_ROOT);
        }

        // F2: sibling of F (will be pruned by fork choice).
        let f2_seq = match tile.state.slots().roll(Some(anchor_seq)) {
            RollResult::Reset(s) | RollResult::Rolled(s) => s,
        };
        {
            let f2 = tile.state.slots().get_mut(f2_seq);
            f2.slot.slot.slot = 1;
            f2.slot.block_roots.push(F2_ROOT);
        }

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
            state_seq: f2_seq,
        });
        tile.fork_choice.on_block(BlockImport {
            slot: 1,
            block_root: F_ROOT,
            parent_root: ANCHOR_ROOT,
            state_root: [0u8; 32],
            execution_block_hash: [0u8; 32],
            justified: f_cp,
            finalized: f_cp,
            state_seq: f_seq,
        });
        tile.fork_choice.on_block(BlockImport {
            slot: 2,
            block_root: D_ROOT,
            parent_root: F_ROOT,
            state_root: [0u8; 32],
            execution_block_hash: [0u8; 32],
            justified: f_cp,
            finalized: f_cp,
            state_seq: d_seq,
        });

        // Head is D; finality target is F.
        tile.last_applied = d_seq;
        tile.last_applied_block_root = D_ROOT;
        tile.fork_choice.finalized_checkpoint = f_cp;
        // Republish so the seqlock control matches the new head.
        tile.state.publish_offsets(None, Some(d_seq));

        // Sanity: pre-finalize state.
        assert_eq!(tile.state.state().finalized.slot.slot.slot, 0);
        assert_eq!(tile.state.state().slots.get(d_seq).slot.block_roots, vec![F_ROOT, D_ROOT]);
        assert!(tile.fork_choice.find_node_idx(&F2_ROOT).is_some());

        tile.maybe_finalize();

        // (a) Base advanced to F's slot scalars; F's block_root landed in the
        //     circular buffer at the old finalized slot offset.
        let base = &tile.state.state().finalized;
        assert_eq!(base.slot.slot.slot, 1, "base.slot promoted to F's slot");
        assert_eq!(base.slot.block_roots[0], F_ROOT, "F's block_root in base circular buffer");

        // (b) F2 pruned from fork choice; F is now node 0 (anchor); D survives.
        assert!(tile.fork_choice.find_node_idx(&F2_ROOT).is_none(), "F2 dropped");
        assert_eq!(tile.fork_choice.find_node_idx(&F_ROOT), Some(0), "F is the new anchor");
        assert!(tile.fork_choice.find_node_idx(&D_ROOT).is_some(), "D survives");

        // (c) D's cumulative `block_roots` log re-based against the new base:
        //     F's prefix drained, only D's incremental entry remains.
        let d = tile.state.state().slots.get(d_seq);
        assert_eq!(d.slot.block_roots, vec![D_ROOT], "D's block_roots drained of F's prefix");

        // (d) Slots ring tail advanced past the freed prefix (anchor + F2's
        //     slot are below the new tail).
        assert!(tile.state.state().slots.head().is_some(), "ring head present after finalize",);
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
