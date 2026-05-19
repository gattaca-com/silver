use flux::{
    spine::{FluxSpine, SpineAdapter, SpineProducers},
    tile::Tile,
};
use silver_common::{
    BeaconStateEvent, GossipTopic, NewGossipMsg, P2pStreamId, PeerEvent, RejectSource, RpcInbound,
    RpcMsg, RpcResponse, RpcResponseInbound, RpcSeverity, SilverSpine, SyncUpdate, TCacheRead,
    TRandomAccess,
    ssz_view::{
        AttesterSlashingView, PROPOSER_SLASHING_SIZE, ProposerSlashingView, SIGNED_BLS_CHANGE_SIZE,
        SIGNED_VOLUNTARY_EXIT_SIZE, SINGLE_ATT_SIZE, STATUS_V2_SIZE, SignedAggregateAndProofView,
        SignedBeaconBlockView, SignedBlsToExecutionChangeView, SignedVoluntaryExitView,
        SingleAttestationView,
    },
};

use crate::{
    arena::ArenaBacking,
    bls, decompose,
    epoch_transition::{self, MAX_PENDING_DEPOSITS_PER_EPOCH},
    error::PrecheckError,
    fork_choice::{BlockImport, compute_deltas},
    shuffling::{self, DOMAIN_BEACON_ATTESTER},
    ssz_hash, state_transition,
    ticker::{SlotTicker, TickEvent},
    types::{
        self, B256, BLOB_SCHEDULE, BeaconStateRef, BlobParameters, DEFAULT_BLOB_PARAMETERS,
        EPOCH_POOL_CAP, Epoch, EpochData, FULU_FORK_VERSION, ForkChoice, MAX_VALIDATORS,
        PENDING_POOL_CAP, PendingQueues, ROOTS_POOL_CAP, SLOT_POOL_CAP, SLOTS_PER_EPOCH,
        SLOTS_PER_HISTORICAL_ROOT, ShufflingCache, Slot, SlotData, ValidatorIdentity, Version,
        VoteTracker, box_zeroed,
    },
    validate,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct LastApplied {
    imm_idx: u8,
    vid_idx: u8,
    longtail_idx: u8,
    epoch_idx: u8,
    roots_idx: u8,
    slot_idx: u8,
    pending_idx: u8,
}

impl LastApplied {
    fn from_ref(r: &BeaconStateRef) -> Self {
        Self {
            imm_idx: r.imm_idx,
            vid_idx: r.vid_idx,
            longtail_idx: r.longtail_idx,
            epoch_idx: r.epoch_idx,
            roots_idx: r.roots_idx,
            slot_idx: r.slot_idx,
            pending_idx: r.pending_idx,
        }
    }
}

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
    Accept,
    Ignore,
    /// Carries the failed `block_root` (only) when the reject came from a
    /// post-`body_root`/STF path in block validation, so PM can blacklist
    /// the chain. All other reject paths (attestation, exit, slashing,
    /// pre-hash block fails) use `Reject(None)`.
    Reject(Option<B256>),
}

struct ParsedBlock<'a> {
    block_slot: Slot,
    proposer_index: u64,
    parent_root: B256,
    state_root: B256,
    body_root: B256,
    block_root: B256,
    body: &'a [u8],
    parent_state: BeaconStateRef,
}

pub struct BeaconStateTile {
    mode: Mode,
    ticker: SlotTicker,

    arena: ArenaBacking,
    pending_pool: Vec<PendingQueues>,
    pending_pool_next: usize,

    fork_choice: ForkChoice,
    vote_tracker: Box<VoteTracker>,
    shuffling_cache: Box<ShufflingCache>,

    last_applied: LastApplied,
    last_applied_block_root: B256,

    initial_status_emitted: bool,
    cached_fork_digest: Option<(Epoch, [u8; 4])>,

    zero_hashes: [B256; ssz_hash::ZERO_HASHES_LEN],
    postponed_scratch: Vec<types::PendingDeposit>,
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
    /// Pre-validation pass collects every BLS sig in the block here, then
    /// runs `verify_all` once before pass 2 mutates state.
    sig_batch: bls::SigBatch,

    gossip_consumer: TRandomAccess,
    rpc_consumer: TRandomAccess,
}

type Producers = <SilverSpine as FluxSpine>::Producers;

impl BeaconStateTile {
    pub fn new(
        ticker: SlotTicker,
        gossip_consumer: TRandomAccess,
        rpc_consumer: TRandomAccess,
        checkpoint_state: &[u8],
    ) -> Self {
        Self::with_arena(
            ticker,
            gossip_consumer,
            rpc_consumer,
            ArenaBacking::open_shm("silver"),
            checkpoint_state,
        )
    }

    pub fn new_heap(
        ticker: SlotTicker,
        gossip_consumer: TRandomAccess,
        rpc_consumer: TRandomAccess,
        checkpoint_state: &[u8],
    ) -> Self {
        Self::with_arena(
            ticker,
            gossip_consumer,
            rpc_consumer,
            ArenaBacking::heap(),
            checkpoint_state,
        )
    }

    /// Create a tile with the given arena backing. If `checkpoint_state` is
    /// non-empty, bootstraps immediately; otherwise starts inert in
    /// `Mode::Following` (call `bootstrap` before the loop for real use).
    fn with_arena(
        ticker: SlotTicker,
        gossip_consumer: TRandomAccess,
        rpc_consumer: TRandomAccess,
        arena: ArenaBacking,
        checkpoint_state: &[u8],
    ) -> Self {
        let pending_pool: Vec<PendingQueues> =
            (0..PENDING_POOL_CAP).map(|_| PendingQueues::new()).collect();
        let last_applied = LastApplied::default();

        // TierPool cursors start at 0; bump past slot 0 (reserved for the
        // bootstrap state that `last_applied` points at).
        arena.imm.set_cursor(0);
        arena.vid.set_cursor(1);
        arena.longtail.set_cursor(1);
        arena.epoch.set_cursor(1);
        arena.roots.set_cursor(1);
        arena.slot.set_cursor(1);

        let mut tile = Self {
            // Boot in Syncing. PM's first `SyncUpdate::Following` flips us
            // once peer Status data confirms we're caught up.
            mode: Mode::Syncing,
            ticker,
            arena,
            pending_pool,
            pending_pool_next: 1,
            fork_choice: ForkChoice::default(),
            vote_tracker: box_zeroed(),
            shuffling_cache: box_zeroed(),
            last_applied,
            last_applied_block_root: [0u8; 32],
            initial_status_emitted: false,
            cached_fork_digest: None,
            zero_hashes: ssz_hash::compute_zero_hashes(),
            active_scratch: Vec::with_capacity(
                MAX_VALIDATORS.max(types::MAX_ATTESTERS_PER_AGGREGATE),
            ),
            postponed_scratch: Vec::with_capacity(MAX_PENDING_DEPOSITS_PER_EPOCH),
            // Worst case: MAX_ATTESTATIONS_ELECTRA × full committee participation
            attestation_votes_scratch: Vec::with_capacity(16 * 1024),
            sig_batch: bls::SigBatch::new(),
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
        Self::last_applied_slot(&self.arena, self.last_applied).slot
    }

    pub fn try_apply_block(&mut self, data: &[u8]) -> Feedback {
        self.handle_block(data)
    }

    /// SSZ `hash_tree_root` of the most-recently-applied block's full
    /// BeaconState. Used by integration tests to cross-check tile-applied
    /// STF output against EF post-state vectors.
    pub fn head_state_root(&self) -> B256 {
        ssz_hash::hash_tree_root_state(
            Self::last_applied_imm(&self.arena, self.last_applied),
            Self::last_applied_vid(&self.arena, self.last_applied),
            Self::last_applied_longtail(&self.arena, self.last_applied),
            Self::last_applied_epoch(&self.arena, self.last_applied),
            Self::last_applied_roots(&self.arena, self.last_applied),
            Self::last_applied_slot(&self.arena, self.last_applied),
            &self.pending_pool[self.last_applied.pending_idx as usize],
            &self.zero_hashes,
        )
    }

    /// Load a checkpoint state SSZ blob. Decomposes into tiered storage at
    /// slot 0 of each pool.
    fn bootstrap(&mut self, ssz: &[u8]) {
        let pq = decompose::decompose_beacon_state(
            ssz,
            &self.zero_hashes,
            self.arena.imm.get_mut(0),
            self.arena.vid.get_mut(0),
            self.arena.longtail.get_mut(0),
            self.arena.epoch.get_mut(0),
            self.arena.roots.get_mut(0),
            self.arena.slot.get_mut(0),
        )
        .unwrap_or_else(|e| panic!("bootstrap: decompose failed: {e}"));
        self.pending_pool[0] = pq;

        let sd = self.arena.slot.get(0);
        let slot = sd.slot;

        let mut anchor_header = sd.latest_block_header;
        if anchor_header.state_root == [0u8; 32] {
            anchor_header.state_root = ssz_hash::hash_tree_root_state(
                self.arena.imm.get(0),
                self.arena.vid.get(0),
                self.arena.longtail.get(0),
                self.arena.epoch.get(0),
                self.arena.roots.get(0),
                sd,
                &self.pending_pool[0],
                &self.zero_hashes,
            );
        }
        let block_root = ssz_hash::hash_tree_root_block_header(&anchor_header, &self.zero_hashes);

        // Checkpoint-sync convention: the anchor is trusted, so both
        // finalized and justified checkpoints refer to the anchor block
        // itself. Using the pre-state's stored checkpoints would leave
        // `find_head` looking up a root no fork-choice node holds.
        let trusted_cp = types::Checkpoint { epoch: slot / SLOTS_PER_EPOCH, root: block_root };
        let finalized = trusted_cp;
        let justified = trusted_cp;
        self.last_applied = LastApplied::default();
        self.last_applied_block_root = block_root;

        let anchor_ref = BeaconStateRef {
            imm_idx: 0,
            vid_idx: 0,
            vid_gen: self.arena.vid.gen_at(0),
            longtail_idx: 0,
            epoch_idx: 0,
            epoch_gen: self.arena.epoch.gen_at(0),
            roots_idx: 0,
            roots_gen: self.arena.roots.gen_at(0),
            slot_idx: 0,
            slot_gen: self.arena.slot.gen_at(0),
            pending_idx: 0,
        };
        self.fork_choice =
            ForkChoice::init(finalized, justified, slot, block_root, block_root, anchor_ref);

        let current_epoch = slot / SLOTS_PER_EPOCH;
        self.ensure_shuffling_window(current_epoch);
    }

    fn alloc_pending(&mut self) -> usize {
        let idx = self.pending_pool_next;
        self.pending_pool_next = (idx + 1) % PENDING_POOL_CAP;
        idx
    }

    fn slot(&self, r: &BeaconStateRef) -> &SlotData {
        self.arena.slot.get_checked(r.slot_idx as usize, r.slot_gen)
    }

    fn imm_at(arena: &ArenaBacking, r: BeaconStateRef) -> &types::Immutable {
        arena.imm.get(r.imm_idx as usize)
    }

    fn vid_at(arena: &ArenaBacking, r: BeaconStateRef) -> &ValidatorIdentity {
        arena.vid.get_checked(r.vid_idx as usize, r.vid_gen)
    }

    fn epoch_at(arena: &ArenaBacking, r: BeaconStateRef) -> &EpochData {
        arena.epoch.get_checked(r.epoch_idx as usize, r.epoch_gen)
    }

    fn slot_at(arena: &ArenaBacking, r: BeaconStateRef) -> &SlotData {
        arena.slot.get_checked(r.slot_idx as usize, r.slot_gen)
    }

    /// `BeaconStateRef` of fork-choice's canonical tip. For gossip-object
    /// validation per spec ("the head state").
    fn canonical_state_ref(&self) -> BeaconStateRef {
        let head_root = self.fork_choice.find_head();
        let idx = self
            .fork_choice
            .find_node_idx(&head_root)
            .expect("find_head returns a node-resident root");
        self.fork_choice.node(idx).state
    }

    // ── Tier accessors via `last_applied`.

    fn last_applied_imm(arena: &ArenaBacking, la: LastApplied) -> &types::Immutable {
        arena.imm.get(la.imm_idx as usize)
    }

    fn last_applied_vid(arena: &ArenaBacking, la: LastApplied) -> &ValidatorIdentity {
        arena.vid.get(la.vid_idx as usize)
    }

    fn last_applied_longtail(arena: &ArenaBacking, la: LastApplied) -> &types::HistoricalLongtail {
        arena.longtail.get(la.longtail_idx as usize)
    }

    fn last_applied_epoch(arena: &ArenaBacking, la: LastApplied) -> &EpochData {
        arena.epoch.get(la.epoch_idx as usize)
    }

    fn last_applied_roots(arena: &ArenaBacking, la: LastApplied) -> &types::SlotRoots {
        arena.roots.get(la.roots_idx as usize)
    }

    #[allow(clippy::mut_from_ref)]
    fn last_applied_roots_mut(arena: &ArenaBacking, la: LastApplied) -> &mut types::SlotRoots {
        arena.roots.get_mut(la.roots_idx as usize)
    }

    fn last_applied_slot(arena: &ArenaBacking, la: LastApplied) -> &SlotData {
        arena.slot.get(la.slot_idx as usize)
    }

    #[allow(clippy::mut_from_ref)]
    fn last_applied_slot_mut(arena: &ArenaBacking, la: LastApplied) -> &mut SlotData {
        arena.slot.get_mut(la.slot_idx as usize)
    }

    /// Build a `BeaconStateRef` pinned to `last_applied`'s indices with
    /// arena gens snapshotted at call time. Only used to seed a
    /// `ForkChoice` anchor node from tests — fork-choice nodes need the
    /// long-lived gen-checked variant.
    #[cfg(test)]
    fn synth_anchor_ref(&self) -> BeaconStateRef {
        let la = self.last_applied;
        BeaconStateRef {
            imm_idx: la.imm_idx,
            vid_idx: la.vid_idx,
            vid_gen: self.arena.vid.gen_at(la.vid_idx as usize),
            longtail_idx: la.longtail_idx,
            epoch_idx: la.epoch_idx,
            epoch_gen: self.arena.epoch.gen_at(la.epoch_idx as usize),
            roots_idx: la.roots_idx,
            roots_gen: self.arena.roots.gen_at(la.roots_idx as usize),
            slot_idx: la.slot_idx,
            slot_gen: self.arena.slot.gen_at(la.slot_idx as usize),
            pending_idx: la.pending_idx,
        }
    }

    /// Compute and cache the shuffling for `epoch`. No-op if already cached.
    /// Maintain the 2-epoch attester window: attestations with
    /// `target_epoch ∈ {epoch, epoch - 1}` resolve their committee against
    /// both.
    fn ensure_shuffling_window(&mut self, epoch: Epoch) {
        self.ensure_shuffling(epoch);
        if epoch > 0 {
            self.ensure_shuffling(epoch - 1);
        }
    }

    // TODO(reorg): cache hit is keyed on `epoch` only; a re-org across an
    // epoch boundary into a fork with different RANDAO history serves the
    // stale entry. Include the head's `vid_gen`/`epoch_gen` (or seed) in the
    // key. See MAX_SHUFFLING_CACHE.
    fn ensure_shuffling(&mut self, epoch: Epoch) {
        for entry in self.shuffling_cache.entries.iter() {
            if entry.status == 1 && entry.epoch == epoch {
                return;
            }
        }

        let vid = Self::last_applied_vid(&self.arena, self.last_applied);
        let epoch_data = Self::last_applied_epoch(&self.arena, self.last_applied);

        let seed = shuffling::get_seed(epoch_data, epoch, DOMAIN_BEACON_ATTESTER);

        shuffling::get_active_validator_indices_into(
            epoch_data,
            vid.validator_cnt,
            epoch,
            &mut self.active_scratch,
        );
        shuffling::shuffle_list(&mut self.active_scratch, &seed);

        let slot = self.find_shuffling_slot(epoch);
        let entry = &mut self.shuffling_cache.entries[slot];
        entry.epoch = epoch;
        entry.seed = seed;
        entry.status = 1;
        entry.shuffled_indices.clear();
        for &idx in self.active_scratch.iter() {
            entry.shuffled_indices.push(idx);
        }
    }

    fn find_shuffling_slot(&self, _epoch: Epoch) -> usize {
        // Prefer empty slot, otherwise evict lowest epoch.
        let mut best = 0;
        let mut best_epoch = u64::MAX;
        for (i, entry) in self.shuffling_cache.entries.iter().enumerate() {
            if entry.status == 0 {
                return i;
            }
            if entry.epoch < best_epoch {
                best_epoch = entry.epoch;
                best = i;
            }
        }
        best
    }

    fn get_shuffling(&self, epoch: Epoch) -> Option<&types::ShufflingEntry> {
        self.shuffling_cache.entries.iter().find(|e| e.status == 1 && e.epoch == epoch)
    }

    /// Spec `compute_fork_digest` (Fulu EIP-7892). Cached per epoch:
    /// inputs (`FULU_FORK_VERSION`, gvr, active blob_parameters) only change
    /// at epoch boundaries — schedule entries are epoch-aligned and `gvr` is
    /// frozen. Reorg within an epoch keeps the cache valid.
    fn fork_digest(&mut self) -> [u8; 4] {
        let epoch = Self::last_applied_slot(&self.arena, self.last_applied).slot / SLOTS_PER_EPOCH;
        if let Some((cached_epoch, d)) = self.cached_fork_digest &&
            cached_epoch == epoch
        {
            return d;
        }
        let gvr = Self::last_applied_imm(&self.arena, self.last_applied).genesis_validators_root;
        let bp = get_blob_parameters(epoch, BLOB_SCHEDULE, DEFAULT_BLOB_PARAMETERS);
        let d = compute_fork_digest(FULU_FORK_VERSION, &gvr, Some(bp));
        self.cached_fork_digest = Some((epoch, d));
        d
    }

    fn status_payload(&mut self) -> [u8; STATUS_V2_SIZE] {
        let fork_digest = self.fork_digest();
        let sd = Self::last_applied_slot(&self.arena, self.last_applied);
        // Use the cached canonical block_root rather than rehashing
        // `latest_block_header` — the header's `state_root` is zero in the
        // window between block-apply and the next `process_slot`.
        let head_root = self.last_applied_block_root;
        let finalized = sd.finalized_checkpoint;
        let slot = sd.slot;
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

    fn status_event(&mut self) -> BeaconStateEvent {
        BeaconStateEvent::Status {
            ssz: self.status_payload(),
            wall_slot: self.ticker.current_slot(),
        }
    }

    /// Post-import emission: PersistBlock (for storage) + Status (head and
    /// possibly finalized just moved). Called after `handle_block` returns
    /// `GossipFeedback::Accept` from gossip or RPC range/root response paths.
    fn apply_block(
        &mut self,
        data: &[u8],
        data_tcache: TCacheRead,
        source: RejectSource,
        producers: &mut Producers,
    ) -> Feedback {
        let prev_last_applied = self.last_applied;
        let prev_finalized =
            Self::last_applied_slot(&self.arena, self.last_applied).finalized_checkpoint;

        let f = self.handle_block(data);
        if let Feedback::Reject(Some(block_root)) = f {
            producers.produce(BeaconStateEvent::BlockRejected { block_root, source });
        }
        if f != Feedback::Accept {
            tracing::warn!("handle block failed");
            return f;
        }

        producers.produce(BeaconStateEvent::PersistBlock(data_tcache));

        let head_changed = self.last_applied != prev_last_applied;
        let new_finalized =
            Self::last_applied_slot(&self.arena, self.last_applied).finalized_checkpoint;
        let finalized_changed = new_finalized != prev_finalized;
        if head_changed || finalized_changed {
            producers.produce(self.status_event());
        }
        f
    }

    /// Returns `true` iff at least one slot was processed (so head_slot
    /// definitely advanced, and finalized may have advanced via an epoch
    /// transition along the way).
    fn on_slot_start(&mut self, target_slot: Slot) -> bool {
        if target_slot <= Self::last_applied_slot(&self.arena, self.last_applied).slot {
            return false;
        }

        // Spec process_slots: per slot, run process_slot (root snapshot),
        // then epoch transition at boundary, then bump sd.slot.
        // `epoch_transition` may CoW VID/epoch/longtail and update
        // `last_applied`'s indices in place; the la_* accessors below
        // pick up the fresh slots automatically.
        while Self::last_applied_slot(&self.arena, self.last_applied).slot < target_slot {
            let s = Self::last_applied_slot(&self.arena, self.last_applied).slot;
            let pending_idx = self.last_applied.pending_idx as usize;
            state_transition::process_slot(
                Self::last_applied_imm(&self.arena, self.last_applied),
                Self::last_applied_vid(&self.arena, self.last_applied),
                Self::last_applied_longtail(&self.arena, self.last_applied),
                Self::last_applied_epoch(&self.arena, self.last_applied),
                Self::last_applied_roots_mut(&self.arena, self.last_applied),
                Self::last_applied_slot_mut(&self.arena, self.last_applied),
                &self.pending_pool[pending_idx],
                &self.zero_hashes,
            );

            if (s + 1).is_multiple_of(SLOTS_PER_EPOCH) {
                self.epoch_transition();
            }
            Self::last_applied_slot_mut(&self.arena, self.last_applied).slot += 1;
        }

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

    fn epoch_transition(&mut self) {
        let la = self.last_applied;

        // Always COW EpochData (mutated every epoch).
        let new_ei = self.arena.epoch.copy_from(la.epoch_idx as usize);

        // COW ValidatorIdentity if deposits may add new validators this epoch.
        let new_vid = if self.pending_pool[la.pending_idx as usize].pending_deposits.is_empty() {
            la.vid_idx as usize
        } else {
            self.arena.vid.copy_from(la.vid_idx as usize)
        };

        let next_epoch =
            Self::last_applied_slot(&self.arena, self.last_applied).slot / SLOTS_PER_EPOCH + 1;
        let new_longtail = if longtail_rotates_at_epoch(next_epoch) {
            self.arena.longtail.copy_from(la.longtail_idx as usize)
        } else {
            la.longtail_idx as usize
        };

        let vid = self.arena.vid.get_mut(new_vid);
        let longtail = self.arena.longtail.get_mut(new_longtail);
        let epoch = self.arena.epoch.get_mut(new_ei);
        let sd = self.arena.slot.get_mut(la.slot_idx as usize);
        let roots = self.arena.roots.get(la.roots_idx as usize);

        epoch_transition::process_epoch(
            vid,
            longtail,
            epoch,
            sd,
            &mut self.pending_pool[la.pending_idx as usize],
            roots,
            &self.zero_hashes,
            &mut self.active_scratch,
            &mut self.postponed_scratch,
        );

        self.last_applied.epoch_idx = new_ei as u8;
        self.last_applied.vid_idx = new_vid as u8;
        self.last_applied.longtail_idx = new_longtail as u8;

        let sd = Self::last_applied_slot(&self.arena, self.last_applied);
        let cp = (sd.current_justified_checkpoint, sd.finalized_checkpoint);
        let new_epoch = sd.slot / SLOTS_PER_EPOCH;
        self.fork_choice.justified_checkpoint = cp.0;
        self.fork_choice.finalized_checkpoint = cp.1;

        self.prune_fork_choice();
        self.ensure_shuffling_window(new_epoch);
    }

    fn on_attestation(&mut self, validator_idx: usize, block_root: B256, epoch: Epoch) {
        if validator_idx >= Self::last_applied_vid(&self.arena, self.last_applied).validator_cnt {
            return;
        }
        // Spec `update_latest_messages`: only newer-epoch votes overwrite.
        // Same-epoch later messages are slashable double-votes; LMD keeps the
        // first one observed. Applies to both gossip and block-included paths.
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
        let vid = Self::last_applied_vid(&self.arena, self.last_applied);
        let epoch = Self::last_applied_epoch(&self.arena, self.last_applied);
        let n = vid.validator_cnt;

        let mut deltas = compute_deltas(
            &mut self.vote_tracker.votes,
            n,
            self.fork_choice.indices.as_slice(),
            &epoch.val_effective_balance,
            &epoch.val_effective_balance,
        );
        self.fork_choice.apply_score_changes(&mut deltas);

        // Update fork choice justified/finalized from current head state.
        // Monotone, and only to roots present in our node list — otherwise
        // `find_head` walks from an unknown root and falls through.
        // During sync the block's post-state often names checkpoints from
        // much earlier blocks we never imported; skip those updates.
        let sd = Self::last_applied_slot(&self.arena, self.last_applied);
        let j = sd.current_justified_checkpoint;
        let f = sd.finalized_checkpoint;
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

    fn prune_fork_choice(&mut self) {
        let pruned = self.fork_choice.prune();
        if pruned.is_empty() {
            return;
        }

        // Collect indices still referenced by surviving nodes + last_applied.
        let mut live_epoch = [false; EPOCH_POOL_CAP];
        let mut live_roots = [false; ROOTS_POOL_CAP];
        let mut live_slot = [false; SLOT_POOL_CAP];

        live_epoch[self.last_applied.epoch_idx as usize] = true;
        live_roots[self.last_applied.roots_idx as usize] = true;
        live_slot[self.last_applied.slot_idx as usize] = true;
        for node in self.fork_choice.nodes.as_slice() {
            live_epoch[node.state.epoch_idx as usize] = true;
            live_roots[node.state.roots_idx as usize] = true;
            live_slot[node.state.slot_idx as usize] = true;
        }

        // Reset allocator cursors to freed entries so they get reused first.
        // Best-effort: the ring allocator still works correctly without it,
        // but this reclaims sooner.
        for &ref_pruned in pruned.as_slice() {
            if !live_slot[ref_pruned.slot_idx as usize] {
                self.arena.slot.set_cursor(ref_pruned.slot_idx as usize);
            }
            if !live_roots[ref_pruned.roots_idx as usize] {
                self.arena.roots.set_cursor(ref_pruned.roots_idx as usize);
            }
            if !live_epoch[ref_pruned.epoch_idx as usize] {
                self.arena.epoch.set_cursor(ref_pruned.epoch_idx as usize);
            }
        }
    }

    fn handle_gossip(&mut self, m: NewGossipMsg, data: &[u8], producers: &mut Producers) {
        let feedback = match m.topic {
            GossipTopic::BeaconBlock => {
                Some(self.apply_block(data, m.ssz, RejectSource::Gossip, producers))
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
            Some(Feedback::Accept) => producers.produce(PeerEvent::SendGossip {
                originator_stream_id: m.stream_id,
                topic: m.topic,
                msg_hash: m.msg_hash,
                recv_ts: m.recv_ts,
                protobuf: m.protobuf,
            }),
            Some(Feedback::Ignore) | None => {}
        }
    }

    fn handle_rpc(
        &mut self,
        msg: RpcMsg,
        sender: P2pStreamId,
        data: &[u8],
        data_tcache: TCacheRead,
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
            let block_slot = SignedBeaconBlockView::slot(data);
            let f = self.apply_block(data, data_tcache, RejectSource::Rpc, producers);
            tracing::info!(
                block_slot,
                head_slot = self.head_state_slot(),
                "rpc block chunk applied: {:?}",
                f
            );
            match f {
                Feedback::Accept | Feedback::Ignore => {}
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
        self.ensure_shuffling_window(block_epoch);

        // On Reject, restore the cursors
        // so the freed slots are reused next time.
        let pre_slot = self.arena.slot.cursor();
        let pre_roots = self.arena.roots.cursor();
        let pre_vid = self.arena.vid.cursor();
        let pre_epoch = self.arena.epoch.cursor();
        let pre_longtail = self.arena.longtail.cursor();
        let pre_pending = self.pending_pool_next;

        let state_ref = self.cow_state_for_block(parsed.parent_state, parsed.body, block_epoch);

        // Build shuffling reference for attestation processing.
        let prev_epoch = block_epoch.saturating_sub(1);
        let find_entry = |epoch: Epoch| -> Option<usize> {
            self.shuffling_cache.entries.iter().position(|e| e.status == 1 && e.epoch == epoch)
        };
        let curr_idx = find_entry(block_epoch);
        let prev_idx = find_entry(prev_epoch);
        let shuffling_ref = match (curr_idx, prev_idx) {
            (Some(ci), Some(pi)) => {
                let c = &self.shuffling_cache.entries[ci];
                let p = &self.shuffling_cache.entries[pi];
                Some(state_transition::ShufflingRef {
                    current_epoch: block_epoch,
                    current_shuffled: c.shuffled_indices.as_slice(),
                    current_cps: shuffling::committees_per_slot(c.shuffled_indices.len()),
                    previous_epoch: prev_epoch,
                    previous_shuffled: p.shuffled_indices.as_slice(),
                    previous_cps: shuffling::committees_per_slot(p.shuffled_indices.len()),
                })
            }
            _ => None,
        };

        let imm = self.arena.imm.get(state_ref.imm_idx as usize);
        let vid = self.arena.vid.get_mut_checked(state_ref.vid_idx as usize, state_ref.vid_gen);
        let longtail = self.arena.longtail.get_mut(state_ref.longtail_idx as usize);
        let epoch =
            self.arena.epoch.get_mut_checked(state_ref.epoch_idx as usize, state_ref.epoch_gen);
        let roots =
            self.arena.roots.get_mut_checked(state_ref.roots_idx as usize, state_ref.roots_gen);
        let sd = self.arena.slot.get_mut_checked(state_ref.slot_idx as usize, state_ref.slot_gen);

        self.attestation_votes_scratch.clear();
        if let Err(e) = state_transition::apply_block(
            imm,
            vid,
            longtail,
            epoch,
            roots,
            sd,
            &mut self.pending_pool[state_ref.pending_idx as usize],
            data,
            parsed.block_slot,
            parsed.proposer_index,
            parsed.parent_root,
            parsed.body_root,
            parsed.state_root,
            shuffling_ref.as_ref(),
            &self.zero_hashes,
            &mut self.active_scratch,
            &mut self.postponed_scratch,
            &mut self.attestation_votes_scratch,
            &mut self.sig_batch,
        ) {
            // Roll back the speculative COW allocs.
            self.arena.slot.set_cursor(pre_slot);
            self.arena.roots.set_cursor(pre_roots);
            self.arena.vid.set_cursor(pre_vid);
            self.arena.epoch.set_cursor(pre_epoch);
            self.arena.longtail.set_cursor(pre_longtail);
            self.pending_pool_next = pre_pending;

            tracing::error!(error = %e, block_slot = %parsed.block_slot, head_slot=self.head_state_slot(), "block rejected");
            return Feedback::Reject(Some(parsed.block_root));
        }

        tracing::info!(
            block_slot = parsed.block_slot,
            head_slot = self.head_state_slot(),
            "applied block"
        );

        // Fold block-included attestations into the tracker.
        for i in 0..self.attestation_votes_scratch.len() {
            let (vi, root, ep) = self.attestation_votes_scratch[i];
            self.on_attestation(vi as usize, root, ep);
        }

        let sd = self.slot(&state_ref);
        // TODO(EL): extract execution_block_hash from the execution payload
        // header (sd.latest_execution_payload_header.block_hash) and pass it to
        // fork choice. After recomputing head, send engine_forkchoiceUpdatedV3
        // to the EL with the new head's execution_block_hash, finalized hash,
        // and safe hash. The EL response determines whether the head is VALID,
        // INVALID, or SYNCING (optimistic).
        self.fork_choice.on_block(&BlockImport {
            slot: parsed.block_slot,
            block_root: parsed.block_root,
            parent_root: parsed.parent_root,
            state_root: parsed.state_root,
            execution_block_hash: [0u8; 32],
            justified: sd.current_justified_checkpoint,
            finalized: sd.finalized_checkpoint,
            state_ref,
        });

        self.recompute_head();

        self.last_applied = LastApplied::from_ref(&state_ref);
        self.last_applied_block_root = parsed.block_root;
        Feedback::Accept
    }

    /// Pre-COW block validation: parse, parent-known, past-slot, proposer
    /// lookahead, BLS sig. Cheap, no state mutation. Returns parsed fields
    /// on accept; a structured `PrecheckError` on reject/ignore. Caller
    /// projects via `err.feedback()`.
    fn precheck_block<'a>(&self, data: &'a [u8]) -> Result<ParsedBlock<'a>, PrecheckError> {
        if !SignedBeaconBlockView::check_size(data) {
            return Err(PrecheckError::SizeMismatch {
                expected_min: silver_common::ssz_view::SIGNED_BEACON_BLOCK_MIN,
                expected_max: silver_common::ssz_view::SIGNED_BEACON_BLOCK_MAX,
                got: data.len(),
            });
        }
        let block_slot = SignedBeaconBlockView::slot(data);
        let proposer_index = SignedBeaconBlockView::proposer_index(data);
        let parent_root = *SignedBeaconBlockView::parent_root(data);
        let state_root = *SignedBeaconBlockView::state_root(data);

        let Some(parent_idx) = self.fork_choice.find_node_idx(&parent_root) else {
            let last_applied_slot = Self::last_applied_slot(&self.arena, self.last_applied).slot;
            return Err(PrecheckError::ParentMissing { parent_root, last_applied_slot, block_slot });
        };
        let parent_state = self.fork_choice.node(parent_idx).state;
        let parent_slot = Self::slot_at(&self.arena, parent_state).slot;

        // Past-slot blocks: a block must strictly extend its parent's slot.
        if block_slot <= parent_slot {
            return Err(PrecheckError::PastSlot { block_slot, parent_slot });
        }

        // Future-slot blocks: spec gossip rule says IGNORE blocks whose slot
        // exceeds wall slot.
        let wall_slot_plus_one = self.ticker.current_slot() + 1;
        if block_slot > wall_slot_plus_one {
            return Err(PrecheckError::FutureSlot { block_slot, wall_slot_plus_one });
        }

        let body = SignedBeaconBlockView::body(data);
        let body_root = ssz_hash::hash_tree_root_body(body, &self.zero_hashes);
        let block_header = types::BeaconBlockHeader {
            slot: block_slot,
            proposer_index,
            parent_root,
            state_root,
            body_root,
        };
        let block_root = ssz_hash::hash_tree_root_block_header(&block_header, &self.zero_hashes);

        let block_epoch = block_slot / SLOTS_PER_EPOCH;
        let parent_epoch = parent_slot / SLOTS_PER_EPOCH;
        // Fulu canonicalises proposer selection via `proposer_lookahead`
        // (spans current + next epoch, 64 slots). The lookahead is a field
        // of the parent's `SlotData`, fixed at the parent's prior epoch
        // boundary — read it from the parent, not `last_applied`.
        if block_epoch == parent_epoch || block_epoch == parent_epoch + 1 {
            let la_idx = (block_slot - parent_epoch * SLOTS_PER_EPOCH) as usize;
            if la_idx < types::PROPOSER_LOOKAHEAD_SIZE {
                let expected = Self::slot_at(&self.arena, parent_state).proposer_lookahead[la_idx];
                if proposer_index != expected {
                    return Err(PrecheckError::ProposerLookaheadMismatch {
                        expected,
                        got: proposer_index,
                        block_root,
                    });
                }
            }
        }

        let imm = Self::imm_at(&self.arena, parent_state);
        let vid = Self::vid_at(&self.arena, parent_state);
        if proposer_index as usize >= vid.validator_cnt {
            return Err(PrecheckError::ProposerIndexTooBig {
                got: proposer_index,
                validator_cnt: vid.validator_cnt,
                block_root,
            });
        }
        let fork_version = bls::fork_version_at_epoch(
            imm.fork.epoch,
            imm.fork.previous_version,
            imm.fork.current_version,
            block_epoch,
        );
        let proposer_pubkey = &vid.val_pubkey_decompressed[proposer_index as usize];
        if !bls::verify_block_signature(
            data,
            proposer_pubkey,
            &body_root,
            fork_version,
            &imm.genesis_validators_root,
            &self.zero_hashes,
        ) {
            return Err(PrecheckError::InvalidBls {
                proposer_index,
                pubkey: vid.val_pubkey[proposer_index as usize],
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
            body,
            parent_state,
        })
    }

    fn cow_state_for_block(
        &mut self,
        parent: BeaconStateRef,
        body: &[u8],
        block_epoch: Epoch,
    ) -> BeaconStateRef {
        let new_slot_idx = self.arena.slot.copy_from(parent.slot_idx as usize);
        let new_slot_gen = self.arena.slot.gen_at(new_slot_idx);
        let new_roots_idx = self.arena.roots.copy_from(parent.roots_idx as usize);
        let new_roots_gen = self.arena.roots.gen_at(new_roots_idx);
        let new_pending_idx = self.alloc_pending();
        debug_assert_ne!(new_pending_idx, parent.pending_idx as usize);
        // Split borrow because src and dst index the same `pending_pool`.
        let pool = self.pending_pool.as_mut_slice();
        let (src, dst) = if (parent.pending_idx as usize) < new_pending_idx {
            let (lo, hi) = pool.split_at_mut(new_pending_idx);
            (&lo[parent.pending_idx as usize], &mut hi[0])
        } else {
            let (lo, hi) = pool.split_at_mut(parent.pending_idx as usize);
            (&hi[0], &mut lo[new_pending_idx])
        };
        dst.pending_deposits.clone_from(&src.pending_deposits);
        dst.pending_partial_withdrawals.clone_from(&src.pending_partial_withdrawals);
        dst.pending_consolidations.clone_from(&src.pending_consolidations);

        let mut state_ref = BeaconStateRef {
            imm_idx: parent.imm_idx,
            vid_idx: parent.vid_idx,
            vid_gen: parent.vid_gen,
            longtail_idx: parent.longtail_idx,
            epoch_idx: parent.epoch_idx,
            epoch_gen: parent.epoch_gen,
            roots_idx: new_roots_idx as u8,
            roots_gen: new_roots_gen,
            slot_idx: new_slot_idx as u8,
            slot_gen: new_slot_gen,
            pending_idx: new_pending_idx as u8,
        };

        // TODO(simpler): body_mutation_hints duplicates the SSZ offset parsing
        // that process_block_body does. Combine both into one parse pass, or
        // drop hints and conservatively COW (profile to confirm cost).
        let (may_mut_vid, may_mut_epoch) = body_mutation_hints(body);
        let parent_epoch = self.slot(&state_ref).slot / SLOTS_PER_EPOCH;
        let crosses_epoch = block_epoch != parent_epoch;

        if may_mut_vid {
            state_ref.vid_idx = self.arena.vid.copy_from(state_ref.vid_idx as usize) as u8;
            state_ref.vid_gen = self.arena.vid.gen_at(state_ref.vid_idx as usize);
        }
        // COW epoch if this block mutates it, OR if it crosses an epoch
        // boundary (process_slots runs epoch transition on the EpochData).
        if may_mut_epoch || crosses_epoch {
            state_ref.epoch_idx = self.arena.epoch.copy_from(state_ref.epoch_idx as usize) as u8;
            state_ref.epoch_gen = self.arena.epoch.gen_at(state_ref.epoch_idx as usize);
        }
        // COW longtail at sync-committee / historical-summaries boundaries.
        if crosses_epoch && longtail_rotates_at_epoch(block_epoch) {
            state_ref.longtail_idx =
                self.arena.longtail.copy_from(state_ref.longtail_idx as usize) as u8;
        }

        state_ref
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

        // Validate committee membership via ShufflingCache.
        let att_epoch = att_slot / SLOTS_PER_EPOCH;
        let entry = match self.get_shuffling(att_epoch) {
            Some(e) => e,
            None => return Feedback::Ignore,
        };

        let cps = shuffling::committees_per_slot(entry.shuffled_indices.len());
        if committee_index >= cps {
            return Feedback::Reject(None);
        }
        let committee = shuffling::get_beacon_committee(
            entry.shuffled_indices.as_slice(),
            att_slot,
            committee_index,
            cps,
        );

        if !committee.contains(&(attester_index as u32)) {
            return Feedback::Reject(None);
        }

        let canon = self.canonical_state_ref();
        let imm = Self::imm_at(&self.arena, canon);
        let vid = Self::vid_at(&self.arena, canon);
        if attester_index >= vid.validator_cnt {
            return Feedback::Reject(None);
        }
        let fork_version = bls::fork_version_at_epoch(
            imm.fork.epoch,
            imm.fork.previous_version,
            imm.fork.current_version,
            target_epoch,
        );
        if !bls::verify_single_attestation(
            buf,
            &vid.val_pubkey_decompressed[attester_index],
            fork_version,
            &imm.genesis_validators_root,
            &self.zero_hashes,
        ) {
            return Feedback::Reject(None);
        }

        self.on_attestation(attester_index, block_root, target_epoch);
        Feedback::Accept
    }

    fn handle_aggregate_and_proof(&mut self, data: &[u8]) -> Feedback {
        if !SignedAggregateAndProofView::check_size(data) {
            return Feedback::Reject(None);
        }

        let outer_sig = SignedAggregateAndProofView::signature(data);
        let aggregator_index = SignedAggregateAndProofView::aggregator_index(data) as usize;
        let selection_proof = SignedAggregateAndProofView::selection_proof(data);
        let agg_slot = SignedAggregateAndProofView::agg_slot(data);
        let agg_data_index = SignedAggregateAndProofView::agg_data_index(data);
        let beacon_block_root = *SignedAggregateAndProofView::agg_beacon_block_root(data);
        let target_epoch = SignedAggregateAndProofView::agg_target_epoch(data);
        let target_root = *SignedAggregateAndProofView::agg_target_root(data);
        let committee_bits =
            u64::from_le_bytes(*SignedAggregateAndProofView::agg_committee_bits(data));
        let agg_sig = SignedAggregateAndProofView::agg_signature(data);
        let agg_data = SignedAggregateAndProofView::agg_data(data);
        let aggregation_bits = SignedAggregateAndProofView::agg_aggregation_bits(data);
        let aggregate_bytes = SignedAggregateAndProofView::aggregate(data);

        if agg_data_index != 0 {
            return Feedback::Reject(None);
        }
        let att_epoch = agg_slot / SLOTS_PER_EPOCH;
        if target_epoch != att_epoch {
            return Feedback::Reject(None);
        }
        // Spec slot window: aggregate.slot <= current_slot <=
        // aggregate.slot + ATTESTATION_PROPAGATION_SLOT_RANGE.
        // TODO Sub-slot MAXIMUM_GOSSIP_CLOCK_DISPARITY tolerance not yet wired through
        // the ticker.
        let wall = self.ticker.current_slot();
        if agg_slot > wall || agg_slot.saturating_add(ATTESTATION_PROPAGATION_SLOT_RANGE) < wall {
            return Feedback::Ignore;
        }
        // Fulu gossip rule: exactly one committee bit set.
        if committee_bits.count_ones() != 1 {
            return Feedback::Reject(None);
        }
        let committee_index = committee_bits.trailing_zeros() as usize;

        // beacon_block_root in fork choice + target.root is its ancestor at
        // target-epoch's first slot. Implies descendant-of-finalized.
        match self
            .fork_choice
            .get_checkpoint_block(&beacon_block_root, target_epoch * SLOTS_PER_EPOCH)
        {
            Some(r) if r == target_root => {}
            Some(_) => return Feedback::Reject(None),
            None => return Feedback::Ignore,
        }

        let canon = self.canonical_state_ref();
        let imm = Self::imm_at(&self.arena, canon);
        let vid = Self::vid_at(&self.arena, canon);
        if aggregator_index >= vid.validator_cnt {
            return Feedback::Ignore;
        }

        let shuffled = match self
            .shuffling_cache
            .entries
            .iter()
            .find(|e| e.status == 1 && e.epoch == att_epoch)
        {
            Some(e) => e.shuffled_indices.as_slice(),
            None => return Feedback::Ignore,
        };
        let cps = shuffling::committees_per_slot(shuffled.len());
        if committee_index >= cps {
            return Feedback::Reject(None);
        }
        let committee = shuffling::get_beacon_committee(shuffled, agg_slot, committee_index, cps);
        if !committee.contains(&(aggregator_index as u32)) {
            return Feedback::Reject(None);
        }
        let committee_len = committee.len();

        // Build participant index list from (committee, aggregation_bits).
        self.active_scratch.clear();
        for (j, &vi32) in committee.iter().enumerate() {
            let byte_idx = j / 8;
            let bit_idx = j % 8;
            if byte_idx >= aggregation_bits.len() ||
                aggregation_bits[byte_idx] & (1 << bit_idx) == 0
            {
                continue;
            }
            if vi32 as usize >= vid.validator_cnt {
                return Feedback::Reject(None);
            }
            self.active_scratch.push(vi32);
        }
        if self.active_scratch.is_empty() {
            return Feedback::Reject(None);
        }

        // is_aggregator: hash(selection_proof)[0..8] LE mod max(1, |C|/16) == 0.
        if !is_aggregator(committee_len, selection_proof) {
            return Feedback::Reject(None);
        }

        let fv = bls::fork_version_at_epoch(
            imm.fork.epoch,
            imm.fork.previous_version,
            imm.fork.current_version,
            target_epoch,
        );

        // (1) selection_proof — signer = aggregator, msg = htr(uint64(slot)).
        let slot_root = ssz_hash::uint64_chunk(agg_slot);
        let domain_sp =
            bls::compute_domain(bls::DOMAIN_SELECTION_PROOF, fv, &imm.genesis_validators_root);
        let sr_sp = bls::compute_signing_root(&slot_root, &domain_sp);

        // (2) outer AggregateAndProof signature.
        let agg_proof_root = ssz_hash::hash_tree_root_aggregate_and_proof(
            aggregator_index as u64,
            aggregate_bytes,
            selection_proof,
            &self.zero_hashes,
        );
        let domain_aap =
            bls::compute_domain(bls::DOMAIN_AGGREGATE_AND_PROOF, fv, &imm.genesis_validators_root);
        let sr_aap = bls::compute_signing_root(&agg_proof_root, &domain_aap);

        // (3) inner aggregate signature over AttestationData.
        let data_root = ssz_hash::hash_attestation_data(agg_data, &self.zero_hashes);
        let domain_att =
            bls::compute_domain(bls::DOMAIN_BEACON_ATTESTER, fv, &imm.genesis_validators_root);
        let sr_att = bls::compute_signing_root(&data_root, &domain_att);

        self.sig_batch.clear();
        let aggregator_pk = &vid.val_pubkey_decompressed[aggregator_index];
        self.sig_batch.push_one(aggregator_pk, selection_proof, sr_sp);
        self.sig_batch.push_one(aggregator_pk, outer_sig, sr_aap);
        self.sig_batch.push_aggregate(
            self.active_scratch.iter().map(|&vi| &vid.val_pubkey_decompressed[vi as usize]),
            agg_sig,
            sr_att,
        );
        if !self.sig_batch.verify_all() {
            return Feedback::Reject(None);
        }

        // Fold per-participant votes via `on_attestation` so the spec's
        // newer-epoch-only rule applies (same as the SingleAttestation path).
        for i in 0..self.active_scratch.len() {
            let vi = self.active_scratch[i] as usize;
            self.on_attestation(vi, beacon_block_root, target_epoch);
        }
        Feedback::Accept
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

        let canon = self.canonical_state_ref();
        let imm = Self::imm_at(&self.arena, canon);
        let vid = Self::vid_at(&self.arena, canon);
        let epoch_data = Self::epoch_at(&self.arena, canon);
        let sd = Self::slot_at(&self.arena, canon);
        let pq = &self.pending_pool[canon.pending_idx as usize];
        let current_epoch = sd.slot / SLOTS_PER_EPOCH;

        // Out-of-range index: state may be stale, defer.
        if vi >= vid.validator_cnt {
            return Feedback::Ignore;
        }
        if let Err(e) =
            validate::validate_voluntary_exit(vid, epoch_data, vi, exit_epoch, current_epoch)
        {
            tracing::debug!(error = %e, "voluntary_exit gossip rejected");
            return Feedback::Reject(None);
        }
        if state_transition::get_pending_balance_to_withdraw(pq, vi) != 0 {
            return Feedback::Reject(None);
        }

        let object_root =
            ssz_hash::hash_tree_root_voluntary_exit(exit_epoch, vi_u, &self.zero_hashes);
        let domain = bls::compute_domain(
            bls::DOMAIN_VOLUNTARY_EXIT,
            imm.capella_fork_version,
            &imm.genesis_validators_root,
        );
        let signing_root = bls::compute_signing_root(&object_root, &domain);
        let sig = SignedVoluntaryExitView::signature(buf);
        if !bls::verify_one(&vid.val_pubkey_decompressed[vi], sig, &signing_root) {
            return Feedback::Reject(None);
        }
        Feedback::Accept
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

        let canon = self.canonical_state_ref();
        let imm = Self::imm_at(&self.arena, canon);
        let vid = Self::vid_at(&self.arena, canon);
        let epoch_data = Self::epoch_at(&self.arena, canon);
        let sd = Self::slot_at(&self.arena, canon);
        let current_epoch = sd.slot / SLOTS_PER_EPOCH;

        let proposer_index = ProposerSlashingView::h1_proposer_index(buf) as usize;
        if proposer_index >= vid.validator_cnt {
            return Feedback::Ignore;
        }
        if !state_transition::is_slashable_validator(epoch_data, proposer_index, current_epoch) {
            return Feedback::Reject(None);
        }

        // Headers may straddle fork boundary; pick fork version per slot.
        let h1_epoch = ProposerSlashingView::h1_slot(buf) / SLOTS_PER_EPOCH;
        let h2_epoch = ProposerSlashingView::h2_slot(buf) / SLOTS_PER_EPOCH;
        let fv1 = bls::fork_version_at_epoch(
            imm.fork.epoch,
            imm.fork.previous_version,
            imm.fork.current_version,
            h1_epoch,
        );
        let fv2 = bls::fork_version_at_epoch(
            imm.fork.epoch,
            imm.fork.previous_version,
            imm.fork.current_version,
            h2_epoch,
        );
        let sr1 = state_transition::signing_root_for_block_header(
            &buf[0..208],
            fv1,
            &imm.genesis_validators_root,
            &self.zero_hashes,
        );
        let sr2 = state_transition::signing_root_for_block_header(
            &buf[208..416],
            fv2,
            &imm.genesis_validators_root,
            &self.zero_hashes,
        );
        let sig1 = ProposerSlashingView::h1_signature(buf);
        let sig2 = ProposerSlashingView::h2_signature(buf);
        let pubkey = &vid.val_pubkey_decompressed[proposer_index];

        self.sig_batch.clear();
        self.sig_batch.push_one(pubkey, sig1, sr1);
        self.sig_batch.push_one(pubkey, sig2, sr2);
        if !self.sig_batch.verify_all() {
            return Feedback::Reject(None);
        }
        Feedback::Accept
    }

    fn handle_attester_slashing(&mut self, data: &[u8]) -> Feedback {
        if !AttesterSlashingView::check_size(data) {
            return Feedback::Reject(None);
        }
        let canon = self.canonical_state_ref();
        let imm = Self::imm_at(&self.arena, canon);
        let vid = Self::vid_at(&self.arena, canon);
        let epoch_data = Self::epoch_at(&self.arena, canon);
        let sd = Self::slot_at(&self.arena, canon);
        if state_transition::validate_attester_slashing_for_gossip(
            imm,
            vid,
            epoch_data,
            sd,
            data,
            &mut self.sig_batch,
            &self.zero_hashes,
        ) {
            Feedback::Accept
        } else {
            Feedback::Reject(None)
        }
    }

    fn handle_bls_to_execution_change(&mut self, data: &[u8]) -> Feedback {
        if data.len() != SIGNED_BLS_CHANGE_SIZE {
            return Feedback::Reject(None);
        }
        let buf: &[u8; SIGNED_BLS_CHANGE_SIZE] = data[..SIGNED_BLS_CHANGE_SIZE].try_into().unwrap();

        let canon = self.canonical_state_ref();
        let imm = Self::imm_at(&self.arena, canon);
        let vid = Self::vid_at(&self.arena, canon);

        let vi_u = SignedBlsToExecutionChangeView::validator_index(buf);
        let vi = vi_u as usize;
        if vi >= vid.validator_cnt {
            return Feedback::Ignore;
        }
        let from_pubkey = SignedBlsToExecutionChangeView::from_bls_pubkey(buf);
        let to_address = SignedBlsToExecutionChangeView::to_execution_address(buf);
        if let Err(e) = validate::validate_bls_to_execution_change(vid, vi, from_pubkey) {
            tracing::debug!(error = %e, "bls_to_execution_change gossip rejected");
            return Feedback::Reject(None);
        }

        let object_root =
            ssz_hash::hash_tree_root_bls_change(vi_u, from_pubkey, to_address, &self.zero_hashes);
        let domain = bls::compute_domain(
            bls::DOMAIN_BLS_TO_EXECUTION_CHANGE,
            imm.genesis_fork_version,
            &imm.genesis_validators_root,
        );
        let signing_root = bls::compute_signing_root(&object_root, &domain);
        let sig = SignedBlsToExecutionChangeView::signature(buf);
        // Signer is the message's `from_bls_pubkey` — not the validator's
        // cached signing key — so decompress inline.
        if !bls::verify_one_compressed(from_pubkey, sig, &signing_root) {
            return Feedback::Reject(None);
        }
        Feedback::Accept
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
            }
        });
        self.gossip_consumer.free();

        // PM drives sync. Mirror the latest target into `mode`, used only
        // to gate gossip/slot-tick processing. Stale events in the queue
        // collapse — only the latest wins.
        adapter.consume(|target: SyncUpdate, _producers| {
            let new_sync = match target {
                SyncUpdate::SyncingFinalised { .. } | SyncUpdate::SyncingHead { .. } => {
                    Mode::Syncing
                }
                SyncUpdate::Following => Mode::Following,
            };
            if new_sync != self.mode {
                tracing::info!(
                    head_slot = Self::last_applied_slot(&self.arena, self.last_applied).slot,
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
                        ssz,
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
    epoch.is_multiple_of(types::EPOCHS_PER_SYNC_COMMITTEE_PERIOD) || epoch.is_multiple_of(hs_period)
}

/// Cheap offset-based inspection of a BeaconBlockBody to decide which tiers
/// may be mutated by block processing. Returns (may_mut_vid, may_mut_epoch).
/// Conservative: returns true whenever the corresponding operation list is
/// non-empty. Variable-length lists are detected by end > start; fixed-size
/// element lists count bytes.
fn body_mutation_hints(body: &[u8]) -> (bool, bool) {
    if body.len() < 396 {
        return (true, true);
    }
    let off = |pos: usize| -> usize {
        u32::from_le_bytes(body[pos..pos + 4].try_into().unwrap()) as usize
    };
    let ps = off(200);
    let as_ = off(204);
    let att = off(208);
    let dep = off(212);
    let ve = off(216);
    let ep = off(380);
    let bls = off(384);
    let blob = off(388);
    let er = off(392);

    let has_proposer_slashings = as_ > ps;
    let has_attester_slashings = att > as_;
    let has_deposits = ve > dep;
    let has_voluntary_exits = ep > ve;
    let has_bls_changes = blob > bls;
    let has_exec_requests = body.len() > er;

    let may_mut_vid = has_deposits || has_bls_changes || has_exec_requests;
    let may_mut_epoch = has_proposer_slashings ||
        has_attester_slashings ||
        has_voluntary_exits ||
        has_deposits ||
        has_exec_requests;
    (may_mut_vid, may_mut_epoch)
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

    use silver_common::{TCache, TCacheProducer, ssz_view::SIGNED_AGG_PROOF_MIN};

    use super::*;
    use crate::types::Checkpoint;

    const MAX_EFFECTIVE_BALANCE: u64 = 32_000_000_000;

    fn make_tile() -> BeaconStateTile {
        make_tile_at_wall_slot(1)
    }

    /// Construct a tile whose ticker reports `wall_slot` as the current slot.
    /// Used by the aggregate Accept test to widen the slot-window check so it
    /// covers wherever the committee for validator 0 lands.
    fn make_tile_at_wall_slot(wall_slot: u64) -> BeaconStateTile {
        let secs_per_slot = 12u64;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let genesis = now.saturating_sub(wall_slot * secs_per_slot + 1);
        let ticker = SlotTicker::new(genesis, Duration::from_secs(12), Duration::from_secs(4));
        let gossip_p = TCache::producer(1 << 20);
        let event_p = TCache::producer(1 << 20);
        let gossip_c = gossip_p.cache_ref().random_access(true).unwrap();
        let rpc_c = event_p.cache_ref().random_access(true).unwrap();
        BeaconStateTile::new_heap(ticker, gossip_c, rpc_c, &[])
    }

    fn seed_tile(tile: &mut BeaconStateTile, n: usize, start_slot: Slot) {
        let root = [0x01u8; 32];
        let cp = Checkpoint { epoch: 0, root };

        tile.arena.vid.get_mut(0).validator_cnt = n;
        let epoch = tile.arena.epoch.get_mut(0);
        for i in 0..n {
            epoch.val_effective_balance[i] = MAX_EFFECTIVE_BALANCE;
            epoch.val_activation_epoch[i] = 0;
            epoch.val_exit_epoch[i] = u64::MAX;
            epoch.val_withdrawable_epoch[i] = u64::MAX;
        }

        let sd = tile.arena.slot.get_mut(0);
        sd.slot = start_slot;
        sd.current_justified_checkpoint = cp;
        sd.finalized_checkpoint = cp;
        for i in 0..n {
            sd.balances[i] = MAX_EFFECTIVE_BALANCE;
        }

        let anchor_ref = tile.synth_anchor_ref();
        tile.fork_choice = ForkChoice::init(cp, cp, start_slot, root, root, anchor_ref);
        tile.last_applied_block_root = root;
        tile.mode = Mode::Following;

        // Precompute shuffling for the start epoch.
        let start_epoch = start_slot / SLOTS_PER_EPOCH;
        tile.ensure_shuffling(start_epoch);
    }

    /// Like `seed_tile` but installs real BLS pubkeys for validators `0..n`
    /// (sk_idx = i % PRIVKEY_HEX.len()). Sets BLS-prefix withdrawal credentials
    /// so `validate_bls_to_execution_change` will accept the corresponding
    /// `from_bls_pubkey`. Required for Accept-path tests of gossip handlers.
    fn seed_tile_with_keys(tile: &mut BeaconStateTile, n: usize, start_slot: Slot) {
        seed_tile(tile, n, start_slot);

        let vid = tile.arena.vid.get_mut(0);
        for i in 0..n {
            let sk_idx = i % crate::test_signing::PRIVKEY_HEX.len();
            let pk = crate::test_signing::pubkey_pk(sk_idx);
            let pk_bytes = pk.to_bytes();
            vid.val_pubkey[i] = pk_bytes;
            vid.val_pubkey_decompressed[i] = pk;

            // BLS-prefix withdrawal creds: creds[0]=0x00, creds[1..]=hash(pk)[1..].
            let mut creds = ssz_hash::sha256(&pk_bytes);
            creds[0] = 0x00;
            vid.val_withdrawal_credentials[i] = creds;
        }
    }

    #[test]
    fn slot_advance_skip_multiple() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 10);

        tile.on_slot_start(15);
        assert_eq!(BeaconStateTile::last_applied_slot(&tile.arena, tile.last_applied).slot, 15);
    }

    #[test]
    fn slot_advance_noop_past_slot() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 10);

        tile.on_slot_start(5);
        assert_eq!(BeaconStateTile::last_applied_slot(&tile.arena, tile.last_applied).slot, 10);
    }

    #[test]
    fn slot_advance_crosses_epoch_boundary() {
        let mut tile = make_tile();
        // Start at slot 30 (epoch 0). Advance to slot 34 (epoch 1).
        // Epoch transition should fire at end of slot 31 (since (31+1) % 32 == 0).
        seed_tile(&mut tile, 4, 30);

        let old_epoch_idx = tile.last_applied.epoch_idx;
        tile.on_slot_start(34);

        assert_eq!(BeaconStateTile::last_applied_slot(&tile.arena, tile.last_applied).slot, 34);
        // Epoch transition allocated a new EpochData.
        assert_ne!(tile.last_applied.epoch_idx, old_epoch_idx);
    }

    #[test]
    fn slot_advance_crosses_two_epoch_boundaries() {
        let mut tile = make_tile();
        // Start at slot 30. Advance to slot 66 (epoch 2).
        // Epoch boundaries at slot 31 and slot 63.
        seed_tile(&mut tile, 4, 30);

        tile.on_slot_start(66);

        assert_eq!(BeaconStateTile::last_applied_slot(&tile.arena, tile.last_applied).slot, 66);
    }

    #[test]
    fn attestation_too_short_ignored() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 10);

        let buf = [0u8; 100]; // too short
        tile.handle_attestation(&buf);
        // No crash, no change.
        assert_eq!(tile.vote_tracker.votes[0].next_epoch, 0);
    }

    #[test]
    fn attestation_updates_vote_tracker() {
        use blst::min_pk::{PublicKey, SecretKey};
        use silver_common::ssz_view::SINGLE_ATT_SIZE;

        use crate::shuffling;

        let mut tile = make_tile();
        let n = 128;
        seed_tile(&mut tile, n, 0);

        let attester: u32 = 5;

        // Spec test privkey 0; install both compressed + decompressed
        // copies so the gossip path reads the cached pubkey.
        const SK_BYTES: [u8; 32] = [
            0x26, 0x3d, 0xbd, 0x79, 0x2f, 0x5b, 0x1b, 0xe4, 0x7e, 0xd8, 0x5f, 0x89, 0x38, 0xc0,
            0xf2, 0x95, 0x86, 0xaf, 0x0d, 0x3a, 0xc7, 0xb9, 0x77, 0xf2, 0x1c, 0x27, 0x8f, 0xe1,
            0x46, 0x20, 0x40, 0xe3,
        ];
        let sk = SecretKey::from_bytes(&SK_BYTES).unwrap();
        let pk: PublicKey = sk.sk_to_pk();
        let vid = tile.arena.vid.get_mut(0);
        vid.val_pubkey[attester as usize] = pk.to_bytes();
        vid.val_pubkey_decompressed[attester as usize] = pk;

        // Find which (slot, committee_index) contains the attester.
        let entry = tile.get_shuffling(0).unwrap();
        let cps = shuffling::committees_per_slot(entry.shuffled_indices.len());
        let mut att_slot = 0u64;
        let mut att_ci = 0usize;
        let mut found = false;
        'outer: for s in 0..SLOTS_PER_EPOCH {
            for ci in 0..cps {
                let committee =
                    shuffling::get_beacon_committee(entry.shuffled_indices.as_slice(), s, ci, cps);
                if committee.contains(&attester) {
                    att_slot = s;
                    att_ci = ci;
                    found = true;
                    break 'outer;
                }
            }
        }
        assert!(found);

        // Build SingleAttestation (240B, all fixed).
        let mut buf = [0u8; SINGLE_ATT_SIZE];
        buf[0..8].copy_from_slice(&(att_ci as u64).to_le_bytes()); // committee_index
        buf[8..16].copy_from_slice(&(attester as u64).to_le_bytes()); // attester_index
        buf[16..24].copy_from_slice(&att_slot.to_le_bytes()); // slot
        buf[32] = 0xAA; // beacon_block_root[0]
        // index, source, target left zero — handle_attestation does not
        // validate AttestationData beyond what BLS verifies via signing root.

        // Sign over the AttestationData signing root.
        let imm = BeaconStateTile::last_applied_imm(&tile.arena, tile.last_applied);
        let fork_version = bls::fork_version_at_epoch(
            imm.fork.epoch,
            imm.fork.previous_version,
            imm.fork.current_version,
            0, // target_epoch
        );
        let data: &[u8; 128] = buf[16..144].try_into().unwrap();
        let object_root = ssz_hash::hash_attestation_data(data, &tile.zero_hashes);
        let domain = bls::compute_domain(
            bls::DOMAIN_BEACON_ATTESTER,
            fork_version,
            &imm.genesis_validators_root,
        );
        let signing_root = bls::compute_signing_root(&object_root, &domain);
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
        let sig = sk.sign(&signing_root, dst, &[]).to_bytes();
        buf[144..240].copy_from_slice(&sig);

        let fb = tile.handle_attestation(&buf);
        assert_eq!(fb, Feedback::Accept);
        assert_eq!(tile.vote_tracker.votes[attester as usize].next_root[0], 0xAA);
        assert_eq!(tile.vote_tracker.votes[attester as usize].next_epoch, 0);
    }

    #[test]
    fn block_unknown_parent_rejected() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 10);

        // Build minimal SignedBeaconBlock buffer.
        let mut buf = vec![0u8; 200];
        // slot at offset 100.
        buf[100..108].copy_from_slice(&11u64.to_le_bytes());
        // proposer_index at offset 108.
        buf[108..116].copy_from_slice(&0u64.to_le_bytes());
        // parent_root at offset 116 — unknown root.
        buf[116] = 0xFF;

        let head_before = tile.last_applied;
        tile.handle_block(&buf);

        // Block rejected (orphan), head unchanged.
        assert_eq!(tile.last_applied.slot_idx, head_before.slot_idx);
        assert_eq!(tile.fork_choice.nodes.len(), 1); // only genesis
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
        seed_tile_with_keys(&mut tile, 4, 256 * SLOTS_PER_EPOCH);

        let imm = *BeaconStateTile::last_applied_imm(&tile.arena, tile.last_applied);
        let buf = crate::test_signing::sign_voluntary_exit(0, 0, 0, &imm, &tile.zero_hashes);
        assert_eq!(tile.handle_voluntary_exit(&buf), Feedback::Accept);
    }

    #[test]
    fn ps_identical_headers_rejected() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 0);
        // 416B all-zero — h1 == h2, validate_proposer_slashing rejects.
        let buf = [0u8; PROPOSER_SLASHING_SIZE];
        assert_eq!(tile.handle_proposer_slashing(&buf), Feedback::Reject(None));
    }

    #[test]
    fn ps_unknown_proposer_ignored() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 0);
        // Two distinct headers, same slot, same proposer (=999, OOR).
        let mut buf = [0u8; PROPOSER_SLASHING_SIZE];
        buf[8..16].copy_from_slice(&999u64.to_le_bytes());
        buf[216..224].copy_from_slice(&999u64.to_le_bytes());
        // Distinct body_root in second header.
        buf[208 + 80] = 0xFF;
        assert_eq!(tile.handle_proposer_slashing(&buf), Feedback::Ignore);
    }

    #[test]
    fn ps_accept() {
        let mut tile = make_tile();
        seed_tile_with_keys(&mut tile, 4, 0);
        let imm = *BeaconStateTile::last_applied_imm(&tile.arena, tile.last_applied);
        let buf = crate::test_signing::sign_proposer_slashing(0, 0, 0, &imm, &tile.zero_hashes);
        assert_eq!(tile.handle_proposer_slashing(&buf), Feedback::Accept);
    }

    #[test]
    fn ps_mismatched_slot_rejected() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 0);
        let mut buf = [0u8; PROPOSER_SLASHING_SIZE];
        // Both proposers = 0 (default); slots differ → validate_proposer_slashing
        // rejects.
        buf[208] = 1; // h2.slot LE byte 0
        assert_eq!(tile.handle_proposer_slashing(&buf), Feedback::Reject(None));
    }

    #[test]
    fn ps_mismatched_proposer_rejected() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 0);
        let mut buf = [0u8; PROPOSER_SLASHING_SIZE];
        // h1.proposer_index = 0, h2.proposer_index = 1 → reject.
        buf[208 + 8] = 1;
        assert_eq!(tile.handle_proposer_slashing(&buf), Feedback::Reject(None));
    }

    #[test]
    fn as_zero_intersection_rejected() {
        // Build a structurally-valid slashing with disjoint attesting_indices
        // (no intersection → no slashable validator).
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 0);
        let imm = *BeaconStateTile::last_applied_imm(&tile.arena, tile.last_applied);
        // ia1 signs from vi=0, ia2 from vi=1; double-vote on data (different
        // beacon_block_root) but indices disjoint.
        let ia1 = build_ia_with_indices(&imm, &tile.zero_hashes, 0, 0xAA, &[0]);
        let ia2 = build_ia_with_indices(&imm, &tile.zero_hashes, 0, 0xBB, &[1]);
        let buf = wrap_attester_slashing(&ia1, &ia2);
        assert_eq!(tile.handle_attester_slashing(&buf), Feedback::Reject(None));
    }

    #[test]
    fn as_accept() {
        let mut tile = make_tile();
        seed_tile_with_keys(&mut tile, 4, 0);
        let imm = *BeaconStateTile::last_applied_imm(&tile.arena, tile.last_applied);
        // Both ia signed by sk_idx=0 covering vi=0 → double-vote, vi=0 is
        // slashable in head state.
        let buf = crate::test_signing::sign_attester_slashing_double_vote(
            0,
            0,
            0,
            0,
            &imm,
            &tile.zero_hashes,
        );
        assert_eq!(tile.handle_attester_slashing(&buf), Feedback::Accept);
    }

    /// Disjoint attesting_indices but valid BLS sigs on each side — ensures the
    /// intersection check fires before sig verify (and isn't masked by the
    /// zero-sig variant's structural rejects).
    #[test]
    fn as_zero_intersection_with_valid_sigs_rejected() {
        let mut tile = make_tile();
        seed_tile_with_keys(&mut tile, 4, 0);
        let imm = *BeaconStateTile::last_applied_imm(&tile.arena, tile.last_applied);
        // ia1: sk=0/vi=0 ; ia2: sk=1/vi=1 → same target_epoch, different
        // beacon_block_root (double-vote on data), but indices {0} ∩ {1} = ∅.
        let ia1 = crate::test_signing::build_indexed_attestation(
            0,
            0,
            0,
            0,
            0,
            0xAA,
            &imm,
            &tile.zero_hashes,
        );
        let ia2 = crate::test_signing::build_indexed_attestation(
            1,
            1,
            0,
            0,
            0,
            0xBB,
            &imm,
            &tile.zero_hashes,
        );
        let buf = wrap_attester_slashing(&ia1, &ia2);
        assert_eq!(tile.handle_attester_slashing(&buf), Feedback::Reject(None));
    }

    /// Build an IndexedAttestation with attesting_indices = `indices`. Sig is
    /// left zero — only used for structural / state-derived reject tests.
    fn build_ia_with_indices(
        _imm: &types::Immutable,
        _zh: &[B256],
        target_epoch: u64,
        beacon_block_root_marker: u8,
        indices: &[u64],
    ) -> Vec<u8> {
        let mut buf = vec![0u8; 228 + indices.len() * 8];
        let indices_off: u32 = 228;
        buf[0..4].copy_from_slice(&indices_off.to_le_bytes());
        buf[20] = beacon_block_root_marker;
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
    fn bls_change_unknown_validator_ignored() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 0);
        let mut buf = [0u8; SIGNED_BLS_CHANGE_SIZE];
        buf[0..8].copy_from_slice(&999u64.to_le_bytes());
        assert_eq!(tile.handle_bls_to_execution_change(&buf), Feedback::Ignore);
    }

    #[test]
    fn bls_change_wrong_prefix_rejected() {
        // Validator 0 with non-BLS withdrawal prefix → validate rejects.
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 0);
        tile.arena.vid.get_mut(0).val_withdrawal_credentials[0][0] = 0x01; // ETH1 prefix
        let buf = [0u8; SIGNED_BLS_CHANGE_SIZE]; // vi=0
        assert_eq!(tile.handle_bls_to_execution_change(&buf), Feedback::Reject(None));
    }

    #[test]
    fn bls_change_accept() {
        let mut tile = make_tile();
        seed_tile_with_keys(&mut tile, 4, 0);
        let imm = *BeaconStateTile::last_applied_imm(&tile.arena, tile.last_applied);
        let to_addr = [0x42u8; 20];
        let buf = crate::test_signing::sign_bls_to_execution_change(
            0,
            0,
            &to_addr,
            &imm,
            &tile.zero_hashes,
        );
        assert_eq!(tile.handle_bls_to_execution_change(&buf), Feedback::Accept);
    }

    #[test]
    fn agg_multi_committee_bits_rejected() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 0);
        let mut buf = vec![0u8; SIGNED_AGG_PROOF_MIN];
        // committee_bits at [436..444); set two bits.
        buf[436] = 0b0000_0011;
        assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Reject(None));
    }

    #[test]
    fn agg_unknown_block_root_ignored() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 0);
        let mut buf = vec![0u8; SIGNED_AGG_PROOF_MIN];
        // Single committee bit so we pass the count_ones check.
        buf[436] = 0b0000_0001;
        // beacon_block_root at [228..260); pick a value not in fork choice.
        buf[228] = 0xFF;
        assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Ignore);
    }

    /// Locate `(slot, committee_index, pos_in_committee, committee_size)` for
    /// validator 0 in epoch 0.
    fn find_committee_for_vi0(tile: &BeaconStateTile) -> (Slot, usize, usize, usize) {
        let entry = tile.get_shuffling(0).expect("shuffling for epoch 0");
        let cps = shuffling::committees_per_slot(entry.shuffled_indices.len());
        for s in 0..SLOTS_PER_EPOCH {
            for ci in 0..cps {
                let c =
                    shuffling::get_beacon_committee(entry.shuffled_indices.as_slice(), s, ci, cps);
                if let Some(pos) = c.iter().position(|&v| v == 0) {
                    return (s, ci, pos, c.len());
                }
            }
        }
        panic!("validator 0 in some committee")
    }

    /// Sign an accept-ready `SignedAggregateAndProof` for validator 0 against
    /// the seeded tile state. `seed_tile` places genesis at start_slot with
    /// `head_block_root` as the only fork-choice node, so the target-epoch
    /// checkpoint block resolves back to `head_block_root`.
    fn build_agg_for_vi0(tile: &BeaconStateTile) -> Vec<u8> {
        let imm = *BeaconStateTile::last_applied_imm(&tile.arena, tile.last_applied);
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
            &tile.zero_hashes,
        )
    }

    #[test]
    fn agg_accept() {
        // Wall slot 31 → window covers all of epoch 0 (slots 0..31).
        let mut tile = make_tile_at_wall_slot(31);
        seed_tile_with_keys(&mut tile, 128, 0);
        let buf = build_agg_for_vi0(&tile);
        let beacon_block_root = tile.last_applied_block_root;
        let slot = SignedAggregateAndProofView::agg_slot(&buf);
        assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Accept);
        // Single-participant aggregate (validator 0) must land in the vote
        // tracker — same effect as the SingleAttestation gossip path.
        assert_eq!(tile.vote_tracker.votes[0].next_root, beacon_block_root);
        assert_eq!(tile.vote_tracker.votes[0].next_epoch, slot / SLOTS_PER_EPOCH);
    }

    #[test]
    fn agg_respects_epoch_monotonicity() {
        // Spec rule (shared with SingleAttestation): only strictly newer
        // epochs overwrite. A pre-existing vote at epoch 1 must survive an
        // accepted aggregate that targets epoch 0.
        let mut tile = make_tile_at_wall_slot(31);
        seed_tile_with_keys(&mut tile, 128, 0);

        let preset_root = [0x99u8; 32];
        tile.vote_tracker.votes[0].next_root = preset_root;
        tile.vote_tracker.votes[0].next_epoch = 1;

        let buf = build_agg_for_vi0(&tile);
        assert_eq!(SignedAggregateAndProofView::agg_target_epoch(&buf), 0);
        assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Accept);

        assert_eq!(tile.vote_tracker.votes[0].next_root, preset_root);
        assert_eq!(tile.vote_tracker.votes[0].next_epoch, 1);
    }

    #[test]
    fn agg_slot_too_old_ignored() {
        // wall = 100, agg_slot = 31 → wall - slot = 69 > 32 → Ignore.
        let mut tile = make_tile_at_wall_slot(100);
        seed_tile_with_keys(&mut tile, 128, 0);
        let buf = build_agg_for_vi0(&tile);
        // Sanity: agg_slot < wall - 32.
        assert!(
            SignedAggregateAndProofView::agg_slot(&buf) < 100 - ATTESTATION_PROPAGATION_SLOT_RANGE
        );
        assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Ignore);
    }

    #[test]
    fn agg_slot_too_future_ignored() {
        // Tile at wall slot 0; valid agg buffer for vi=0 → just rewrite the
        // slot to wall+5 and the matching target_epoch. is_aggregator and sigs
        // are bypassed because the slot-window check fires first.
        let mut tile = make_tile_at_wall_slot(0);
        seed_tile(&mut tile, 128, 0);
        let mut buf = vec![0u8; SIGNED_AGG_PROOF_MIN];
        // Pass count_ones check.
        buf[436] = 0b0000_0001;
        // slot at [212..220), target.epoch at [300..308). slot=5, target_epoch=0
        // still matches `target.epoch == slot/SLOTS_PER_EPOCH`.
        buf[212] = 5;
        assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Ignore);
    }

    #[test]
    fn agg_committee_index_oor_rejected() {
        // 128 validators → cps = 1, so committee_index = 1 is OOR.
        let mut tile = make_tile_at_wall_slot(31);
        seed_tile_with_keys(&mut tile, 128, 0);
        let mut buf = build_agg_for_vi0(&tile);
        // committee_bits at [436..444); clear all then set bit 1.
        for i in 0..8 {
            buf[436 + i] = 0;
        }
        buf[436] = 0b0000_0010;
        assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Reject(None));
    }

    #[test]
    fn agg_is_aggregator_false_rejected() {
        // 1024 validators → cps=1, committee_len=32, modulo=2. Mutate the
        // selection_proof's first byte until is_aggregator returns false; the
        // handler must reject before BLS sig verify fires.
        let mut tile = make_tile_at_wall_slot(31);
        seed_tile_with_keys(&mut tile, 1024, 0);
        let mut buf = build_agg_for_vi0(&tile);
        let (_, _, _, csize) = find_committee_for_vi0(&tile);
        assert_eq!(csize, 32, "committee_len drives modulo");

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

    #[test]
    fn block_with_known_parent_accepted() {
        use crate::{ssz_hash::hash_tree_root_block_header, types::BeaconBlockHeader};

        let mut tile = make_tile();
        seed_tile(&mut tile, 128, 10);

        // Set a known latest_block_header so we can compute parent_root.
        let genesis_header = BeaconBlockHeader {
            slot: 10,
            proposer_index: 0,
            parent_root: [0u8; 32],
            state_root: [0x01; 32], // non-zero so process_slot doesn't overwrite
            body_root: [0u8; 32],
        };
        tile.arena.slot.get_mut(0).latest_block_header = genesis_header;

        // parent_root = hash of current latest_block_header.
        let parent_root = hash_tree_root_block_header(&genesis_header, &tile.zero_hashes);

        // Fork choice genesis must use this root too.
        let cp = Checkpoint { epoch: 0, root: parent_root };
        let anchor_ref = tile.synth_anchor_ref();
        tile.fork_choice = ForkChoice::init(cp, cp, 10, parent_root, parent_root, anchor_ref);
        tile.last_applied_block_root = parent_root;

        // Construct a block with valid structure but zeroed BLS signature.
        let mut buf = vec![0u8; 200];
        buf[100..108].copy_from_slice(&11u64.to_le_bytes()); // slot
        buf[108..116].copy_from_slice(&0u64.to_le_bytes()); // proposer_index
        buf[116..148].copy_from_slice(&parent_root); // parent_root

        tile.handle_block(&buf);

        // Block is rejected by BLS signature verification (zeroed sig).
        assert_eq!(tile.fork_choice.nodes.len(), 1); // only genesis
    }

    fn fd_genesis_validators_root(b: u8) -> B256 {
        [b; 32]
    }

    // EF test schedule (consensus-specs:
    // tests/core/pyspec/eth_consensus_specs/test/fulu/validator/
    // test_compute_fork_digest.py). FULU_FORK_EPOCH = 0 in the test, so all
    // listed epochs are Fulu+.
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

    // Sentinel default; the EF test cases all have epoch >= schedule[0].epoch,
    // so the default is never consulted.
    const FD_SENTINEL: BlobParameters = BlobParameters { epoch: u64::MAX, max_blobs_per_block: 0 };

    fn fd_ef_digest(epoch: Epoch, fork_version: Version, gvr: &B256) -> [u8; 4] {
        let schedule = fd_ef_schedule();
        let bp = get_blob_parameters(epoch, &schedule, FD_SENTINEL);
        compute_fork_digest(fork_version, gvr, Some(bp))
    }

    /// EF spec test vectors (FULU_FORK_EPOCH=0, fd_ef_schedule).
    #[test]
    fn ef_compute_fork_digest_vectors() {
        let v6 = [0x06, 0x00, 0x00, 0x00];
        let v61 = [0x06, 0x00, 0x00, 0x01];
        let v7 = [0x07, 0x00, 0x00, 0x00];
        let v71 = [0x07, 0x00, 0x00, 0x01];

        let cases: &[(Epoch, Version, B256, [u8; 4])] = &[
            // Different epochs and blob limits (schedule transitions):
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
            // Different genesis_validators_root:
            (9, v6, fd_genesis_validators_root(1), [0x89, 0x67, 0x11, 0x11]),
            (9, v6, fd_genesis_validators_root(2), [0xf4, 0x9b, 0x0e, 0x24]),
            (9, v6, fd_genesis_validators_root(3), [0x86, 0x54, 0x4e, 0x4f]),
            (100, v6, fd_genesis_validators_root(1), [0xfd, 0x3a, 0xa2, 0xa2]),
            (100, v6, fd_genesis_validators_root(2), [0x80, 0xc6, 0xbd, 0x97]),
            (100, v6, fd_genesis_validators_root(3), [0xf2, 0x09, 0xfd, 0xfc]),
            // Different fork versions:
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

    /// Mainnet Fulu fork digest at the second BLOB_SCHEDULE entry
    /// (epoch >= 419072, MAX_BLOBS_PER_BLOCK=21).
    #[test]
    fn mainnet_fulu_fork_digest_419072() {
        // mainnet genesis_validators_root:
        // 0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95
        let mainnet_gvr: B256 = [
            0x4b, 0x36, 0x3d, 0xb9, 0x4e, 0x28, 0x61, 0x20, 0xd7, 0x6e, 0xb9, 0x05, 0x34, 0x0f,
            0xdd, 0x4e, 0x54, 0xbf, 0xe9, 0xf0, 0x6b, 0xf3, 0x3f, 0xf6, 0xcf, 0x5a, 0xd2, 0x7f,
            0x51, 0x1b, 0xfe, 0x95,
        ];
        let bp = get_blob_parameters(419072, BLOB_SCHEDULE, DEFAULT_BLOB_PARAMETERS);
        assert_eq!(bp, BlobParameters { epoch: 419072, max_blobs_per_block: 21 });

        let digest = compute_fork_digest(FULU_FORK_VERSION, &mainnet_gvr, Some(bp));
        assert_eq!(digest, [0x8c, 0x9f, 0x62, 0xfe]);
    }
}
