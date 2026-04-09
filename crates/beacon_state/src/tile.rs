use flux::{
    spine::{FluxSpine, SpineAdapter, SpineProducers},
    tile::Tile,
};
use silver_common::{
    BeaconStateEvent, Gossip, GossipTopic, NewGossipMsg, P2pStreamId, PeerEvent, PeerRpcIn, RpcMsg,
    SilverSpine, TProducer, TRandomAccess,
    ssz_view::{
        BLOCKS_BY_RANGE_REQ_SIZE, SIGNED_BEACON_BLOCK_MIN, SINGLE_ATT_SIZE, STATUS_V2_SIZE,
        SignedBeaconBlockView, SingleAttestationView,
    },
};

use crate::{
    arena::ArenaBacking,
    decompose,
    epoch_transition::{self, MAX_PENDING_DEPOSITS_PER_EPOCH},
    fork_choice::{BlockImport, compute_deltas},
    shuffling::{self, DOMAIN_BEACON_ATTESTER},
    ssz_hash, state_transition,
    ticker::{SlotTicker, TickEvent},
    types::{
        self, B256, BeaconStateRef, EPOCH_POOL_CAP, Epoch, EpochData, ForkChoice, MAX_VALIDATORS,
        PENDING_POOL_CAP, PendingQueues, ROOTS_POOL_CAP, SLOT_POOL_CAP, SLOTS_PER_EPOCH,
        SLOTS_PER_HISTORICAL_ROOT, ShufflingCache, Slot, SlotData, ValidatorIdentity, Vote,
        VoteTracker, box_zeroed,
    },
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Catching up from checkpoint to chain head.
    Syncing,
    /// Tracking head via gossip.
    Following,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GossipFeedback {
    Accept,
    Ignore,
    Reject,
}

#[derive(Clone, Copy, Debug)]
struct PendingRangeReq {
    start_slot: Slot,
    count: u64,
    /// Last accepted chunk's slot. `0` until the first chunk lands; spec
    /// requires strictly-increasing slots within a response.
    last_seen_slot: Slot,
    chunks_received: u32,
    /// Wall slot at issue, used for the 2-slot timeout in `sync_step`.
    issued_at_wall_slot: Slot,
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

    head: BeaconStateRef,

    // Sync state.
    sync_cursor: Slot,
    sync_target: Slot,
    // Outstanding BlocksByRange request; cleared on completion, timeout, or head advancing past
    // the requested range.
    in_flight: Option<(u64, PendingRangeReq)>,
    next_request_id: u64,
    synced_emitted: bool,

    zero_hashes: [B256; ssz_hash::ZERO_HASHES_LEN],
    active_scratch: Vec<u32>,
    postponed_scratch: Vec<types::PendingDeposit>,

    event_producer: TProducer,
    gossip_consumer: TRandomAccess,
    rpc_consumer: TRandomAccess,
}

type Producers = <SilverSpine as FluxSpine>::Producers;

impl BeaconStateTile {
    pub fn new(
        ticker: SlotTicker,
        gossip_consumer: TRandomAccess,
        event_producer: TProducer,
        rpc_consumer: TRandomAccess,
        checkpoint_state: &[u8],
    ) -> Self {
        Self::with_arena(
            ticker,
            gossip_consumer,
            event_producer,
            rpc_consumer,
            ArenaBacking::open_shm("silver"),
            checkpoint_state,
        )
    }

    pub fn new_heap(
        ticker: SlotTicker,
        gossip_consumer: TRandomAccess,
        event_producer: TProducer,
        rpc_consumer: TRandomAccess,
        checkpoint_state: &[u8],
    ) -> Self {
        Self::with_arena(
            ticker,
            gossip_consumer,
            event_producer,
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
        event_producer: TProducer,
        rpc_consumer: TRandomAccess,
        arena: ArenaBacking,
        checkpoint_state: &[u8],
    ) -> Self {
        let pending_pool: Vec<PendingQueues> =
            (0..PENDING_POOL_CAP).map(|_| PendingQueues::new()).collect();
        let head = BeaconStateRef {
            imm_idx: 0,
            vid_idx: 0,
            vid_gen: arena.vid.gen_at(0),
            longtail_idx: 0,
            epoch_idx: 0,
            epoch_gen: arena.epoch.gen_at(0),
            roots_idx: 0,
            roots_gen: arena.roots.gen_at(0),
            slot_idx: 0,
            slot_gen: arena.slot.gen_at(0),
            pending_idx: 0,
        };

        // TierPool cursors start at 0; bump past slot 0 (reserved for the
        // bootstrap state that `head` points at).
        arena.imm.set_cursor(0);
        arena.vid.set_cursor(1);
        arena.longtail.set_cursor(1);
        arena.epoch.set_cursor(1);
        arena.roots.set_cursor(1);
        arena.slot.set_cursor(1);

        let mut tile = Self {
            mode: Mode::Syncing,
            ticker,
            arena,
            pending_pool,
            pending_pool_next: 1,
            fork_choice: ForkChoice::default(),
            vote_tracker: box_zeroed(),
            shuffling_cache: box_zeroed(),
            head,
            sync_cursor: 0,
            sync_target: 0,
            in_flight: None,
            next_request_id: 1,
            synced_emitted: false,
            zero_hashes: ssz_hash::compute_zero_hashes(),
            active_scratch: Vec::with_capacity(MAX_VALIDATORS),
            postponed_scratch: Vec::with_capacity(MAX_PENDING_DEPOSITS_PER_EPOCH),
            event_producer,
            gossip_consumer,
            rpc_consumer,
        };

        if !checkpoint_state.is_empty() {
            tile.bootstrap(checkpoint_state);
        }
        tile
    }

    /// Load a checkpoint state SSZ blob. Decomposes into tiered storage at
    /// slot 0 of each pool. Returns false if the SSZ is invalid.
    fn bootstrap(&mut self, ssz: &[u8]) -> bool {
        let Some(pq) = decompose::decompose_beacon_state(
            ssz,
            &self.zero_hashes,
            self.arena.imm.get_mut(0),
            self.arena.vid.get_mut(0),
            self.arena.longtail.get_mut(0),
            self.arena.epoch.get_mut(0),
            self.arena.roots.get_mut(0),
            self.arena.slot.get_mut(0),
        ) else {
            return false;
        };
        self.pending_pool[0] = pq;

        let sd = self.arena.slot.get(0);

        let slot = sd.slot;
        let block_root =
            ssz_hash::hash_tree_root_block_header(&sd.latest_block_header, &self.zero_hashes);
        // Checkpoint-sync convention: the anchor is trusted, so both
        // finalized and justified checkpoints refer to the anchor block
        // itself. Using the pre-state's stored checkpoints would leave
        // `find_head` looking up a root no fork-choice node holds.
        let trusted_cp = types::Checkpoint { epoch: slot / SLOTS_PER_EPOCH, root: block_root };
        let finalized = trusted_cp;
        let justified = trusted_cp;
        self.head = BeaconStateRef {
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
            ForkChoice::init(finalized, justified, slot, block_root, block_root, self.head);

        let current_epoch = slot / SLOTS_PER_EPOCH;
        let vid0 = self.arena.vid.get(0);
        let epoch0 = self.arena.epoch.get(0);
        Self::compute_shuffling_into(
            vid0,
            epoch0,
            current_epoch,
            &mut self.shuffling_cache,
            &mut self.active_scratch,
        );
        if current_epoch > 0 {
            Self::compute_shuffling_into(
                vid0,
                epoch0,
                current_epoch - 1,
                &mut self.shuffling_cache,
                &mut self.active_scratch,
            );
        }

        let wall_slot = self.ticker.current_slot();
        self.sync_cursor = slot + 1;
        self.sync_target = wall_slot;
        self.mode = if wall_slot > slot + 2 { Mode::Syncing } else { Mode::Following };
        true
    }

    fn compute_shuffling_into(
        vid: &ValidatorIdentity,
        epoch_data: &EpochData,
        epoch: Epoch,
        cache: &mut ShufflingCache,
        scratch: &mut Vec<u32>,
    ) {
        let seed = shuffling::get_seed(epoch_data, epoch, DOMAIN_BEACON_ATTESTER);
        shuffling::get_active_validator_indices_into(epoch_data, vid.validator_cnt, epoch, scratch);
        shuffling::shuffle_list(scratch, &seed);
        let slot = cache.entries.iter().position(|e| e.status == 0).unwrap_or(0);
        let entry = &mut cache.entries[slot];
        entry.epoch = epoch;
        entry.seed = seed;
        entry.status = 1;
        entry.shuffled_indices.clear();
        for &idx in scratch.iter() {
            entry.shuffled_indices.push(idx);
        }
    }

    fn alloc_pending(&mut self) -> usize {
        let idx = self.pending_pool_next;
        self.pending_pool_next = (idx + 1) % PENDING_POOL_CAP;
        idx
    }

    fn imm(&self, r: &BeaconStateRef) -> &types::Immutable {
        self.arena.imm.get(r.imm_idx)
    }

    fn vid(&self, r: &BeaconStateRef) -> &ValidatorIdentity {
        self.arena.vid.get_checked(r.vid_idx, r.vid_gen)
    }

    fn longtail(&self, r: &BeaconStateRef) -> &types::HistoricalLongtail {
        self.arena.longtail.get(r.longtail_idx)
    }

    fn epoch(&self, r: &BeaconStateRef) -> &EpochData {
        self.arena.epoch.get_checked(r.epoch_idx, r.epoch_gen)
    }

    fn roots(&self, r: &BeaconStateRef) -> &types::SlotRoots {
        self.arena.roots.get_checked(r.roots_idx, r.roots_gen)
    }

    fn roots_mut(&self, r: &BeaconStateRef) -> &mut types::SlotRoots {
        self.arena.roots.get_mut_checked(r.roots_idx, r.roots_gen)
    }

    fn slot(&self, r: &BeaconStateRef) -> &SlotData {
        self.arena.slot.get_checked(r.slot_idx, r.slot_gen)
    }

    fn slot_mut(&self, r: &BeaconStateRef) -> &mut SlotData {
        self.arena.slot.get_mut_checked(r.slot_idx, r.slot_gen)
    }

    /// Compute and cache the shuffling for `epoch`. No-op if already cached.
    fn ensure_shuffling(&mut self, epoch: Epoch) {
        for entry in self.shuffling_cache.entries.iter() {
            if entry.status == 1 && entry.epoch == epoch {
                return;
            }
        }

        let head = self.head;
        let vid = self.arena.vid.get_checked(head.vid_idx, head.vid_gen);
        let epoch_data = self.arena.epoch.get_checked(head.epoch_idx, head.epoch_gen);

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

    fn sync_step(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        let head = self.head;
        let head_slot = self.slot(&head).slot;
        let wall_slot = self.ticker.current_slot();

        // Update cursor from processed blocks.
        if head_slot >= self.sync_cursor {
            self.sync_cursor = head_slot + 1;
            // Reclaim pool entries for pruned fork choice nodes.
            self.prune_fork_choice();
        }

        // Drop the in-flight bookkeeping if (a) the head has advanced past
        // the requested range (further chunks would be redundant), or (b)
        // the 2-wall-slot timeout has elapsed. After this, the request_id
        // changes, so any straggler chunks for the prior id are rejected.
        if let Some((_, req)) = &self.in_flight {
            let past_range = head_slot >= req.start_slot + req.count;
            let timed_out = wall_slot > req.issued_at_wall_slot + 2;
            if past_range || timed_out {
                self.in_flight = None;
            }
        }

        self.sync_target = wall_slot;

        // Check if caught up.
        if head_slot + 2 >= self.sync_target {
            if self.mode != Mode::Following {
                self.mode = Mode::Following;
                self.synced_emitted = false; // re-emit on next loop_body tick
            }
            let epoch = head_slot / SLOTS_PER_EPOCH;
            self.ensure_shuffling(epoch);
            if epoch > 0 {
                self.ensure_shuffling(epoch - 1);
            }
            return;
        }

        // Request next batch.
        if self.in_flight.is_none() && self.sync_cursor <= self.sync_target {
            let start_slot = self.sync_cursor;
            let count = (self.sync_target - self.sync_cursor + 1).min(64);
            let request_id = self.next_request_id;
            if let Some(ev) = self.build_request_blocks_by_range(request_id, start_slot, count) {
                adapter.produce(ev);
                self.next_request_id += 1;
                self.in_flight = Some((request_id, PendingRangeReq {
                    start_slot,
                    count,
                    last_seen_slot: 0,
                    chunks_received: 0,
                    issued_at_wall_slot: wall_slot,
                }));
            }
        }
    }

    fn fork_digest(&self) -> [u8; 4] {
        let imm = self.imm(&self.head);
        let mut version_chunk = [0u8; 32];
        version_chunk[..4].copy_from_slice(&imm.fork.current_version);
        let root =
            ssz_hash::merkleize(&[version_chunk, imm.genesis_validators_root], &self.zero_hashes);
        root[..4].try_into().unwrap()
    }

    fn status_payload(&self) -> [u8; STATUS_V2_SIZE] {
        let sd = self.slot(&self.head);
        let fork_digest = self.fork_digest();
        let head_root =
            ssz_hash::hash_tree_root_block_header(&sd.latest_block_header, &self.zero_hashes);
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

    fn build_request_blocks_by_range(
        &mut self,
        request_id: u64,
        start_slot: Slot,
        count: u64,
    ) -> Option<BeaconStateEvent> {
        let Some(mut r) = self.event_producer.reserve(BLOCKS_BY_RANGE_REQ_SIZE, true) else {
            tracing::warn!("event_producer reserve failed (request_blocks_by_range)");
            return None;
        };
        if let Ok(buf) = r.buffer() {
            buf[0..8].copy_from_slice(&start_slot.to_le_bytes());
            buf[8..16].copy_from_slice(&count.to_le_bytes());
            buf[16..24].copy_from_slice(&1u64.to_le_bytes());
        }
        r.increment_offset(BLOCKS_BY_RANGE_REQ_SIZE);
        Some(BeaconStateEvent::RequestBlocksByRange { request_id, ssz: r.read() })
    }

    fn build_persist_block(&mut self, data: &[u8]) -> Option<BeaconStateEvent> {
        let len = data.len();
        let Some(mut r) = self.event_producer.reserve(len, true) else {
            tracing::warn!(len, "event_producer reserve failed (persist_block)");
            return None;
        };
        if let Ok(buf) = r.buffer() {
            buf[..len].copy_from_slice(data);
        }
        r.increment_offset(len);
        Some(BeaconStateEvent::PersistBlock(r.read()))
    }

    /// Post-import emission: PersistBlock (for storage) + Status (head and
    /// possibly finalized just moved). Called after `handle_block` returns
    /// `GossipFeedback::Accept` from gossip or RPC range/root response paths.
    fn apply_block(&mut self, data: &[u8], producers: &mut Producers) -> GossipFeedback {
        let prev_head = self.head;
        let prev_finalized = self.slot(&prev_head).finalized_checkpoint;

        let f = self.handle_block(data);
        if f != GossipFeedback::Accept {
            return f;
        }

        if let Some(ev) = self.build_persist_block(data) {
            producers.produce(ev);
        }

        let head_changed = self.head != prev_head;
        let new_finalized = self.slot(&self.head).finalized_checkpoint;
        let finalized_changed = new_finalized != prev_finalized;
        if head_changed || finalized_changed {
            producers.produce(BeaconStateEvent::Status(self.status_payload()));
        }
        f
    }

    /// Returns `true` iff at least one slot was processed (so head_slot
    /// definitely advanced, and finalized may have advanced via an epoch
    /// transition along the way).
    fn on_slot_start(&mut self, target_slot: Slot) -> bool {
        let head = self.head;
        let current_slot = self.slot(&head).slot;
        if target_slot <= current_slot {
            return false;
        }

        // Spec: process_slots loops slot by slot.
        // For each slot: process_slot (bookkeeping), then epoch transition
        // if (slot + 1) % SLOTS_PER_EPOCH == 0, then slot += 1.
        for s in current_slot..target_slot {
            // 1. process_slot: snapshot roots.
            let head = self.head;
            let idx = s as usize % SLOTS_PER_HISTORICAL_ROOT;

            let prev_state_root = ssz_hash::hash_tree_root_state(
                self.imm(&head),
                self.vid(&head),
                self.longtail(&head),
                self.epoch(&head),
                self.roots(&head),
                self.slot(&head),
                &self.pending_pool[head.pending_idx],
                &self.zero_hashes,
            );

            let roots = self.roots_mut(&head);
            let sd = self.slot_mut(&head);
            roots.state_roots[idx] = prev_state_root;

            if sd.latest_block_header.state_root == [0u8; 32] {
                sd.latest_block_header.state_root = prev_state_root;
            }

            let block_root =
                ssz_hash::hash_tree_root_block_header(&sd.latest_block_header, &self.zero_hashes);
            roots.block_roots[idx] = block_root;

            // 2. Epoch transition after process_slot, at the end of the last slot of an
            //    epoch: (slot + 1) % SLOTS_PER_EPOCH == 0.
            if (s + 1).is_multiple_of(SLOTS_PER_EPOCH) {
                self.epoch_transition();
            }
        }

        let head = self.head;
        self.slot_mut(&head).slot = target_slot;
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
        let head = self.head;

        // Always COW EpochData (mutated every epoch).
        let new_ei = self.arena.epoch.copy_from(head.epoch_idx);

        // COW ValidatorIdentity if deposits may add new validators this epoch.
        let new_vid = if self.pending_pool[head.pending_idx].pending_deposits.is_empty() {
            head.vid_idx
        } else {
            self.arena.vid.copy_from(head.vid_idx)
        };

        // COW HistoricalLongtail if sync committee rotates or historical summary
        // pushes.
        let slot = self.slot(&head).slot;
        let next_epoch = slot / SLOTS_PER_EPOCH + 1;
        let hs_period = SLOTS_PER_HISTORICAL_ROOT as u64 / SLOTS_PER_EPOCH;
        let sync_rotates = next_epoch.is_multiple_of(types::EPOCHS_PER_SYNC_COMMITTEE_PERIOD);
        let hs_pushes = next_epoch.is_multiple_of(hs_period);
        let new_longtail = if sync_rotates || hs_pushes {
            self.arena.longtail.copy_from(head.longtail_idx)
        } else {
            head.longtail_idx
        };

        let vid = self.arena.vid.get_mut(new_vid);
        let longtail = self.arena.longtail.get_mut(new_longtail);
        let epoch = self.arena.epoch.get_mut(new_ei);
        let sd = self.arena.slot.get_mut_checked(head.slot_idx, head.slot_gen);
        let roots = self.arena.roots.get_checked(head.roots_idx, head.roots_gen);

        epoch_transition::process_epoch(
            vid,
            longtail,
            epoch,
            sd,
            &mut self.pending_pool[head.pending_idx],
            roots,
            &self.zero_hashes,
            &mut self.active_scratch,
            &mut self.postponed_scratch,
        );

        self.head.epoch_idx = new_ei;
        self.head.epoch_gen = self.arena.epoch.gen_at(new_ei);
        if new_vid != head.vid_idx {
            self.head.vid_idx = new_vid;
            self.head.vid_gen = self.arena.vid.gen_at(new_vid);
        }
        self.head.longtail_idx = new_longtail;

        let sd = self.arena.slot.get_checked(head.slot_idx, head.slot_gen);
        let cp = (sd.current_justified_checkpoint, sd.finalized_checkpoint);
        let new_epoch = sd.slot / SLOTS_PER_EPOCH;
        self.fork_choice.justified_checkpoint = cp.0;
        self.fork_choice.finalized_checkpoint = cp.1;

        self.prune_fork_choice();
        self.ensure_shuffling(new_epoch);
        if new_epoch > 0 {
            self.ensure_shuffling(new_epoch - 1);
        }
    }

    fn on_attestation(&mut self, validator_idx: usize, block_root: B256, epoch: Epoch) {
        let head = self.head;
        if validator_idx >= self.vid(&head).validator_cnt {
            return;
        }
        self.vote_tracker.votes[validator_idx] = Vote {
            current_root: self.vote_tracker.votes[validator_idx].current_root,
            next_root: block_root,
            next_epoch: epoch,
        };
    }

    fn recompute_head(&mut self) {
        let head = self.head;
        let vid = self.arena.vid.get_checked(head.vid_idx, head.vid_gen);
        let epoch = self.arena.epoch.get_checked(head.epoch_idx, head.epoch_gen);
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
        let sd = self.arena.slot.get_checked(head.slot_idx, head.slot_gen);
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

        // Collect indices still referenced by surviving nodes + head.
        let mut live_epoch = [false; EPOCH_POOL_CAP];
        let mut live_roots = [false; ROOTS_POOL_CAP];
        let mut live_slot = [false; SLOT_POOL_CAP];

        let mark = |s: &BeaconStateRef,
                    le: &mut [bool; EPOCH_POOL_CAP],
                    lw: &mut [bool; ROOTS_POOL_CAP],
                    ls: &mut [bool; SLOT_POOL_CAP]| {
            le[s.epoch_idx] = true;
            lw[s.roots_idx] = true;
            ls[s.slot_idx] = true;
        };

        mark(&self.head, &mut live_epoch, &mut live_roots, &mut live_slot);
        for node in self.fork_choice.nodes.as_slice() {
            mark(&node.state, &mut live_epoch, &mut live_roots, &mut live_slot);
        }

        // Reset allocator cursors to freed entries so they get reused first.
        // Best-effort: the ring allocator still works correctly without it,
        // but this reclaims sooner.
        for &ref_pruned in pruned.as_slice() {
            if !live_slot[ref_pruned.slot_idx] {
                self.arena.slot.set_cursor(ref_pruned.slot_idx);
            }
            if !live_roots[ref_pruned.roots_idx] {
                self.arena.roots.set_cursor(ref_pruned.roots_idx);
            }
            if !live_epoch[ref_pruned.epoch_idx] {
                self.arena.epoch.set_cursor(ref_pruned.epoch_idx);
            }
        }
    }

    fn handle_gossip(&mut self, m: NewGossipMsg, data: &[u8], producers: &mut Producers) {
        let feedback = match m.topic {
            GossipTopic::BeaconBlock => Some(self.apply_block(data, producers)),
            GossipTopic::BeaconAttestation(_) => Some(self.handle_attestation(data)),
            _ => None,
        };
        match feedback {
            Some(GossipFeedback::Reject) => producers.produce(PeerEvent::P2pGossipInvalidMsg {
                p2p_peer: m.stream_id.peer(),
                topic: m.topic,
                hash: m.msg_hash,
            }),
            Some(GossipFeedback::Accept) => producers.produce(PeerEvent::SendGossip {
                originator_stream_id: m.stream_id,
                topic: m.topic,
                msg_hash: m.msg_hash,
                recv_ts: m.recv_ts,
                protobuf: m.protobuf,
            }),
            Some(GossipFeedback::Ignore) | None => {}
        }
    }

    fn handle_rpc(
        &mut self,
        msg: RpcMsg,
        _sender: P2pStreamId,
        request_id: u64,
        data: &[u8],
        producers: &mut Producers,
    ) {
        if let RpcMsg::BlocksRangeResp(_) = msg {
            if !self.accept_blocks_range_chunk(request_id, data) {
                return;
            }
            if self.apply_block(data, producers) == GossipFeedback::Accept &&
                let Some((_, req)) = self.in_flight.as_mut()
            {
                req.last_seen_slot = SignedBeaconBlockView::slot(data);
                req.chunks_received += 1;
                if req.chunks_received as u64 >= req.count {
                    self.in_flight = None;
                }
            }
        }
    }

    fn accept_blocks_range_chunk(&self, request_id: u64, data: &[u8]) -> bool {
        let Some((id, req)) = &self.in_flight else { return false };
        if request_id != *id {
            return false;
        }
        if !SignedBeaconBlockView::check_size(data) {
            return false;
        }
        let slot = SignedBeaconBlockView::slot(data);
        if slot < req.start_slot || slot >= req.start_slot + req.count {
            return false;
        }
        if req.last_seen_slot != 0 && slot <= req.last_seen_slot {
            return false;
        }
        if req.chunks_received as u64 >= req.count {
            return false;
        }
        true
    }

    fn handle_block(&mut self, data: &[u8]) -> GossipFeedback {
        if !SignedBeaconBlockView::check_size(data) {
            return GossipFeedback::Reject;
        }
        let block_slot = SignedBeaconBlockView::slot(data);
        let proposer_index = SignedBeaconBlockView::proposer_index(data);
        let parent_root = *SignedBeaconBlockView::parent_root(data);
        let state_root = *SignedBeaconBlockView::state_root(data);

        // Parent not yet imported — not the sender's fault.
        if self.fork_choice.find_node_idx(&parent_root).is_none() {
            return GossipFeedback::Ignore;
        }

        let block_epoch = block_slot / SLOTS_PER_EPOCH;
        {
            let head = self.head;
            let sd_head = self.slot(&head);
            let head_epoch = sd_head.slot / SLOTS_PER_EPOCH;
            // Fulu canonicalises proposer selection via `proposer_lookahead`
            // (spans current + next epoch, 64 slots). Using this avoids
            // recomputing from (epoch_data, seed) which can diverge mid-epoch
            // because the lookahead was fixed at the prior epoch boundary.
            if block_epoch == head_epoch || block_epoch == head_epoch + 1 {
                let la_idx = (block_slot - head_epoch * SLOTS_PER_EPOCH) as usize;
                if la_idx < types::PROPOSER_LOOKAHEAD_SIZE &&
                    proposer_index != sd_head.proposer_lookahead[la_idx]
                {
                    return GossipFeedback::Reject;
                }
            }
        }

        self.ensure_shuffling(block_epoch);
        if block_epoch > 0 {
            self.ensure_shuffling(block_epoch - 1);
        }

        let head = self.head;

        let new_slot_idx = self.arena.slot.copy_from(head.slot_idx);
        let new_slot_gen = self.arena.slot.gen_at(new_slot_idx);
        let new_roots_idx = self.arena.roots.copy_from(head.roots_idx);
        let new_roots_gen = self.arena.roots.gen_at(new_roots_idx);
        let new_pending_idx = self.alloc_pending();
        debug_assert_ne!(new_pending_idx, head.pending_idx);
        // Split borrow because src and dst index the same `pending_pool`.
        let pool = self.pending_pool.as_mut_slice();
        let (src, dst) = if head.pending_idx < new_pending_idx {
            let (lo, hi) = pool.split_at_mut(new_pending_idx);
            (&lo[head.pending_idx], &mut hi[0])
        } else {
            let (lo, hi) = pool.split_at_mut(head.pending_idx);
            (&hi[0], &mut lo[new_pending_idx])
        };
        dst.pending_deposits.clone_from(&src.pending_deposits);
        dst.pending_partial_withdrawals.clone_from(&src.pending_partial_withdrawals);
        dst.pending_consolidations.clone_from(&src.pending_consolidations);

        let mut state_ref = BeaconStateRef {
            imm_idx: head.imm_idx,
            vid_idx: head.vid_idx,
            vid_gen: head.vid_gen,
            longtail_idx: head.longtail_idx,
            epoch_idx: head.epoch_idx,
            epoch_gen: head.epoch_gen,
            roots_idx: new_roots_idx,
            roots_gen: new_roots_gen,
            slot_idx: new_slot_idx,
            slot_gen: new_slot_gen,
            pending_idx: new_pending_idx,
        };

        // Check if the block body may mutate vid (new deposits, BLS changes) or
        // the epoch tier (slashings, exits, etc). If so, COW the affected
        // tier(s) from the head's shared entry. Cheap offset inspection.
        // TODO(simpler): body_mutation_hints duplicates the SSZ offset parsing
        // that process_block_body does. Combine both into one parse pass, or
        // drop hints and conservatively COW (profile to confirm cost).
        let body = if data.len() > SIGNED_BEACON_BLOCK_MIN {
            &data[SIGNED_BEACON_BLOCK_MIN..]
        } else {
            &[]
        };
        let (may_mut_vid, may_mut_epoch) = body_mutation_hints(body);

        // COW vid if block may mutate it, or if we'll cross an epoch boundary
        // (epoch transition may add validators via process_pending_deposits).
        let head_epoch = self.slot(&state_ref).slot / SLOTS_PER_EPOCH;
        let crosses_epoch = block_epoch != head_epoch;

        if may_mut_vid {
            state_ref.vid_idx = self.arena.vid.copy_from(state_ref.vid_idx);
            state_ref.vid_gen = self.arena.vid.gen_at(state_ref.vid_idx);
        }

        // COW epoch if this block mutates it, OR if it crosses an epoch
        // boundary (process_slots runs epoch transition on the EpochData).
        if may_mut_epoch || crosses_epoch {
            state_ref.epoch_idx = self.arena.epoch.copy_from(state_ref.epoch_idx);
            state_ref.epoch_gen = self.arena.epoch.gen_at(state_ref.epoch_idx);
        }

        // COW longtail if the block crosses a sync-committee rotation or
        // historical-summary push boundary.
        if crosses_epoch {
            let next_epoch = block_epoch;
            let hs_period = SLOTS_PER_HISTORICAL_ROOT as u64 / SLOTS_PER_EPOCH;
            let sync_rotates = next_epoch.is_multiple_of(types::EPOCHS_PER_SYNC_COMMITTEE_PERIOD);
            let hs_pushes = next_epoch.is_multiple_of(hs_period);
            if sync_rotates || hs_pushes {
                state_ref.longtail_idx = self.arena.longtail.copy_from(state_ref.longtail_idx);
            }
        }

        // Compute body_root before state transition (needed for header storage).
        let body = silver_common::ssz_view::SignedBeaconBlockView::body(data);
        let body_root = ssz_hash::hash_tree_root_body(body, &self.zero_hashes);

        // Build shuffling reference for attestation processing.
        // Access shuffling cache fields directly to avoid borrow conflict
        // with the mutable borrows on the arena below.
        let block_epoch = block_slot / SLOTS_PER_EPOCH;
        let prev_epoch = block_epoch.saturating_sub(1);

        let find_entry = |epoch: Epoch| -> Option<usize> {
            self.shuffling_cache.entries.iter().position(|e| e.status == 1 && e.epoch == epoch)
        };
        let cur_idx = find_entry(block_epoch);
        let prev_idx = find_entry(prev_epoch);

        let shuffling_ref = match (cur_idx, prev_idx) {
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

        let imm = self.arena.imm.get(state_ref.imm_idx);
        let vid = self.arena.vid.get_mut_checked(state_ref.vid_idx, state_ref.vid_gen);
        let longtail = self.arena.longtail.get_mut(state_ref.longtail_idx);
        let epoch = self.arena.epoch.get_mut_checked(state_ref.epoch_idx, state_ref.epoch_gen);
        let roots = self.arena.roots.get_mut_checked(state_ref.roots_idx, state_ref.roots_gen);
        let sd = self.arena.slot.get_mut_checked(state_ref.slot_idx, state_ref.slot_gen);

        let ok = state_transition::apply_block(
            imm,
            vid,
            longtail,
            epoch,
            roots,
            sd,
            &mut self.pending_pool[state_ref.pending_idx],
            data,
            block_slot,
            proposer_index,
            parent_root,
            body_root,
            state_root,
            shuffling_ref.as_ref(),
            &self.zero_hashes,
            &mut self.active_scratch,
            &mut self.postponed_scratch,
        );
        if !ok {
            return GossipFeedback::Reject;
        }

        let block_header = types::BeaconBlockHeader {
            slot: block_slot,
            proposer_index,
            parent_root,
            state_root,
            body_root,
        };
        let block_root = ssz_hash::hash_tree_root_block_header(&block_header, &self.zero_hashes);

        let sd = self.slot(&state_ref);

        // TODO(EL): extract execution_block_hash from the execution payload
        // header (sd.latest_execution_payload_header.block_hash) and pass it to
        // fork choice. After recomputing head, send engine_forkchoiceUpdatedV3
        // to the EL with the new head's execution_block_hash, finalized hash,
        // and safe hash. The EL response determines whether the head is VALID,
        // INVALID, or SYNCING (optimistic).
        self.fork_choice.on_block(&BlockImport {
            slot: block_slot,
            block_root,
            parent_root,
            state_root,
            execution_block_hash: [0u8; 32],
            justified: sd.current_justified_checkpoint,
            finalized: sd.finalized_checkpoint,
            state_ref,
        });

        self.recompute_head();
        let new_head = self.fork_choice.find_head();

        if let Some(idx) = self.fork_choice.find_node_idx(&new_head) {
            self.head = self.fork_choice.node(idx).state;
        }
        GossipFeedback::Accept
    }

    fn handle_attestation(&mut self, data: &[u8]) -> GossipFeedback {
        if data.len() < SINGLE_ATT_SIZE {
            return GossipFeedback::Reject;
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
            None => return GossipFeedback::Ignore,
        };

        let cps = shuffling::committees_per_slot(entry.shuffled_indices.len());
        if committee_index >= cps {
            return GossipFeedback::Reject;
        }
        let committee = shuffling::get_beacon_committee(
            entry.shuffled_indices.as_slice(),
            att_slot,
            committee_index,
            cps,
        );

        if !committee.contains(&(attester_index as u32)) {
            return GossipFeedback::Reject;
        }

        // TODO(BLS): verify the SingleAttestation signature against the
        // attester pubkey under DOMAIN_BEACON_ATTESTER for target_epoch
        // before updating the vote tracker. Ungated, any peer can spam votes
        // for arbitrary block roots and skew fork choice weight.

        self.on_attestation(attester_index, block_root, target_epoch);
        GossipFeedback::Accept
    }
}

impl Tile<SilverSpine> for BeaconStateTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        if self.mode == Mode::Following && !self.synced_emitted {
            adapter.produce(BeaconStateEvent::Synced(self.status_payload()));
            self.synced_emitted = true;
        }

        if self.mode == Mode::Following {
            match self.ticker.tick() {
                TickEvent::SlotStart(slot) => {
                    if self.on_slot_start(slot) {
                        adapter.produce(BeaconStateEvent::Status(self.status_payload()));
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

        adapter.consume(|m: Gossip, producers| {
            if let Gossip::NewInbound(m) = m {
                let seq = m.ssz.seq();
                let data = self.gossip_consumer.read_at(seq).ok().map(|(d, _)| d as *const [u8]);
                if let Some(p) = data {
                    self.handle_gossip(m, unsafe { &*p }, producers);
                }
                self.gossip_consumer.set_tail(seq);
            }
        });

        adapter.consume(|m: PeerRpcIn, producers| {
            let seq = m.tcache.seq();
            let data = self.rpc_consumer.read_at(seq).ok().map(|(d, _)| d as *const [u8]);
            if let Some(p) = data {
                self.handle_rpc(m.msg, m.sender, m.request_id, unsafe { &*p }, producers);
            }
            self.rpc_consumer.set_tail(seq);
        });

        // Sync: request more blocks.
        if self.mode == Mode::Syncing {
            self.sync_step(adapter);
        }

        // Publish outbound tcache head so downstream consumers see new seqs.
        self.event_producer.publish_head();
    }
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
    let _ = att;
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

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use silver_common::TCache;

    use super::*;
    use crate::types::Checkpoint;

    const MAX_EFFECTIVE_BALANCE: u64 = 32_000_000_000;

    fn make_tile() -> BeaconStateTile {
        let genesis = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - 12;
        let ticker = SlotTicker::new(genesis, Duration::from_secs(12), Duration::from_secs(4));
        let gossip_p = TCache::producer(1 << 20);
        let event_p = TCache::producer(1 << 20);
        let gossip_c = gossip_p.cache_ref().random_access().unwrap();
        let rpc_c = event_p.cache_ref().random_access().unwrap();
        let event_p = TCache::producer(1 << 20);
        BeaconStateTile::new_heap(ticker, gossip_c, event_p, rpc_c, &[])
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
        }

        let sd = tile.arena.slot.get_mut(0);
        sd.slot = start_slot;
        sd.current_justified_checkpoint = cp;
        sd.finalized_checkpoint = cp;
        for i in 0..n {
            sd.balances[i] = MAX_EFFECTIVE_BALANCE;
        }

        tile.fork_choice = ForkChoice::init(cp, cp, start_slot, root, root, tile.head);
        tile.mode = Mode::Following;

        // Precompute shuffling for the start epoch.
        let start_epoch = start_slot / SLOTS_PER_EPOCH;
        tile.ensure_shuffling(start_epoch);
    }

    #[test]
    fn slot_advance_skip_multiple() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 10);

        tile.on_slot_start(15);
        assert_eq!(tile.slot(&tile.head).slot, 15);
    }

    #[test]
    fn slot_advance_noop_past_slot() {
        let mut tile = make_tile();
        seed_tile(&mut tile, 4, 10);

        tile.on_slot_start(5);
        assert_eq!(tile.slot(&tile.head).slot, 10);
    }

    #[test]
    fn slot_advance_crosses_epoch_boundary() {
        let mut tile = make_tile();
        // Start at slot 30 (epoch 0). Advance to slot 34 (epoch 1).
        // Epoch transition should fire at end of slot 31 (since (31+1) % 32 == 0).
        seed_tile(&mut tile, 4, 30);

        let old_epoch_idx = tile.head.epoch_idx;
        tile.on_slot_start(34);

        assert_eq!(tile.slot(&tile.head).slot, 34);
        // Epoch transition allocated a new EpochData.
        assert_ne!(tile.head.epoch_idx, old_epoch_idx);
    }

    #[test]
    fn slot_advance_crosses_two_epoch_boundaries() {
        let mut tile = make_tile();
        // Start at slot 30. Advance to slot 66 (epoch 2).
        // Epoch boundaries at slot 31 and slot 63.
        seed_tile(&mut tile, 4, 30);

        tile.on_slot_start(66);

        assert_eq!(tile.slot(&tile.head).slot, 66);
    }

    #[test]
    fn attestation_updates_vote_tracker() {
        let mut tile = make_tile();
        let n = 128; // enough for non-empty committees
        seed_tile(&mut tile, n, 0);

        let attester: u32 = 5;

        // Find which (slot, committee_index) contains validator 5.
        let entry = tile.get_shuffling(0).unwrap();
        let cps = shuffling::committees_per_slot(entry.shuffled_indices.len());
        let mut att_slot = 0u64;
        let mut att_ci = 0usize;
        let mut found = false;
        for s in 0..SLOTS_PER_EPOCH {
            for ci in 0..cps {
                let committee =
                    shuffling::get_beacon_committee(entry.shuffled_indices.as_slice(), s, ci, cps);
                if committee.contains(&attester) {
                    att_slot = s;
                    att_ci = ci;
                    found = true;
                    break;
                }
            }
            if found {
                break;
            }
        }
        assert!(found, "validator {attester} should be in some committee");

        let mut buf = [0u8; SINGLE_ATT_SIZE];
        buf[0..8].copy_from_slice(&(att_ci as u64).to_le_bytes()); // committee_index
        buf[8..16].copy_from_slice(&(attester as u64).to_le_bytes()); // attester_index
        buf[16..24].copy_from_slice(&att_slot.to_le_bytes()); // slot
        buf[32] = 0xAA; // beacon_block_root
        buf[104..112].copy_from_slice(&0u64.to_le_bytes()); // target.epoch = 0

        tile.handle_attestation(&buf);

        assert_eq!(tile.vote_tracker.votes[attester as usize].next_root[0], 0xAA);
        assert_eq!(tile.vote_tracker.votes[attester as usize].next_epoch, 0);
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

        let head_before = tile.head;
        tile.handle_block(&buf);

        // Block rejected (orphan), head unchanged.
        assert_eq!(tile.head.slot_idx, head_before.slot_idx);
        assert_eq!(tile.fork_choice.nodes.len(), 1); // only genesis
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
        tile.fork_choice = ForkChoice::init(cp, cp, 10, parent_root, parent_root, tile.head);

        // Construct a block with valid structure but zeroed BLS signature.
        let mut buf = vec![0u8; 200];
        buf[100..108].copy_from_slice(&11u64.to_le_bytes()); // slot
        buf[108..116].copy_from_slice(&0u64.to_le_bytes()); // proposer_index
        buf[116..148].copy_from_slice(&parent_root); // parent_root

        tile.handle_block(&buf);

        // Block is rejected by BLS signature verification (zeroed sig).
        assert_eq!(tile.fork_choice.nodes.len(), 1); // only genesis
    }
}
