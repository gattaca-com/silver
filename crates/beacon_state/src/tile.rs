use flux::{spine::SpineAdapter, tile::Tile};
use silver_common::{PeerGossipIn, PeerRpcIn, SilverSpine};

use crate::{
    arena::ArenaBacking,
    decompose, ssz_hash,
    ticker::{SlotTicker, TickEvent},
    types::{B256, BeaconStateRef, PENDING_POOL_CAP, PendingQueues, SLOTS_PER_EPOCH, Slot},
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Catching up from checkpoint to chain head.
    Syncing,
    /// Tracking head via gossip.
    Following,
}

pub struct BeaconStateTile {
    mode: Mode,
    ticker: SlotTicker,

    arena: ArenaBacking,
    pending_pool: Vec<PendingQueues>,

    head: BeaconStateRef,

    zero_hashes: [B256; ssz_hash::ZERO_HASHES_LEN],
}

impl BeaconStateTile {
    /// Shm-backed arena. Bootstraps from `checkpoint_state` if non-empty.
    pub fn new(ticker: SlotTicker, checkpoint_state: &[u8]) -> Self {
        Self::with_arena(ticker, ArenaBacking::open_shm("silver"), checkpoint_state)
    }

    /// Heap-backed arena for tests.
    pub fn new_heap(ticker: SlotTicker, checkpoint_state: &[u8]) -> Self {
        Self::with_arena(ticker, ArenaBacking::heap(), checkpoint_state)
    }

    fn with_arena(ticker: SlotTicker, arena: ArenaBacking, checkpoint_state: &[u8]) -> Self {
        let pending_pool: Vec<PendingQueues> =
            (0..PENDING_POOL_CAP).map(|_| PendingQueues::new()).collect();
        let head = BeaconStateRef {
            imm_idx: 0,
            vid_idx: 0,
            longtail_idx: 0,
            epoch_idx: 0,
            roots_idx: 0,
            slot_idx: 0,
            pending_idx: 0,
        };

        // TierPool cursors start at 0; bump past slot 0 (reserved for the
        // bootstrap state that `head` points at).
        arena.imm.set_cursor(1);
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
            head,
            zero_hashes: ssz_hash::compute_zero_hashes(),
        };

        if !checkpoint_state.is_empty() {
            tile.bootstrap(checkpoint_state);
        }
        tile
    }

    /// Load a checkpoint state SSZ blob. Decomposes into tiered storage at
    /// slot 0 of each pool. Returns false if the SSZ is invalid.
    fn bootstrap(&mut self, ssz: &[u8]) -> bool {
        let Some(d) = decompose::decompose_beacon_state(ssz, &self.zero_hashes) else {
            return false;
        };

        self.arena.imm.set(0, &d.imm);
        self.arena.vid.set(0, &d.vid);
        self.arena.longtail.set(0, &d.longtail);
        self.arena.epoch.set(0, &d.epoch);
        self.arena.roots.set(0, &d.roots);
        self.arena.slot.set(0, &d.sd);
        self.pending_pool[0] = d.pq;
        self.head = BeaconStateRef {
            imm_idx: 0,
            vid_idx: 0,
            longtail_idx: 0,
            epoch_idx: 0,
            roots_idx: 0,
            slot_idx: 0,
            pending_idx: 0,
        };

        let wall_slot = self.ticker.current_slot();
        let state_slot = self.arena.slot.get(0).slot;
        self.mode = if wall_slot > state_slot + 2 { Mode::Syncing } else { Mode::Following };
        true
    }

    pub fn on_slot_start(&mut self, _slot: Slot) {
        // TODO: snapshot roots, fire epoch transition at boundary.
    }
    pub fn on_state_advance(&mut self, _slot: Slot) {
        // TODO: pre-compute state for next slot.
    }
    pub fn on_fc_lookahead(&mut self, _slot: Slot) {
        // TODO: pre-emptive get_head for next slot.
    }
    pub fn sync_step(&mut self, _adapter: &SpineAdapter<SilverSpine>) {
        // TODO: request blocks to close gap to wall slot.
    }

    // Observables for tests.

    pub fn observe_mode(&self) -> &'static str {
        match self.mode {
            Mode::Syncing => "syncing",
            Mode::Following => "following",
        }
    }

    pub fn observe_head_slot(&self) -> Slot {
        self.arena.slot.get(self.head.slot_idx).slot
    }

    pub fn observe_head_epoch(&self) -> Slot {
        self.observe_head_slot() / SLOTS_PER_EPOCH
    }
}

impl Tile<SilverSpine> for BeaconStateTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        if self.mode == Mode::Following {
            match self.ticker.tick() {
                TickEvent::SlotStart(slot) => self.on_slot_start(slot),
                TickEvent::StateAdvance(slot) => self.on_state_advance(slot),
                TickEvent::ForkChoiceLookahead(slot) => self.on_fc_lookahead(slot),
                // TODO(EL): send engine_forkchoiceUpdatedV3 with payload
                // attributes to start EL block building for this slot.
                TickEvent::PreparePayload(_) => {}
                TickEvent::None => {}
            }
        }

        adapter.consume(|m: PeerGossipIn, _producers| {
            if let Ok(_bytes) = m.data.data() {
                // TODO handle gossip
            }
        });
        adapter.consume(|m: PeerRpcIn, _producers| {
            if let Ok(_bytes) = m.data.data() {
                // TODO handle rpc
            }
        });

        if self.mode == Mode::Syncing {
            self.sync_step(adapter);
        }
    }
}
