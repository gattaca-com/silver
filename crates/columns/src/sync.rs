use std::time::Instant;

use silver_beacon_state_data::SLOTS_PER_EPOCH;
use silver_common::{
    SyncUpdate, merkle::B256, ssz_view::StatusView, ticker::MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS,
};

#[derive(Debug)]
pub(crate) struct SyncStatus {
    sync_target: SyncUpdate,
    wall_slot: u64,
    wall_slot_at: Instant,
    head_root: B256,
    finalized_slot: u64,
}

impl Default for SyncStatus {
    fn default() -> Self {
        Self {
            sync_target: SyncUpdate::default(),
            wall_slot: 0,
            wall_slot_at: Instant::now(),
            head_root: B256::default(),
            finalized_slot: 0,
        }
    }
}

impl SyncStatus {
    pub(crate) fn is_synced(&self) -> bool {
        self.sync_target.is_following()
    }

    pub(crate) fn finalized_slot(&self) -> u64 {
        self.finalized_slot
    }

    pub(crate) fn data_availability_floor(&self) -> u64 {
        self.sync_target.data_availability_floor(self.finalized_slot)
    }

    pub(crate) fn wall_slot(&self) -> u64 {
        self.wall_slot
    }

    pub(crate) fn head_root(&self) -> &B256 {
        &self.head_root
    }

    pub(crate) fn is_future_slot(&self, slot: u64, slot_ms: u64) -> bool {
        let ms_into_slot = self.wall_slot_at.elapsed().as_millis() as u64;
        slot.saturating_mul(slot_ms) >
            self.wall_slot.saturating_mul(slot_ms) +
                ms_into_slot +
                MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS
    }

    pub(crate) fn update(&mut self, ssz: [u8; 92], wall_slot: u64) {
        self.wall_slot = wall_slot;
        self.wall_slot_at = Instant::now();
        self.head_root = *StatusView::head_root(&ssz);
        self.finalized_slot = StatusView::finalized_epoch(&ssz) * SLOTS_PER_EPOCH;
    }

    pub(crate) fn set_sync_target(&mut self, target: SyncUpdate) {
        self.sync_target = target;
    }
}
