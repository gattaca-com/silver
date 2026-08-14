use silver_beacon_state_data::SLOTS_PER_EPOCH;
use silver_common::{merkle::B256, ssz_view::StatusView};

#[derive(Debug, Default)]
pub(crate) struct SyncStatus {
    is_synced: bool,
    head_slot: u64,
    wall_slot: u64,
    head_root: B256,
    finalized_slot: u64,
}

impl SyncStatus {
    pub(crate) fn is_synced(&self) -> bool {
        self.is_synced
    }

    pub(crate) fn finalized_slot(&self) -> u64 {
        self.finalized_slot
    }

    pub(crate) fn wall_slot(&self) -> u64 {
        self.wall_slot
    }

    pub(crate) fn head_slot(&self) -> u64 {
        self.head_slot
    }

    pub(crate) fn head_root(&self) -> &B256 {
        &self.head_root
    }

    pub(crate) fn update(&mut self, ssz: [u8; 92], wall_slot: u64) {
        self.wall_slot = wall_slot;
        self.head_slot = StatusView::head_slot(&ssz);
        self.head_root = *StatusView::head_root(&ssz);
        self.finalized_slot = StatusView::finalized_epoch(&ssz) * SLOTS_PER_EPOCH;
    }

    pub(crate) fn update_synced(&mut self, synced: bool) {
        self.is_synced = synced;
    }
}
