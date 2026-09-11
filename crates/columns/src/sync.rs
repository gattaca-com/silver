use silver_beacon_state_data::SLOTS_PER_EPOCH;
use silver_common::{SyncUpdate, merkle::B256, ssz_view::StatusView};

#[derive(Debug, Default)]
pub(crate) struct SyncStatus {
    sync_target: SyncUpdate,
    head_root: B256,
    finalized_slot: u64,
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

    pub(crate) fn head_root(&self) -> &B256 {
        &self.head_root
    }

    pub(crate) fn update(&mut self, ssz: [u8; 92]) {
        self.head_root = *StatusView::head_root(&ssz);
        self.finalized_slot = StatusView::finalized_epoch(&ssz) * SLOTS_PER_EPOCH;
    }

    pub(crate) fn set_sync_target(&mut self, target: SyncUpdate) {
        self.sync_target = target;
    }

    #[cfg(feature = "ef_tests")]
    pub(crate) fn ef_set(&mut self, head_root: B256, finalized_slot: u64) {
        self.head_root = head_root;
        self.finalized_slot = finalized_slot;
        self.sync_target = SyncUpdate::Following;
    }
}
