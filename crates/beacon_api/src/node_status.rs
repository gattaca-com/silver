use silver_common::ELSyncStatus;

/// The node's own condition, as against the chain state a
/// `BeaconStateReader` serves. Assembled and refreshed by its single
/// writer; handlers read one consistent snapshot per dispatch.
#[derive(Clone, Copy, Debug, Default)]
pub struct NodeStatus {
    /// `None` until the beacon-state tile publishes its first per-slot
    /// status, i.e. while the node has nothing to report a head against.
    pub slots: Option<SlotStatus>,
    pub syncing: bool,
    pub el: ELSyncStatus,
}

/// Announced once per slot, not once per block, so `head_slot` trails the
/// imported head by up to a slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotStatus {
    pub head_slot: u64,
    pub wall_slot: u64,
}

impl SlotStatus {
    /// Saturating: a head ahead of the wall clock (a peer's block accepted
    /// early in the slot) is zero distance, not an underflow.
    pub fn sync_distance(&self) -> u64 {
        self.wall_slot.saturating_sub(self.head_slot)
    }
}
