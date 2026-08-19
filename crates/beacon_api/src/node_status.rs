use silver_common::ELSyncStatus;

/// The node's own condition, as against the chain state a
/// `BeaconStateReader` serves. Assembled and refreshed by its single
/// writer; handlers read one consistent snapshot per dispatch.
#[derive(Clone, Copy, Debug, Default)]
pub struct NodeStatus {
    /// `None` until the beacon-state tile publishes its first status,
    /// i.e. while the node has nothing to report a head against.
    pub slots: Option<SlotStatus>,
    pub syncing: bool,
    pub el: ELSyncStatus,
}

/// What `getHealth` answers with: 200, the syncing code (206 unless the
/// request names another), or 503.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Health {
    Ready,
    Syncing,
    Uninitialized,
}

impl NodeStatus {
    /// The head's own execution status: true until an EL verdict has verified
    /// the head block's payload.
    pub(crate) fn execution_optimistic(&self) -> bool {
        self.slots.is_none_or(|slots| slots.head_optimistic)
    }

    /// The spec puts an optimistic or offline execution layer on the same
    /// footing as a syncing beacon node — both mean "data served may be
    /// incorrect" — and an EL we have not heard from yet is no better
    /// evidence of readiness than one that is syncing.
    pub(crate) fn health(&self) -> Health {
        if self.slots.is_none() {
            Health::Uninitialized
        } else if self.syncing || self.el != ELSyncStatus::Synced {
            Health::Syncing
        } else {
            Health::Ready
        }
    }
}

/// `head_slot` is the highest imported block's slot, so a `sync_distance` of
/// one is ordinary on a synced node — the current slot's block lands partway
/// into it, and an empty slot never produces one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotStatus {
    pub head_slot: u64,
    pub wall_slot: u64,
    pub head_optimistic: bool,
}

impl SlotStatus {
    /// Saturating: a head ahead of the wall clock (a peer's block accepted
    /// early in the slot) is zero distance, not an underflow.
    pub fn sync_distance(&self) -> u64 {
        self.wall_slot.saturating_sub(self.head_slot)
    }
}
