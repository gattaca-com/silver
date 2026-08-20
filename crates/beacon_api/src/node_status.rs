use silver_beacon_state_data::{Epoch, SLOTS_PER_EPOCH};
use silver_common::ELSyncStatus;

use crate::json::{PeerCountData, SyncingData};

/// `SyncingConfig::head_lag_threshold_slots`'s default: the lag past which
/// the node's own sync engine stops treating itself as at the head.
const SYNC_TOLERANCE_SLOTS: u64 = 8;

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
    pub peers: PeerCounts,
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
        } else if self.is_syncing() || self.el != ELSyncStatus::Synced {
            Health::Syncing
        } else {
            Health::Ready
        }
    }

    /// The schema has no way to say "no head", so a node with none reports
    /// slot zero: reporting that state synced would send a validator client
    /// to attest against nothing.
    pub(crate) fn syncing_data(&self) -> SyncingData {
        SyncingData {
            head_slot: self.slots.map_or(0, |slots| slots.head_slot),
            sync_distance: self.sync_distance(),
            is_syncing: self.is_syncing(),
            is_optimistic: self.execution_optimistic(),
            el_offline: self.el_offline(),
        }
    }

    pub(crate) fn peer_count_data(&self) -> PeerCountData {
        PeerCountData { connected: self.peers.connected, connecting: self.peers.connecting }
    }

    /// The epoch the chain is in, whatever epoch this node's head has reached:
    /// what a duties endpoint tells a request that arrives before the head
    /// does from one no chain schedules duties for. `None` until the first
    /// status, which leaves nothing to judge either by.
    pub(crate) fn wall_epoch(&self) -> Option<Epoch> {
        self.slots.map(|slots| slots.wall_slot / SLOTS_PER_EPOCH)
    }

    /// `syncing` alone would answer for the head this node is chasing, not the
    /// one the chain is at: the control tile publishes a `SyncUpdate` only when
    /// its target changes, so a node that has yet to find a peer to sync from
    /// stays `false` however far behind it falls.
    fn is_syncing(&self) -> bool {
        self.syncing || self.sync_distance() > SYNC_TOLERANCE_SLOTS
    }

    /// `u64::MAX` before the first head: no distance the schema can carry is
    /// truthful there, and the zero it would otherwise report is the one value
    /// every validator client reads as synced.
    fn sync_distance(&self) -> u64 {
        self.slots.map_or(u64::MAX, |slots| slots.sync_distance())
    }

    /// True while nothing has come back from the EL: an `Unknown` EL has
    /// answered no healthcheck, which is no better evidence that it can be
    /// reached than a failed one. A *syncing* EL answered, so it is reachable;
    /// what it cannot yet do is reported by `is_optimistic`.
    fn el_offline(&self) -> bool {
        matches!(self.el, ELSyncStatus::Unknown | ELSyncStatus::Offline)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerCounts {
    pub connected: u64,
    pub connecting: u64,
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
