use silver_common::{BlockSource, RpcSeverity, SyncUpdate};

/// Inputs.
#[allow(clippy::large_enum_variant)]
pub enum SyncEvent {
    /// A peer's `Status` (parsed). Feeds target selection + eligibility.
    PeerStatus {
        peer: usize,
        head_slot: u64,
        head_root: [u8; 32],
        finalized_epoch: u64,
        finalized_root: [u8; 32],
        earliest_available_slot: u64,
        custody: u128,
    },
    PeerConnected {
        peer: usize,
    },
    PeerDisconnected {
        peer: usize,
    },
    RpcChunk {
        request_id: u64,
        peer: usize,
    },
    RpcComplete {
        request_id: u64,
        peer: usize,
    },
    RpcFailed {
        request_id: u64,
        peer: usize,
    },
    BlockRejected {
        block_root: [u8; 32],
        source: BlockSource,
    },
    LocalStatus {
        head_slot: u64,
        finalized_epoch: u64,
        finalized_root: [u8; 32],
        wall_slot: u64,
    },
    ReplayComplete,
    BackfillState {
        block_floor: u64,
        earliest_present: u64,
        column_floor: u64,
    },
    ColumnNeed {
        block_root: [u8; 32],
        slot: u64,
        missing: u128,
    },
}

/// Outputs.
pub enum SyncAction {
    RequestBlocksByRange {
        request_id: u64,
        peer: usize,
        start: u64,
        count: u64,
    },
    RequestColumnsByRange {
        request_id: u64,
        peer: usize,
        start: u64,
        count: u64,
        columns: u128,
        tried_peers: Vec<usize>,
    },
    RequestColumnsByRoot {
        request_id: u64,
        peer: usize,
        block_root: [u8; 32],
        columns: u128,
    },
    RequestBlocksByRoot {
        request_id: u64,
        peer: usize,
        block_root: [u8; 32],
    },
    SetSyncTarget(SyncUpdate),
    ScorePeer {
        peer: usize,
        severity: RpcSeverity,
    },
}
