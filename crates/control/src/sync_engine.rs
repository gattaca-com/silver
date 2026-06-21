//! Unified driver for all outbound block + data-column sync and backfill
//! requests. See `docs/sync-engine-design.md`.
//!
//! Standalone, event-driven, strict state machine — owned by the control tile,
//! driven synchronously from its loop. Pure `event -> actions`: no spine
//! handles, no I/O, only a `now: Instant` passed in. Block/column payloads
//! never enter the engine; it consumes request-lifecycle control signals only.
//!
//! MIGRATION STATE (step 1 of 3, per the design doc): this is the module +
//! contract. The flat per-flag state is being lifted out of `silver_peer`'s
//! `PeerManager` (live targeting + range issuance) and the storage tile
//! (backfill scheduling); the `Ctx`/`Phase` enum-of-structs reshape is step 3.
//! Until the lift lands, `SyncEngine` only enforces the `ReplayComplete` start
//! gate and is not yet wired into the control loop.

use silver_common::{RpcSeverity, SyncUpdate};

/// Inputs. All exist on the spine today except `BackfillState` / `ColumnNeed`,
/// which storage emits from its startup scan (storage scans + reports; it no
/// longer schedules backfill requests).
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
    /// A response chunk arrived — progress only (refreshes the request timer).
    RpcChunk {
        request_id: u64,
        peer: usize,
    },
    /// Stream closed cleanly: the request's range/roots are delivered.
    RpcComplete {
        request_id: u64,
        peer: usize,
    },
    /// Error response or stream reset (timeout / goodbye): request failed.
    RpcFailed {
        request_id: u64,
        peer: usize,
    },
    /// Fork choice rejected an imported block — invalidate + blacklist.
    BlockRejected {
        block_root: [u8; 32],
    },
    /// Beacon-state `Status`: used ONLY for the gap cap + stall/backtrack,
    /// never to mark a request complete.
    LocalStatus {
        head_slot: u64,
        finalized_epoch: u64,
    },
    /// Disk replay finished applying to fork choice — gates start of sync.
    ReplayComplete,
    /// Storage startup scan result: the historical gap to backfill.
    BackfillState {
        block_floor: u64,
        earliest_present: u64,
        column_floor: u64,
    },
    /// A backfilled (or present) block carries blobs whose custody columns are
    /// absent — fold into the column backfill plan (today's "set 2").
    ColumnNeed {
        block_root: [u8; 32],
        slot: u64,
        missing: u128,
    },
}

/// Outputs. The control tile is the sole adapter: it transmits each request to
/// the named peer (applying rate-limit + in-flight caps; a rejection is fed
/// back as `RpcFailed` so the engine retries), and forwards `SetSyncTarget`
/// onto the `sync_target` queue. The engine selects the peer (sync policy);
/// peer ranking data reaches it via `PeerStatus`.
pub enum SyncAction {
    RequestBlocksByRange { request_id: u64, peer: usize, start: u64, count: u64 },
    RequestColumnsByRange { request_id: u64, peer: usize, start: u64, count: u64, columns: u128 },
    RequestColumnsByRoot { request_id: u64, peer: usize, block_root: [u8; 32], columns: u128 },
    RequestBlocksByRoot { request_id: u64, peer: usize, block_root: [u8; 32] },
    SetSyncTarget(SyncUpdate),
    ScorePeer { peer: usize, severity: RpcSeverity },
}

/// MIGRATION STATE: flat (step 1). The `Ctx` (mechanism) / `Phase` (policy)
/// enum-of-structs split is step 3; fields move in from `PeerManager` / storage
/// in step 2 and graduate into phase variants in step 3.
#[derive(Default)]
pub struct SyncEngine {
    /// Forward sync is gated until beacon-state `ReplayComplete` (replay must
    /// settle the local head first, so sync targets off a real head).
    replay_complete: bool,
}

impl SyncEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// True once the start gate has opened (`ReplayComplete` seen).
    pub fn started(&self) -> bool {
        self.replay_complete
    }

    pub fn on_event(
        &mut self,
        event: SyncEvent,
        _now: std::time::Instant,
        _emit: &mut impl FnMut(SyncAction),
    ) {
        // TODO(sync-engine step 2): the full event match — target selection,
        // request lifecycle, backfill, gap-cap / stall-backtrack. See
        // docs/sync-engine-design.md. For now only the start gate is live.
        if let SyncEvent::ReplayComplete = event {
            self.replay_complete = true;
        }
    }

    pub fn tick(&mut self, _now: std::time::Instant, _emit: &mut impl FnMut(SyncAction)) {
        // TODO(sync-engine step 2): retry timeouts, import-stall backtrack,
        // Following status watchdog, backfill pump.
    }
}
