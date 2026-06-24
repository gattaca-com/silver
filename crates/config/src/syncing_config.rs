use serde::{Deserialize, Serialize};

use super::{default_u64, default_usize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SyncingConfig {
    /// Max remembered rejected roots (one set; failed block roots + the
    /// poisoned target_root from `SyncingFinalized`-time rejects). Sized
    /// for "many bad blocks during one bad-chain catchup attempt" — 256
    /// covers ~8 epochs.
    #[serde(default = "default_usize::<256>")]
    pub rejected_cap: usize,
    /// SyncingHead trigger: enter SyncingHead only when a peer's head_slot
    /// exceeds ours by at least this much. Avoids thrash on 1-slot
    /// wall-clock jitter but stays small enough to catch the post-
    /// finalized-sync tail quickly. Also gates the "refuse Following"
    /// guard in `select_target` — beyond this lag vs wall_slot we won't
    /// declare Following even with no viable peer target.
    #[serde(default = "default_u64::<8>")]
    pub head_lag_threshold_slots: u64,
    /// SyncingFinalized trigger: enter SyncingFinalized only when a peer's
    /// `finalized_epoch` exceeds ours by at least this many epochs. Mainnet
    /// FFG lags head by ~2 epochs, and peer Statuses snapshot before they
    /// finalize their own next epoch — a 1-epoch drift between peers and us
    /// is the steady-state, not a sign we're behind.
    #[serde(default = "default_u64::<2>")]
    pub finalized_lag_threshold_epochs: u64,
    /// Defensive ceiling on peers' claimed finalized / head slot vs our
    /// wall slot. Beyond this, the claim is rejected as bogus.
    #[serde(default = "default_u64::<32>")]
    pub wall_clock_tolerance_slots: u64,
    /// Max slots per `BlocksByRange` request issued by the peer-manager
    /// catch-up driver. Bounds in-flight memory + response time on the
    /// peer.
    #[serde(default = "default_u64::<128>")]
    pub max_blocks_by_range_batch: u64,
    /// Inflight `BlocksByRange` request progress timeout, in milliseconds.
    /// If no head_slot advance into the requested range is observed for
    /// this long, the request is declared stuck: peer is scored
    /// (high-tolerance, the lightest penalty) and the request is re-issued.
    /// A healthy peer's
    /// terminator clears the request well before this; the bound exists to
    /// rotate off a silent/slow peer fast during catch-up.
    #[serde(default = "default_u64::<2000>")]
    pub inflight_progress_timeout_ms: u64,
    /// Consecutive failed `DataColumnsByRange` attempts (error terminator
    /// or progress timeout) on one catch-up range before its remainder is
    /// conceded to the by-root straggler fallback.
    #[serde(default = "default_u64::<3>")]
    pub max_colreq_attempts: u64,
    /// Beacon-state pending-block buffer bounds.
    #[serde(default)]
    pub pending: PendingBounds,
}

impl Default for SyncingConfig {
    fn default() -> Self {
        Self {
            rejected_cap: 256,
            head_lag_threshold_slots: 8,
            finalized_lag_threshold_epochs: 2,
            wall_clock_tolerance_slots: 32,
            max_blocks_by_range_batch: 128,
            inflight_progress_timeout_ms: 2_000,
            max_colreq_attempts: 3,
            pending: PendingBounds::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct PendingBounds {
    /// Admission: buffer an orphan / DA-awaiting block only if its slot is at
    /// most this many slots ahead of the wall clock.
    #[serde(default = "default_u64::<2>")]
    pub future_tolerance: u64,
    /// Max distinct missing-parent roots buffered.
    #[serde(default = "default_usize::<64>")]
    pub max_parents: usize,
    /// Max blocks buffered awaiting data columns.
    #[serde(default = "default_usize::<128>")]
    pub max_dc: usize,
    /// Max forward slot gap (orphan slot − head) tolerated for by-root
    /// backtracking; beyond it the peer-manager range-syncs the gap instead.
    #[serde(default = "default_usize::<32>")]
    pub max_chain_len: usize,
}

impl Default for PendingBounds {
    fn default() -> Self {
        Self { future_tolerance: 2, max_parents: 64, max_dc: 512, max_chain_len: 32 }
    }
}
