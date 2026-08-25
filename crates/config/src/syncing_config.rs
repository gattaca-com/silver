use serde::{Deserialize, Serialize};

use super::{default_u64, default_usize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SyncingConfig {
    /// Max remembered rejected roots (one set; failed block roots + the
    /// poisoned target_root from `SyncingFinalized`-time rejects). Sized
    /// for "many bad blocks while syncing one bad chain" — 256
    /// covers ~8 epochs.
    #[serde(default = "default_usize::<256>")]
    pub rejected_cap: usize,
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
    #[serde(default = "default_u64::<2000>")]
    pub inflight_progress_timeout_ms: u64,
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
            inflight_progress_timeout_ms: 2_000,
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
    #[serde(default = "default_usize::<512>")]
    pub max_dc: usize,
    /// Max forward slot gap (orphan slot − head) tolerated for by-root
    /// backtracking; beyond it syncing covers the gap instead.
    #[serde(default = "default_usize::<64>")]
    pub max_chain_len: usize,
}

impl Default for PendingBounds {
    fn default() -> Self {
        Self { future_tolerance: 2, max_parents: 64, max_dc: 512, max_chain_len: 64 }
    }
}
