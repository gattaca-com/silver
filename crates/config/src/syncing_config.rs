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
    /// Mainnet `SLOTS_PER_EPOCH`. Used by the finalized-target wall-clock
    /// filter to convert `epoch * SLOTS_PER_EPOCH → start slot`. Spec
    /// constant, but kept here so tests / non-mainnet networks can
    /// override.
    #[serde(default = "default_u64::<32>")]
    pub slots_per_epoch: u64,
    /// Max slots per `BlocksByRange` request issued by the peer-manager
    /// catch-up driver. Bounds in-flight memory + response time on the
    /// peer.
    #[serde(default = "default_u64::<128>")]
    pub max_blocks_by_range_batch: u64,
    /// Inflight `BlocksByRange` request progress timeout, in milliseconds.
    /// If no head_slot advance into the requested range is observed for
    /// this long, the request is declared stuck: peer is scored
    /// (mid-severity) and the request is re-issued. Sized to absorb BLS
    /// and STF import latency for a full 128-block batch (several seconds)
    /// without false positives.
    #[serde(default = "default_u64::<15000>")]
    pub inflight_progress_timeout_ms: u64,
}

impl Default for SyncingConfig {
    fn default() -> Self {
        Self {
            rejected_cap: 256,
            head_lag_threshold_slots: 8,
            finalized_lag_threshold_epochs: 2,
            wall_clock_tolerance_slots: 32,
            slots_per_epoch: 32,
            max_blocks_by_range_batch: 128,
            inflight_progress_timeout_ms: 15_000,
        }
    }
}
