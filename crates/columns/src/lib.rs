mod batch;
pub mod counters;
mod el_blobs;
mod sync;
pub mod tile;
mod validate;

pub use counters::DataColumnCounters;

/// SSZ `hash_tree_root(BeaconBlockHeader)` — the same value carried as
/// `head_root` in Status RPC and `block_root` in
/// `DataColumnsByRootIdentifier`. Keys `validated_columns` so ByRoot
/// lookups and head-update integration are direct lookups.
pub(crate) type BlockRoot = [u8; 32];

/// Mainnet epoch: 32 slots × 12s. Wheel bucket width for the
/// block-level validation caches.
pub(crate) const EPOCH_DURATION: std::time::Duration = std::time::Duration::from_secs(32 * 12);
