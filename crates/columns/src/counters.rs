//! Per-tile counters exposed via `silver_common`'s shmem-mapped
//! atomic-counter primitive. Surfer maps `counters-columns` into
//! its TUI by registering [`DataColumnCounters::NAMES`] in its schema
//! table.
//!
//! Counters are interpreted by position — append before `_Count`, do
//! not reorder.

silver_common::declare_counters! {
    pub DataColumnCounters => "columns" {
        // store side
        DataColumnsAvailableEmitted,
        // EL-mempool blob fetch (engine_getBlobsV2)
        ElBlobsFetched,
        ElColumnsBuilt,
        // Batched KZG verification: calls, sidecars per call (ratio = batch
        // size), and sidecars rejected via the per-sidecar fallback.
        KzgBatchesVerified,
        KzgBatchColumns,
        KzgBatchRejects,
    }
}
