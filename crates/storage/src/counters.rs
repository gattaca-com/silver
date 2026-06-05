//! Per-tile counters exposed via `silver_common`'s shmem-mapped
//! atomic-counter primitive. Surfer maps `counters-storage` into
//! its TUI by registering [`StorageCounters::NAMES`] in its schema
//! table.
//!
//! Counters are interpreted by position — append before `_Count`, do
//! not reorder.

silver_common::declare_counters! {
    pub StorageCounters => "storage" {
        // gossip ingest
        GossipSidecarsReceived,
        GossipSidecarsRejected,
        // rpc ingest
        RpcSidecarsReceived,
        RpcSidecarsRejected,
        // per-block validation outcomes
        SidecarsAccepted,
        InclusionProofFailures,
        KzgVerifyFailures,
        // block-level checks (state-driven)
        BelowFinalized,
        ParentUnknown,
        ProposerIndexMismatch,
        ProposerSignatureInvalid,
        // store side
        DataColumnsAvailableEmitted,
        StoreWrites,
        UnfinalizedBlocksWritten,
        UnfinalizedColumnsWritten,
        BlocksPromoted,
        BlocksPruned,
        ColumnsPromoted,
        ColumnsPruned,
        BackfillBlocksWritten,
        BackfillColumnsWritten,
    }
}
