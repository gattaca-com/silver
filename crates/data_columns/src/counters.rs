//! Per-tile counters exposed via `silver_common`'s shmem-mapped
//! atomic-counter primitive. Surfer maps `counters-data_columns` into
//! its TUI by registering [`DataColumnCounters::NAMES`] in its schema
//! table.
//!
//! Counters are interpreted by position — append before `_Count`, do
//! not reorder.

silver_common::declare_counters! {
    pub DataColumnCounters => "data_columns" {
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
        BelowFinalised,
        ParentUnknown,
        ProposerIndexMismatch,
        ProposerSignatureInvalid,
        // store side
        DataColumnsAvailableEmitted,
        StoreWrites,
    }
}
