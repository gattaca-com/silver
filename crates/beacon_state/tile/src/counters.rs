//! Per-tile counters exposed via `silver_common`'s shmem-mapped
//! atomic-counter primitive.
//!
//! Counters are interpreted by position — append before `_Count`, do
//! not reorder.

silver_common::declare_counters! {
    pub BeaconStateCounters => "beacon_state" {
        // gossip-admission structures at capacity (attestations still
        // accepted and relayed; aggregation/shedding coverage degrades)
        AttestationPoolFull,
        // Gossip attestation ignored (never relayed): beacon_block_root not
        // in fork choice — the reprocess-queue gap vs lighthouse, which
        // parks and replays these.
        AttestationUnknownRoot,
        SeenAggregatesFull,
        AttestationRootMemoFull,
        // attestation-root memo effectiveness (hit rate is the memo's
        // whole premise; a miss storm plus Full = distinct-data spray).
        // Aggregate-path probes land before full validation, so invalid
        // aggregates inflate Miss without ever becoming votes.
        AttestationRootMemoHit,
        AttestationRootMemoMiss,
        // gossip vote batching (attestations + sync messages + PTC): size of
        // the latest flush (gauge) and batch-verify failures that fell back
        // to per-message verifies (non-zero = someone is feeding us invalid
        // signatures).
        VoteBatchSize,
        VoteBatchFallback,
        // Valid sync messages are still accepted and relayed when this is
        // full; only creation of a local contribution is skipped.
        SyncContributionPoolFull,
    }
}
