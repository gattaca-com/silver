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
        SeenAggregatesFull,
        AttestationRootMemoFull,
        // attestation-root memo effectiveness (hit rate is the memo's
        // whole premise; a miss storm plus Full = distinct-data spray).
        // Aggregate-path probes land before full validation, so invalid
        // aggregates inflate Miss without ever becoming votes.
        AttestationRootMemoHit,
        AttestationRootMemoMiss,
    }
}
