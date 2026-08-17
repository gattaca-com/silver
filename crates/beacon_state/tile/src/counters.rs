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
    }
}
