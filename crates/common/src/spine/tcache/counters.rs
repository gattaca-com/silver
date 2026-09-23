//! Process-wide consumer-tail fault counters, `counters-tcache`. The consumer
//! name is in the accompanying `tracing::warn!`; per-consumer tails are in
//! `counters-tcache-{name}`.

crate::declare_counters! {
    pub TCacheCounters => "tcache" {
        // Acquire below the consumer's tail: not counted as a pin, so the
        // producer may reclaim the slot while the read is held.
        AcquireBelowTail,
        // Out-of-order acquire behind the newest bucket: protected only by
        // the sliding guard's slack.
        AcquireInGuard,
        // Tail forced past pinned buckets at the lag threshold.
        LagEviction,
        // Idle consumer's tail forced to the head.
        IdleReset,
    }
}
