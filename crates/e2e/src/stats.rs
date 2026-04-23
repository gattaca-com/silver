use std::time::Instant;

use hdrhistogram::Histogram;

pub struct Stats {
    pub gossip_received: u64,
    pub gossip_decompressed_bytes: u64,
    pub invalid_msgs: u64,
    pub first_seen_at: Option<Instant>,
    pub last_seen_at: Option<Instant>,
    /// Per-message publish→receive latency in nanoseconds, populated when
    /// the publisher stamps the first 8 bytes of its payload with a
    /// `flux::timing::Instant::now().0` and the receive side reads that
    /// back. Record in ns; query in whatever unit you like.
    pub latency_ns: Histogram<u64>,
    pub receive_ns: Histogram<u64>,
}

impl Default for Stats {
    fn default() -> Self {
        // Max ≈ 10s in ns; 3 significant figures. Covers anything realistic
        // while keeping the histogram compact.
        let latency_ns =
            Histogram::new_with_bounds(1, 10_000_000_000, 3).expect("histogram bounds");
        let receive_ns =
            Histogram::new_with_bounds(1, 10_000_000_000, 3).expect("histogram bounds");
        Self {
            gossip_received: 0,
            gossip_decompressed_bytes: 0,
            invalid_msgs: 0,
            first_seen_at: None,
            last_seen_at: None,
            latency_ns,
            receive_ns,
        }
    }
}

impl std::fmt::Debug for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stats")
            .field("gossip_received", &self.gossip_received)
            .field("gossip_decompressed_bytes", &self.gossip_decompressed_bytes)
            .field("invalid_msgs", &self.invalid_msgs)
            .field("latency_samples", &self.latency_ns.len())
            .finish()
    }
}
