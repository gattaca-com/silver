use std::time::Instant;

use silver_common::{
    DEFAULT_GOSSIP_MAX_BYTES_PER_SECOND, MAX_GOSSIP_FRAME_SIZE,
    rpc_rate_limit::{DEFAULT_MAX_INBOUND_STREAMS_PER_SECOND, RpcRateLimitSet},
};

const NANOS_PER_SECOND: u128 = 1_000_000_000;
const MAX_GOSSIP_PREFIX_SIZE: usize = 10;

/// Per-connection inbound quotas; burst is one second's allowance.
#[derive(Clone, Copy, Debug)]
pub struct InboundLimits {
    pub gossip_bytes_per_second: u64,
    pub streams_per_second: u64,
}

impl InboundLimits {
    pub const UNLIMITED: Self =
        Self { gossip_bytes_per_second: u64::MAX, streams_per_second: u64::MAX };
}

impl Default for InboundLimits {
    fn default() -> Self {
        Self {
            gossip_bytes_per_second: DEFAULT_GOSSIP_MAX_BYTES_PER_SECOND,
            streams_per_second: DEFAULT_MAX_INBOUND_STREAMS_PER_SECOND,
        }
    }
}

/// Credit is held in units × ns so sub-unit refills accumulate exactly.
struct TokenBucket {
    per_second: u64,
    capacity: u128,
    credit: u128,
    refilled_at: Instant,
}

impl TokenBucket {
    fn new(per_second: u64, burst: u64, now: Instant) -> Self {
        assert!(per_second > 0, "rate must be positive");
        let capacity = u128::from(burst) * NANOS_PER_SECOND;
        Self { per_second, capacity, credit: capacity, refilled_at: now }
    }

    fn admit(&mut self, units: usize, now: Instant) -> bool {
        if now > self.refilled_at {
            let elapsed = now.duration_since(self.refilled_at).as_nanos();
            let refill = elapsed.saturating_mul(u128::from(self.per_second));
            self.credit = self.credit.saturating_add(refill).min(self.capacity);
            self.refilled_at = now;
        }
        let cost = units as u128 * NANOS_PER_SECOND;
        if cost > self.credit {
            return false;
        }
        self.credit -= cost;
        true
    }
}

pub(crate) struct InboundRateLimits {
    pub(crate) rpc: RpcRateLimitSet,
    gossip: TokenBucket,
    streams: TokenBucket,
}

impl InboundRateLimits {
    pub(crate) fn new(limits: InboundLimits, now: Instant) -> Self {
        // Admit a maximum-size frame even when the configured rate is smaller.
        let gossip_burst = limits
            .gossip_bytes_per_second
            .max((MAX_GOSSIP_FRAME_SIZE + MAX_GOSSIP_PREFIX_SIZE) as u64);
        Self {
            rpc: RpcRateLimitSet::default(),
            gossip: TokenBucket::new(limits.gossip_bytes_per_second, gossip_burst, now),
            streams: TokenBucket::new(limits.streams_per_second, limits.streams_per_second, now),
        }
    }

    pub(crate) fn gossip_bytes_per_second(&self) -> u64 {
        self.gossip.per_second
    }

    pub(crate) fn admit_gossip(&mut self, frame_bytes: usize, now: Instant) -> bool {
        self.gossip.admit(frame_bytes, now)
    }

    pub(crate) fn admit_stream(&mut self, now: Instant) -> bool {
        self.streams.admit(1, now)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn gossip_rate(gossip_bytes_per_second: u64, now: Instant) -> InboundRateLimits {
        InboundRateLimits::new(
            InboundLimits { gossip_bytes_per_second, ..InboundLimits::default() },
            now,
        )
    }

    #[test]
    fn maximum_frame_fits_even_below_the_frame_size_rate() {
        let now = Instant::now();
        let burst = MAX_GOSSIP_FRAME_SIZE + MAX_GOSSIP_PREFIX_SIZE;
        let rate = 1_000_000;
        let mut limits = gossip_rate(rate, now);
        assert!(limits.admit_gossip(burst, now));
        assert!(!limits.admit_gossip(1, now));
        assert!(!limits.admit_gossip(burst, now + Duration::from_secs(1)));
        assert!(limits.admit_gossip(rate as usize, now + Duration::from_secs(1)));
        assert!(!limits.admit_gossip(1, now + Duration::from_secs(1)));
    }

    #[test]
    fn fractional_refills_survive_repeated_rejections() {
        let now = Instant::now();
        let mut limits = gossip_rate(1000, now);
        assert!(limits.admit_gossip(MAX_GOSSIP_FRAME_SIZE + MAX_GOSSIP_PREFIX_SIZE, now));
        for micros in [250, 500, 750] {
            assert!(!limits.admit_gossip(1, now + Duration::from_micros(micros)));
        }
        assert!(limits.admit_gossip(1, now + Duration::from_millis(1)));
        assert!(!limits.admit_gossip(1, now + Duration::from_millis(1)));
        assert!(!limits.admit_gossip(1, now));
        assert!(limits.admit_gossip(999, now + Duration::from_secs(1)));
        assert!(!limits.admit_gossip(1, now + Duration::from_secs(1)));
    }

    #[test]
    fn idle_refill_is_capped_at_one_burst() {
        let now = Instant::now();
        let rate = 20_000_000;
        let mut limits = gossip_rate(rate, now);
        assert!(limits.admit_gossip(rate as usize, now));
        assert!(!limits.admit_gossip(1, now));
        let later = now + Duration::from_secs(60);
        assert!(limits.admit_gossip(rate as usize, later));
        assert!(!limits.admit_gossip(1, later));
    }

    #[test]
    fn very_large_rates_do_not_overflow_refill() {
        let now = Instant::now();
        let mut limits = InboundRateLimits::new(InboundLimits::UNLIMITED, now);
        assert!(limits.admit_gossip(usize::MAX, now));
        assert!(limits.admit_gossip(usize::MAX, now + Duration::from_secs(1000 * 365 * 24 * 3600)));
        assert!(limits.admit_stream(now));
    }

    #[test]
    fn streams_burst_one_second_then_refill_at_rate() {
        let now = Instant::now();
        let mut limits = InboundRateLimits::new(
            InboundLimits { streams_per_second: 20, ..InboundLimits::default() },
            now,
        );
        for _ in 0..20 {
            assert!(limits.admit_stream(now));
        }
        assert!(!limits.admit_stream(now));
        assert!(!limits.admit_stream(now + Duration::from_millis(49)));
        assert!(limits.admit_stream(now + Duration::from_millis(50)));
        assert!(!limits.admit_stream(now + Duration::from_millis(50)));
        assert!(limits.admit_gossip(1, now), "stream and gossip budgets are separate");
    }
}
