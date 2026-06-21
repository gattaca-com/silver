use std::time::{Duration, Instant};

use crate::StreamProtocol;

pub const N_STREAM_PROTOCOLS: usize = StreamProtocol::Unset as usize + 1;
pub const RPC_ERR_RATE_LIMITED: u8 = 0x8b;
pub const RPC_RATE_LIMITED_MSG: &[u8] = b"rate limit exceeded";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpcQuota {
    max_tokens: u64,
    period: Duration,
}

impl RpcQuota {
    pub const fn n_every(max_tokens: u64, period_secs: u64) -> Self {
        Self { max_tokens, period: Duration::from_secs(period_secs) }
    }

    pub const fn one_every(period_secs: u64) -> Self {
        Self::n_every(1, period_secs)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcRateLimit {
    Allowed,
    TooLarge,
    TooSoon,
}

#[derive(Clone, Debug)]
pub struct RpcRateLimitSet {
    tokens: [u64; N_STREAM_PROTOCOLS],
    last_refill: [Option<Instant>; N_STREAM_PROTOCOLS],
}

impl Default for RpcRateLimitSet {
    fn default() -> Self {
        Self { tokens: [0; N_STREAM_PROTOCOLS], last_refill: [None; N_STREAM_PROTOCOLS] }
    }
}

impl RpcRateLimitSet {
    pub fn peek_inbound(
        &self,
        protocol: StreamProtocol,
        tokens: u64,
        now: Instant,
    ) -> RpcRateLimit {
        self.peek(protocol, protocol.inbound_rpc_quota(), tokens, now)
    }

    pub fn peek_outbound(
        &self,
        protocol: StreamProtocol,
        tokens: u64,
        now: Instant,
    ) -> RpcRateLimit {
        self.peek(protocol, protocol.outbound_rpc_quota(), tokens, now)
    }

    pub fn admit_inbound(
        &mut self,
        protocol: StreamProtocol,
        tokens: u64,
        now: Instant,
    ) -> RpcRateLimit {
        self.admit(protocol, protocol.inbound_rpc_quota(), tokens, now)
    }

    pub fn admit_outbound(
        &mut self,
        protocol: StreamProtocol,
        tokens: u64,
        now: Instant,
    ) -> RpcRateLimit {
        self.admit(protocol, protocol.outbound_rpc_quota(), tokens, now)
    }

    fn peek(
        &self,
        protocol: StreamProtocol,
        quota: Option<RpcQuota>,
        tokens: u64,
        now: Instant,
    ) -> RpcRateLimit {
        let idx = protocol.ordinal() as usize;
        let Some(quota) = quota else {
            return RpcRateLimit::Allowed;
        };
        let tokens = tokens.max(1);
        if tokens > quota.max_tokens {
            return RpcRateLimit::TooLarge;
        }

        let (available, _) = self.refilled(idx, quota, now);
        if available >= tokens { RpcRateLimit::Allowed } else { RpcRateLimit::TooSoon }
    }

    fn admit(
        &mut self,
        protocol: StreamProtocol,
        quota: Option<RpcQuota>,
        tokens: u64,
        now: Instant,
    ) -> RpcRateLimit {
        let idx = protocol.ordinal() as usize;
        let Some(quota) = quota else {
            return RpcRateLimit::Allowed;
        };
        let tokens = tokens.max(1);
        if tokens > quota.max_tokens {
            return RpcRateLimit::TooLarge;
        }

        let (available, last_refill) = self.refilled(idx, quota, now);
        self.tokens[idx] = available;
        self.last_refill[idx] = Some(last_refill);

        if self.tokens[idx] >= tokens {
            self.tokens[idx] -= tokens;
            RpcRateLimit::Allowed
        } else {
            RpcRateLimit::TooSoon
        }
    }

    fn refilled(&self, idx: usize, quota: RpcQuota, now: Instant) -> (u64, Instant) {
        let Some(last) = self.last_refill[idx] else {
            return (quota.max_tokens, now);
        };

        let per_token_ns = quota.period.as_nanos() as u64 / quota.max_tokens;
        if per_token_ns == 0 {
            return (quota.max_tokens, now);
        }

        let elapsed_ns = now.saturating_duration_since(last).as_nanos() as u64;
        let new_tokens = (elapsed_ns / per_token_ns).min(quota.max_tokens);
        if new_tokens == 0 {
            return (self.tokens[idx], last);
        }

        let available = self.tokens[idx].saturating_add(new_tokens).min(quota.max_tokens);
        let advance_ns = per_token_ns.saturating_mul(new_tokens);
        (available, last + Duration::from_nanos(advance_ns))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_initial_burst_then_refills() {
        let start = Instant::now();
        let mut limiter = RpcRateLimitSet::default();

        assert_eq!(limiter.admit_inbound(StreamProtocol::Ping, 2, start), RpcRateLimit::Allowed);
        assert_eq!(limiter.peek_inbound(StreamProtocol::Ping, 1, start), RpcRateLimit::TooSoon);
        assert_eq!(
            limiter.admit_inbound(StreamProtocol::Ping, 1, start + Duration::from_secs(5)),
            RpcRateLimit::Allowed
        );
    }

    #[test]
    fn rejects_batches_larger_than_quota() {
        let mut limiter = RpcRateLimitSet::default();
        assert_eq!(
            limiter.admit_inbound(StreamProtocol::Ping, 3, Instant::now()),
            RpcRateLimit::TooLarge
        );
    }

    #[test]
    fn unquotaed_protocols_are_always_allowed() {
        let mut limiter = RpcRateLimitSet::default();
        assert_eq!(
            limiter.admit_inbound(StreamProtocol::GossipSub, u64::MAX, Instant::now()),
            RpcRateLimit::Allowed
        );
    }

    #[test]
    fn outbound_quotas_are_more_conservative_than_inbound() {
        let now = Instant::now();
        let mut inbound = RpcRateLimitSet::default();
        let mut outbound = RpcRateLimitSet::default();

        let protocol = StreamProtocol::BeaconBlocksByRange;
        assert_eq!(inbound.admit_inbound(protocol, 128, now), RpcRateLimit::Allowed);
        assert_eq!(outbound.admit_outbound(protocol, 128, now), RpcRateLimit::Allowed);
        assert_eq!(
            inbound.peek_inbound(protocol, 128, now + Duration::from_secs(10)),
            RpcRateLimit::Allowed
        );
        assert_eq!(
            outbound.peek_outbound(protocol, 128, now + Duration::from_secs(10)),
            RpcRateLimit::TooSoon
        );
        assert_eq!(
            outbound.peek_outbound(protocol, 128, now + Duration::from_secs(15)),
            RpcRateLimit::Allowed
        );
    }
}
