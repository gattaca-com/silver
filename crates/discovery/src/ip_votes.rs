use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use rustc_hash::FxHashMap;
use silver_common::NodeId;

/// Peers refresh their vote on every PONG, so only departed peers age out.
const VOTE_TTL: Duration = Duration::from_secs(30 * 60);

struct Vote {
    addr: SocketAddr,
    cast_at: Instant,
}

#[derive(Default)]
pub struct IpVotes(FxHashMap<NodeId, Vote>);

impl IpVotes {
    pub fn cast(&mut self, voter: NodeId, addr: SocketAddr, now: Instant) {
        self.0.insert(voter, Vote { addr, cast_at: now });
    }

    pub fn remove(&mut self, voter: &NodeId) {
        self.0.remove(voter);
    }

    pub fn expire(&mut self, now: Instant) {
        self.0.retain(|_, v| now.saturating_duration_since(v.cast_at) < VOTE_TTL);
    }

    /// IPv4 and IPv6 are tallied apart, since a dual-stack node has one
    /// external address per family.
    pub fn has_majority(&self, addr: SocketAddr, threshold: u32, now: Instant) -> bool {
        let mut for_addr = 0u32;
        let mut same_family = 0u32;
        for v in self.0.values() {
            if v.addr.is_ipv4() != addr.is_ipv4() ||
                now.saturating_duration_since(v.cast_at) >= VOTE_TTL
            {
                continue;
            }
            same_family += 1;
            if v.addr == addr {
                for_addr += 1;
            }
        }
        for_addr >= threshold && 2 * for_addr > same_family
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    fn v4(last: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)), 9000)
    }

    #[test]
    fn threshold_and_strict_majority_are_both_required() {
        let now = Instant::now();
        let mut votes = IpVotes::default();
        for _ in 0..3 {
            votes.cast(NodeId::random(), v4(1), now);
        }
        assert!(votes.has_majority(v4(1), 3, now));
        assert!(!votes.has_majority(v4(1), 4, now));

        for _ in 0..3 {
            votes.cast(NodeId::random(), v4(2), now);
        }
        assert!(!votes.has_majority(v4(1), 3, now), "a tie is not a majority");
    }

    #[test]
    fn other_family_does_not_dilute_majority() {
        let now = Instant::now();
        let mut votes = IpVotes::default();
        for _ in 0..3 {
            votes.cast(NodeId::random(), v4(1), now);
        }
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9000);
        for _ in 0..5 {
            votes.cast(NodeId::random(), v6, now);
        }
        assert!(votes.has_majority(v4(1), 3, now));
        assert!(votes.has_majority(v6, 3, now));
    }

    #[test]
    fn expired_votes_do_not_count() {
        let now = Instant::now();
        let mut votes = IpVotes::default();
        for _ in 0..3 {
            votes.cast(NodeId::random(), v4(1), now);
        }
        let later = now + VOTE_TTL;
        assert!(!votes.has_majority(v4(1), 3, later));

        votes.expire(later);
        assert!(votes.0.is_empty());
    }

    #[test]
    fn recast_replaces_previous_vote() {
        let now = Instant::now();
        let mut votes = IpVotes::default();
        let voter = NodeId::random();
        votes.cast(voter, v4(1), now);
        votes.cast(voter, v4(2), now);
        assert!(votes.has_majority(v4(2), 1, now));
        assert!(!votes.has_majority(v4(1), 1, now));
    }
}
