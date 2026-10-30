use std::{
    collections::hash_map::Entry,
    net::{IpAddr, Ipv6Addr, SocketAddr},
};

use fxhash::{FxHashMap, FxHashSet};

/// Handshakes finish within a round trip, so few are ever in flight. Beyond
/// this many, or this close to the cap, a source must prove its address
/// first, so unvalidated Initials alone never fill the cap.
pub(super) const HANDSHAKES_BEFORE_RETRY: usize = 16;

/// Leaves room for several honest nodes behind one NAT.
const MAX_INBOUND_PER_IP: u32 = 8;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Admission {
    Accept,
    /// Answer with a stateless Retry: the client must echo its token from
    /// the address it claims before it gets any connection state.
    Retry,
    Refuse,
}

pub(crate) struct InboundAdmission {
    /// Hard transport-level connection cap; inbound accepts refused beyond
    /// it. Outbound dials are bounded separately by the peer manager.
    max_connections: usize,
    trusted_ips: FxHashSet<IpAddr>,
    handshaking: usize,
    inbound_per_ip: FxHashMap<IpAddr, u32>,
}

impl InboundAdmission {
    pub(crate) fn new(max_connections: usize, trusted_ips: FxHashSet<IpAddr>) -> Self {
        Self { max_connections, trusted_ips, handshaking: 0, inbound_per_ip: FxHashMap::default() }
    }

    /// Slots that unvalidated Initials could exhaust go only to a source that
    /// proved it receives traffic at its address. The trusted bypass of the
    /// cap is always such a slot.
    pub(crate) fn decide(
        &self,
        remote: SocketAddr,
        validated: bool,
        population: usize,
    ) -> Admission {
        let trusted = self.trusted_ips.contains(&remote.ip());
        if trusted {
            silver_log::info!(peer_addr=?remote, validated, "inbound connection from trusted peer");
        }

        // The peer manager's table indexes at most twice the cap, so trusted
        // overflow beyond it would be refused there anyway.
        let cap = if trusted { 2 * self.max_connections } else { self.max_connections };
        if population >= cap {
            return Admission::Refuse;
        }

        // Loopback traffic is local, and local multi-node setups all share it.
        let from_ip = self.inbound_per_ip.get(&per_ip_key(remote.ip())).copied().unwrap_or(0);
        if from_ip >= MAX_INBOUND_PER_IP && !trusted && !remote.ip().is_loopback() {
            return Admission::Refuse;
        }

        // Validating repeat sources keeps an address's quota for traffic that
        // really comes from it.
        let near_cap = population + HANDSHAKES_BEFORE_RETRY >= self.max_connections;
        let crowded = near_cap || self.handshaking >= HANDSHAKES_BEFORE_RETRY || from_ip > 0;
        if !validated && crowded { Admission::Retry } else { Admission::Accept }
    }

    pub(crate) fn accepted(&mut self, remote: IpAddr) {
        self.handshaking += 1;
        *self.inbound_per_ip.entry(per_ip_key(remote)).or_default() += 1;
    }

    pub(crate) fn handshake_ended(&mut self) {
        self.handshaking -= 1;
    }

    pub(crate) fn closed(&mut self, remote: IpAddr) {
        if let Entry::Occupied(mut count) = self.inbound_per_ip.entry(per_ip_key(remote)) {
            *count.get_mut() -= 1;
            if *count.get() == 0 {
                count.remove();
            }
        }
    }
}

/// One IPv6 host commonly holds a whole /64.
fn per_ip_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => Ipv6Addr::from_bits(v6.to_bits() & (u128::MAX << 64)).into(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    const TRUSTED: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 4);
    const OTHER: Ipv4Addr = Ipv4Addr::new(5, 6, 7, 8);

    fn admission(max_connections: usize) -> InboundAdmission {
        InboundAdmission::new(max_connections, FxHashSet::from_iter([IpAddr::from(TRUSTED)]))
    }

    fn addr(ip: impl Into<IpAddr>) -> SocketAddr {
        SocketAddr::from((ip.into(), 9000))
    }

    #[test]
    fn trusted_bypass_requires_validated_address() {
        let admission = admission(4);
        assert_eq!(admission.decide(addr(TRUSTED), false, 4), Admission::Retry);
        assert_eq!(admission.decide(addr(TRUSTED), true, 4), Admission::Accept);
        assert_eq!(admission.decide(addr(OTHER), true, 4), Admission::Refuse);
    }

    #[test]
    fn handshakes_in_flight_require_validated_address() {
        let mut admission = admission(100);
        for i in 0..HANDSHAKES_BEFORE_RETRY as u8 {
            let remote = addr([10, 0, 0, i]);
            assert_eq!(admission.decide(remote, false, 0), Admission::Accept);
            admission.accepted(remote.ip());
        }
        assert_eq!(admission.decide(addr(OTHER), false, 0), Admission::Retry);
        assert_eq!(admission.decide(addr(OTHER), true, 0), Admission::Accept);

        admission.handshake_ended();
        assert_eq!(admission.decide(addr(OTHER), false, 0), Admission::Accept);
    }

    #[test]
    fn inbound_per_ip_is_capped() {
        let mut admission = admission(100);
        for _ in 0..MAX_INBOUND_PER_IP {
            assert_eq!(admission.decide(addr(OTHER), true, 0), Admission::Accept);
            admission.accepted(OTHER.into());
            admission.handshake_ended();
        }
        assert_eq!(admission.decide(addr(OTHER), true, 0), Admission::Refuse);
        assert_eq!(admission.decide(addr([5, 6, 7, 9]), true, 0), Admission::Accept);

        admission.closed(OTHER.into());
        assert_eq!(admission.decide(addr(OTHER), true, 0), Admission::Accept);
    }

    #[test]
    fn repeat_source_requires_validated_address() {
        let mut admission = admission(100);
        admission.accepted(OTHER.into());
        assert_eq!(admission.decide(addr(OTHER), false, 0), Admission::Retry);

        admission.closed(OTHER.into());
        assert_eq!(admission.decide(addr(OTHER), false, 0), Admission::Accept);
    }

    #[test]
    fn inbound_per_ip_groups_ipv6_by_64_prefix() {
        let mut admission = admission(100);
        for i in 0..MAX_INBOUND_PER_IP as u16 {
            admission.accepted(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i).into());
        }
        let same_64 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 1, 2, 3, 4);
        let other_64 = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0);
        assert_eq!(admission.decide(addr(same_64), true, 0), Admission::Refuse);
        assert_eq!(admission.decide(addr(other_64), true, 0), Admission::Accept);
    }

    #[test]
    fn trusted_and_loopback_skip_inbound_per_ip_cap() {
        let mut admission = admission(100);
        for _ in 0..MAX_INBOUND_PER_IP {
            admission.accepted(TRUSTED.into());
            admission.accepted(Ipv4Addr::LOCALHOST.into());
        }
        assert_eq!(admission.decide(addr(TRUSTED), true, 0), Admission::Accept);
        assert_eq!(admission.decide(addr(Ipv4Addr::LOCALHOST), true, 0), Admission::Accept);
    }

    #[test]
    fn last_slots_require_validated_address() {
        let admission = admission(100);
        let near_cap = 100 - HANDSHAKES_BEFORE_RETRY;
        assert_eq!(admission.decide(addr(OTHER), false, near_cap - 1), Admission::Accept);
        assert_eq!(admission.decide(addr(OTHER), false, near_cap), Admission::Retry);
        assert_eq!(admission.decide(addr(OTHER), true, 99), Admission::Accept);
        assert_eq!(admission.decide(addr(OTHER), true, 100), Admission::Refuse);
    }

    #[test]
    fn trusted_overflow_is_bounded() {
        let admission = admission(4);
        assert_eq!(admission.decide(addr(TRUSTED), true, 7), Admission::Accept);
        assert_eq!(admission.decide(addr(TRUSTED), true, 8), Admission::Refuse);
    }
}
