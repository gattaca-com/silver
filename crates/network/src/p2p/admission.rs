use std::net::{IpAddr, SocketAddr};

use fxhash::FxHashSet;

/// Handshakes finish within a round trip, so few are ever in flight. Beyond
/// this many, or this close to the cap, a source must prove its address
/// first, so unvalidated Initials alone never fill the cap.
pub(super) const HANDSHAKES_BEFORE_RETRY: usize = 16;

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
}

impl InboundAdmission {
    pub(crate) fn new(max_connections: usize, trusted_ips: FxHashSet<IpAddr>) -> Self {
        Self { max_connections, trusted_ips, handshaking: 0 }
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

        let near_cap = population + HANDSHAKES_BEFORE_RETRY >= self.max_connections;
        if !validated && (near_cap || self.handshaking >= HANDSHAKES_BEFORE_RETRY) {
            Admission::Retry
        } else {
            Admission::Accept
        }
    }

    pub(crate) fn accepted(&mut self) {
        self.handshaking += 1;
    }

    pub(crate) fn handshake_ended(&mut self) {
        self.handshaking -= 1;
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

    fn addr(ip: Ipv4Addr) -> SocketAddr {
        SocketAddr::from((ip, 9000))
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
        for _ in 0..HANDSHAKES_BEFORE_RETRY {
            assert_eq!(admission.decide(addr(OTHER), false, 0), Admission::Accept);
            admission.accepted();
        }
        assert_eq!(admission.decide(addr(OTHER), false, 0), Admission::Retry);
        assert_eq!(admission.decide(addr(OTHER), true, 0), Admission::Accept);

        admission.handshake_ended();
        assert_eq!(admission.decide(addr(OTHER), false, 0), Admission::Accept);
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
