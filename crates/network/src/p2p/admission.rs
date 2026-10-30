use std::net::{IpAddr, SocketAddr};

use fxhash::FxHashSet;

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
}

impl InboundAdmission {
    pub(crate) fn new(max_connections: usize, trusted_ips: FxHashSet<IpAddr>) -> Self {
        Self { max_connections, trusted_ips }
    }

    /// Trusted IPs are public, so their bypass of the cap is only granted to
    /// a source that proved it receives traffic at that address.
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

        if population < self.max_connections {
            return Admission::Accept;
        }
        // The peer manager's table indexes at most twice the cap, so trusted
        // overflow beyond it would be refused there anyway.
        if !trusted || population >= 2 * self.max_connections {
            return Admission::Refuse;
        }
        if validated { Admission::Accept } else { Admission::Retry }
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
    fn trusted_overflow_is_bounded() {
        let admission = admission(4);
        assert_eq!(admission.decide(addr(TRUSTED), true, 7), Admission::Accept);
        assert_eq!(admission.decide(addr(TRUSTED), true, 8), Admission::Refuse);
    }
}
