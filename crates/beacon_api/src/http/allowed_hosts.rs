use std::net::{Ipv4Addr, Ipv6Addr};

/// A web page can point a name of its own at this node and then read the API
/// as its own origin. Its requests still carry that name in `Host`, and no
/// page controls what `localhost` or an IP literal reaches.
pub(crate) struct AllowedHosts {
    names: Vec<String>,
    any: bool,
}

impl AllowedHosts {
    pub(crate) fn new(names: &[String]) -> Self {
        Self { names: names.to_vec(), any: names.iter().any(|name| name == "*") }
    }

    /// Browsers always send `Host`, so a request without one is no web page's.
    pub(crate) fn allows(&self, host: Option<&str>) -> bool {
        let Some(host) = host else { return true };
        if self.any {
            return true;
        }
        if let Some(bracketed) = host.strip_prefix('[') {
            return bracketed
                .split_once(']')
                .is_some_and(|(address, _)| address.parse::<Ipv6Addr>().is_ok());
        }
        let name = host.rsplit_once(':').map_or(host, |(name, _)| name);
        name.parse::<Ipv4Addr>().is_ok() ||
            name.eq_ignore_ascii_case("localhost") ||
            self.names.iter().any(|allowed| allowed.eq_ignore_ascii_case(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_names_and_ip_literals_always_pass() {
        let hosts = AllowedHosts::new(&[]);
        for host in ["localhost", "LocalHost:5051", "127.0.0.1", "10.0.0.7:5051", "[::1]:5051"] {
            assert!(hosts.allows(Some(host)), "{host}");
        }
        assert!(hosts.allows(None));
    }

    #[test]
    fn unlisted_names_are_refused() {
        let hosts = AllowedHosts::new(&["beacon.internal".to_owned()]);
        assert!(hosts.allows(Some("beacon.internal:5051")));
        assert!(hosts.allows(Some("Beacon.Internal")));
        for host in ["attacker.example:5051", "localhost.attacker.example", "[attacker]:1", ""] {
            assert!(!hosts.allows(Some(host)), "{host}");
        }
    }

    #[test]
    fn wildcard_allows_any_name() {
        let hosts = AllowedHosts::new(&["*".to_owned()]);
        assert!(hosts.allows(Some("attacker.example")));
    }
}
