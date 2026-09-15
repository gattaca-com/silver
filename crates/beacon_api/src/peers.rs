use std::net::{Ipv4Addr, Ipv6Addr};

use rustc_hash::FxHashMap;
use silver_common::{Eth2Addr, IpBytes, PeerId};
use silver_httpcore::Query;

pub(crate) struct Peer {
    pub(crate) id: PeerId,
    pub(crate) ip: IpBytes,
    pub(crate) port: u16,
    pub(crate) inbound: bool,
}

impl Peer {
    pub(crate) fn id_string(&self) -> String {
        Eth2Addr::PeerId(self.id).to_string().split_off("/p2p/".len())
    }

    pub(crate) fn multiaddr(&self) -> String {
        let transport = match self.ip {
            IpBytes::V4(octets) => Eth2Addr::QuicV4((Ipv4Addr::from(octets), self.port)),
            IpBytes::V6(octets) => Eth2Addr::QuicV6((Ipv6Addr::from(octets), self.port)),
        };
        format!("{transport}{}", Eth2Addr::PeerId(self.id))
    }

    pub(crate) fn direction(&self) -> &'static str {
        if self.inbound { "inbound" } else { "outbound" }
    }
}

#[derive(Default)]
pub(crate) struct PeerTable(FxHashMap<usize, Peer>);

impl PeerTable {
    pub(crate) fn new() -> Self {
        Self(FxHashMap::with_capacity_and_hasher(256, Default::default()))
    }
    pub(crate) fn insert(&mut self, connection: usize, peer: Peer) {
        self.0.insert(connection, peer);
    }

    pub(crate) fn remove(&mut self, connection: usize) {
        self.0.remove(&connection);
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn matching<'a>(&'a self, filter: &'a PeerFilter) -> impl Iterator<Item = &'a Peer> {
        self.0.values().filter(move |peer| filter.admits(peer))
    }
}

pub(crate) struct PeerFilter {
    connected: bool,
    inbound: bool,
    outbound: bool,
}

impl PeerFilter {
    pub(crate) fn parse(query: &str) -> Option<Self> {
        let (mut any_state, mut connected) = (false, false);
        let (mut any_direction, mut inbound, mut outbound) = (false, false, false);

        for (name, value) in Query::new(query) {
            match (&*name, &*value) {
                ("state", "connected") => (any_state, connected) = (true, true),
                ("state", "disconnected" | "connecting" | "disconnecting") => any_state = true,
                ("direction", "inbound") => (any_direction, inbound) = (true, true),
                ("direction", "outbound") => (any_direction, outbound) = (true, true),
                ("state" | "direction", _) => return None,
                _ => {}
            }
        }
        Some(Self {
            connected: !any_state || connected,
            inbound: !any_direction || inbound,
            outbound: !any_direction || outbound,
        })
    }

    fn admits(&self, peer: &Peer) -> bool {
        self.connected && if peer.inbound { self.inbound } else { self.outbound }
    }
}
