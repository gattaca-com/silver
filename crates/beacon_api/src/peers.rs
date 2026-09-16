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

/// Connection handles are reused and do not establish arrival order.
#[derive(Default)]
pub(crate) struct PeerTable {
    connections: FxHashMap<usize, (u64, Peer)>,
    arrivals: u64,
}

impl PeerTable {
    pub(crate) fn new() -> Self {
        Self {
            connections: FxHashMap::with_capacity_and_hasher(256, Default::default()),
            arrivals: 0,
        }
    }

    pub(crate) fn insert(&mut self, connection: usize, peer: Peer) {
        self.arrivals += 1;
        self.connections.insert(connection, (self.arrivals, peer));
    }

    pub(crate) fn remove(&mut self, connection: usize) {
        self.connections.remove(&connection);
    }

    fn by_identity(&self) -> Vec<&Peer> {
        let mut latest: FxHashMap<PeerId, (u64, &Peer)> = FxHashMap::default();
        for (arrival, peer) in self.connections.values() {
            let entry = latest.entry(peer.id).or_insert((*arrival, peer));
            if *arrival > entry.0 {
                *entry = (*arrival, peer);
            }
        }
        latest.into_values().map(|(_, peer)| peer).collect()
    }

    pub(crate) fn connected(&self) -> usize {
        self.by_identity().len()
    }

    pub(crate) fn matching<'a>(&'a self, filter: &'a PeerFilter) -> impl Iterator<Item = &'a Peer> {
        self.by_identity().into_iter().filter(move |peer| filter.admits(peer))
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
