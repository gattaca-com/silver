use std::{
    collections::hash_map::Entry,
    net::{Ipv4Addr, Ipv6Addr},
};

use rustc_hash::FxHashMap;
use silver_common::{Eth2Addr, IpBytes, PeerId};
use silver_httpcore::Query;
use smallvec::SmallVec;

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

struct Connection {
    handle: usize,
    peer: Peer,
}

#[derive(Default)]
pub(crate) struct PeerTable {
    peers: FxHashMap<PeerId, SmallVec<[Connection; 2]>>,
}

impl PeerTable {
    pub(crate) fn new() -> Self {
        // 600 is the default Config::max_connections; preallocate to avoid rehashing.
        Self { peers: FxHashMap::with_capacity_and_hasher(600, Default::default()) }
    }

    pub(crate) fn insert(&mut self, connection: usize, peer: Peer) {
        let connections = self.peers.entry(peer.id).or_default();
        connections.retain(|c| c.handle != connection);
        connections.push(Connection { handle: connection, peer });
    }

    pub(crate) fn remove(&mut self, peer_id: PeerId, connection: usize) {
        let Entry::Occupied(mut entry) = self.peers.entry(peer_id) else { return };
        entry.get_mut().retain(|c| c.handle != connection);
        if entry.get().is_empty() {
            entry.remove();
        }
    }

    pub(crate) fn connected(&self) -> usize {
        self.peers.len()
    }

    pub(crate) fn matching<'a>(&'a self, filter: &'a PeerFilter) -> impl Iterator<Item = &'a Peer> {
        self.peers
            .values()
            .filter_map(|connections| connections.last())
            .map(|connection| &connection.peer)
            .filter(move |peer| filter.admits(peer))
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
