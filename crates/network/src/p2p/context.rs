use std::collections::HashMap;

use fxhash::FxHashMap;
use silver_common::{Enr, PeerId, ProtoIdentify, TProducer, TRandomAccess};

use crate::RemotePeer;

pub struct Context {
    pub gossip_producer: TProducer,
    pub gossip_consumer: TRandomAccess,
    pub rpc_producer: TProducer,
    pub rpc_consumer: TRandomAccess,
    /// Local identify record.
    pub identify: Option<ProtoIdentify>,
    pub cluster_nodes: Option<ClusterNodes>,
    pub cluster_inbound_producer: TProducer,
    pub cluster_outbound_consumer: TRandomAccess,
}

impl Context {
    pub fn cluster_peer(&self, raft_id: u64) -> Option<usize> {
        self.cluster_nodes.as_ref().and_then(|n| n.connection_id(raft_id))
    }

    pub fn raft_id(&self, conn: usize) -> Option<u64> {
        self.cluster_nodes.as_ref().and_then(|n| n.raft_id(&conn))
    }
}

pub struct ClusterNodes {
    /// Fixed membership keyed by authenticated peer identity.
    by_peer_id: FxHashMap<PeerId, u64>,
    /// Mapping of raft id to conneciton id, used in the dispatch
    /// of outbound cluster messages.
    by_raft_id: FxHashMap<u64, usize>,
    /// Mapping of connection id to raft id, used in the dispatch of incoming
    /// cluster messages.
    by_conn_id: FxHashMap<usize, u64>,
}

impl ClusterNodes {
    pub fn new(nodes: HashMap<u64, Enr>) -> Self {
        let mut by_peer_id = FxHashMap::default();
        for (id, enr) in nodes {
            let peer_id = PeerId::from_secp256k1_pubkey(&enr.public_key().serialize());
            by_peer_id.insert(peer_id, id);
        }
        Self { by_peer_id, by_raft_id: FxHashMap::default(), by_conn_id: FxHashMap::default() }
    }

    pub fn raft_id(&self, conn_id: &usize) -> Option<u64> {
        self.by_conn_id.get(conn_id).copied()
    }

    pub fn connection_id(&self, raft_id: u64) -> Option<usize> {
        self.by_raft_id.get(&raft_id).copied()
    }

    pub fn connected(&mut self, peer: &RemotePeer) {
        // A connection handle can be reused for a different identity.
        self.disconnected(peer.connection);
        if let Some(&raft_id) = self.by_peer_id.get(&peer.peer_id) {
            self.by_conn_id.insert(peer.connection, raft_id);
            self.by_raft_id.entry(raft_id).or_insert(peer.connection);
        }
    }

    pub fn disconnected(&mut self, connection: usize) {
        let Some(raft_id) = self.by_conn_id.remove(&connection) else {
            return;
        };
        if self.by_raft_id.get(&raft_id) != Some(&connection) {
            return;
        }

        match self.by_conn_id.iter().find_map(|(&conn, &id)| (id == raft_id).then_some(conn)) {
            Some(conn) => {
                self.by_raft_id.insert(raft_id, conn);
            }
            None => {
                self.by_raft_id.remove(&raft_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use silver_common::Keypair;

    use super::*;

    fn cluster() -> (ClusterNodes, RemotePeer) {
        let keypair = Keypair::from_secret(&[1; 32]).unwrap();
        let enr = Enr::empty(keypair.secret_key()).unwrap();
        let nodes = ClusterNodes::new(HashMap::from([(7, enr)]));
        let peer = RemotePeer {
            peer_id: keypair.peer_id(),
            connection: 10,
            addr: "127.0.0.1:9000".parse().unwrap(),
        };
        (nodes, peer)
    }

    #[test]
    fn closing_duplicate_or_unregistered_connection_preserves_selected_route() {
        let (mut nodes, mut peer) = cluster();
        nodes.connected(&peer);
        nodes.disconnected(11);
        assert_eq!(nodes.connection_id(7), Some(10));

        peer.connection = 11;
        nodes.connected(&peer);
        assert_eq!(nodes.connection_id(7), Some(10));
        assert_eq!(nodes.raft_id(&10), Some(7));
        assert_eq!(nodes.raft_id(&11), Some(7));

        nodes.disconnected(11);
        nodes.disconnected(11);
        assert_eq!(nodes.connection_id(7), Some(10));
        assert_eq!(nodes.raft_id(&10), Some(7));
        assert_eq!(nodes.raft_id(&11), None);
    }

    #[test]
    fn closing_selected_connection_uses_surviving_duplicate() {
        let (mut nodes, mut peer) = cluster();
        nodes.connected(&peer);
        peer.connection = 11;
        nodes.connected(&peer);

        nodes.disconnected(10);
        assert_eq!(nodes.connection_id(7), Some(11));
        assert_eq!(nodes.raft_id(&10), None);
        assert_eq!(nodes.raft_id(&11), Some(7));

        nodes.disconnected(10);
        assert_eq!(nodes.connection_id(7), Some(11));

        nodes.disconnected(11);
        assert_eq!(nodes.connection_id(7), None);
        assert_eq!(nodes.raft_id(&11), None);
    }

    #[test]
    fn reused_connection_handle_cannot_authenticate_non_member() {
        let (mut nodes, mut peer) = cluster();
        nodes.connected(&peer);
        let member = peer.peer_id;

        peer.peer_id = Keypair::from_secret(&[2; 32]).unwrap().peer_id();
        nodes.connected(&peer);
        assert_eq!(nodes.connection_id(7), None);
        assert_eq!(nodes.raft_id(&peer.connection), None);

        peer.peer_id = member;
        nodes.connected(&peer);
        assert_eq!(nodes.connection_id(7), Some(peer.connection));
        assert_eq!(nodes.raft_id(&peer.connection), Some(7));
    }

    #[test]
    fn connection_handle_reuse_preserves_other_members_routes() {
        let (mut nodes, mut peer) = cluster();
        let other_keypair = Keypair::from_secret(&[2; 32]).unwrap();
        nodes.by_peer_id.insert(other_keypair.peer_id(), 8);
        nodes.connected(&peer);
        peer.connection = 11;
        nodes.connected(&peer);

        peer.connection = 10;
        peer.peer_id = other_keypair.peer_id();
        nodes.connected(&peer);
        assert_eq!(nodes.connection_id(7), Some(11));
        assert_eq!(nodes.connection_id(8), Some(10));
        assert_eq!(nodes.raft_id(&10), Some(8));
        assert_eq!(nodes.raft_id(&11), Some(7));

        nodes.disconnected(10);
        assert_eq!(nodes.connection_id(7), Some(11));
        assert_eq!(nodes.connection_id(8), None);
    }
}
